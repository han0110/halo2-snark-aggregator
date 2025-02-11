use self::transcript::TranscriptRead;

use super::lookup::PermutationCommitments;
use super::permutation::Evaluated;
use super::{lookup, permutation};
use crate::arith::api::{ContextGroup, ContextRing, PowConstant};
use crate::arith::code::{FieldCode, PointCode};
use crate::schema::ast::EvaluationAST;
use crate::schema::SchemaGenerator;
use crate::verify::halo2::permutation::EvaluatedSet;
use crate::verify::halo2::verify::query::IVerifierParams;
use crate::{arith_in_ctx, infix2postfix};
use blake2b_simd::Params as Blake2bParams;
use group::prime::PrimeCurveAffine;
use group::Curve;
use halo2_proofs::arithmetic::{BaseExt, Engine};
use halo2_proofs::arithmetic::{CurveAffine, FieldExt, MultiMillerLoop};
use halo2_proofs::plonk::{self, Expression, VerifyingKey};
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::poly::multiopen::{CommitmentReference, VerifierQuery};
use halo2_proofs::poly::{Rotation, MSM};
use halo2_proofs::transcript::{read_n_points, read_n_scalars, ChallengeScalar, EncodedChallenge};
use pairing_bn256::bn256::{Fr as Fp, G1Affine};
use std::fmt::Debug;
use std::marker::PhantomData;

pub(crate) mod evaluate;
pub(crate) mod multiopen;
pub mod query;
pub mod transcript;

#[cfg(test)]
mod tests;

pub struct PlonkCommonSetup {
    pub l: u32,
    pub n: u32,
}

pub struct VerifierParams<C, S: Clone, P: Clone, Error: Debug> {
    //public_wit: Vec<C::ScalarExt>,
    pub gates: Vec<Vec<Expression<S>>>,
    pub common: PlonkCommonSetup,
    pub lookup_evaluated: Vec<Vec<lookup::Evaluated<C, S, P, Error>>>,
    pub permutation_evaluated: Vec<permutation::Evaluated<C, S, P, Error>>,
    pub instance_commitments: Vec<Vec<P>>,
    pub instance_evals: Vec<Vec<S>>,
    pub instance_queries: Vec<(usize, i32)>,
    pub advice_commitments: Vec<Vec<P>>,
    pub advice_evals: Vec<Vec<S>>,
    pub advice_queries: Vec<(usize, i32)>,
    pub fixed_commitments: Vec<P>,
    pub fixed_evals: Vec<S>,
    pub fixed_queries: Vec<(usize, i32)>,
    pub permutation_commitments: Vec<P>,
    pub permutation_evals: Vec<S>, // permutations common evaluation
    pub vanish_commitments: Vec<P>,
    pub random_commitment: P,
    pub w: Vec<P>,
    pub random_eval: S,
    pub beta: S,
    pub gamma: S,
    pub theta: S,
    pub delta: S,
    pub x: S,
    pub x_next: S,
    pub x_last: S,
    pub x_inv: S,
    pub xn: S,
    pub y: S,
    pub u: S,
    pub v: S,
    pub xi: S,
    pub omega: S,
    pub _ctx: PhantomData<C>,
    pub _error: PhantomData<Error>,
}

fn rotate_omega<
    C,
    S: Clone,
    Error,
    T: FieldExt,
    SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
>(
    sgate: &SGate,
    ctx: &mut C,
    x: &S,
    omega: T,
    at: i32,
) -> Result<S, Error> {
    let (base, exp) = if at < 0 {
        (omega.invert().unwrap(), [(-at) as u64, 0, 0, 0])
    } else {
        (omega, [at as u64, 0, 0, 0])
    };
    let omega_at = &sgate.from_constant(ctx, base.pow_vartime(exp))?;

    arith_in_ctx!([sgate, ctx] x * omega_at)
}

fn convert_expression<
    A: CurveAffine,
    C,
    S: Clone + Debug,
    P: Clone,
    Error: Debug,
    SGate: ContextGroup<C, S, S, A::ScalarExt, Error> + ContextRing<C, S, S, Error>,
    PGate: ContextGroup<C, S, P, A, Error>,
>(
    sgate: &SGate,
    pgate: &PGate,
    ctx: &mut C,
    expr: Expression<A::ScalarExt>,
) -> Result<Expression<S>, Error> {
    Ok(match expr {
        Expression::Constant(c) => Expression::Constant(sgate.from_constant(ctx, c)?),
        Expression::Selector(s) => Expression::Selector(s),
        Expression::Fixed {
            query_index,
            column_index,
            rotation,
        } => Expression::Fixed {
            query_index,
            column_index,
            rotation,
        },
        Expression::Advice {
            query_index,
            column_index,
            rotation,
        } => Expression::Advice {
            query_index,
            column_index,
            rotation,
        },
        Expression::Instance {
            query_index,
            column_index,
            rotation,
        } => Expression::Instance {
            query_index,
            column_index,
            rotation,
        },
        Expression::Negated(b) => Expression::Negated(Box::<Expression<S>>::new(
            convert_expression(sgate, pgate, ctx, *b)?,
        )),
        Expression::Sum(b1, b2) => Expression::Sum(
            Box::<Expression<S>>::new(convert_expression(sgate, pgate, ctx, *b1)?),
            Box::<Expression<S>>::new(convert_expression(sgate, pgate, ctx, *b2)?),
        ),
        Expression::Product(b1, b2) => Expression::Product(
            Box::<Expression<S>>::new(convert_expression(sgate, pgate, ctx, *b1)?),
            Box::<Expression<S>>::new(convert_expression(sgate, pgate, ctx, *b2)?),
        ),
        Expression::Scaled(b, f) => Expression::Scaled(
            Box::<Expression<S>>::new(convert_expression(sgate, pgate, ctx, *b)?),
            sgate.from_constant(ctx, f)?,
        ),
    })
}

impl<'a, C, S: Clone + Debug, P: Clone, Error: Debug> VerifierParams<C, S, P, Error> {
    fn read_product_commitments<
        M: MultiMillerLoop,
        T: TranscriptRead<
            C,
            S,
            P,
            Error,
            <M::G1Affine as CurveAffine>::ScalarExt,
            M::G1Affine,
            SGate,
            PGate,
        >,
        SGate: ContextGroup<C, S, S, <M::G1Affine as CurveAffine>::ScalarExt, Error>
            + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, M::G1Affine, Error>,
    >(
        ctx: &mut C,
        sgate: &SGate,
        pgate: &PGate,
        columns: usize,
        vk: &plonk::VerifyingKey<M::G1Affine>,
        transcript: &mut T,
    ) -> Result<Vec<P>, Error> {
        let mut permutation_product_commitments = vec![];
        let chunk_len = vk.cs.degree() - 2;

        for _ in (0..columns).collect::<Vec<_>>().chunks(chunk_len) {
            let p = transcript.read_point(ctx, sgate, pgate).unwrap();
            permutation_product_commitments.push(p)
        }

        Ok(permutation_product_commitments)
    }

    pub fn from_transcript<
        M: MultiMillerLoop,
        T: TranscriptRead<
            C,
            S,
            P,
            Error,
            <M::G1Affine as CurveAffine>::ScalarExt,
            M::G1Affine,
            SGate,
            PGate,
        >,
        SGate: ContextGroup<C, S, S, <M::G1Affine as CurveAffine>::ScalarExt, Error>
            + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, M::G1Affine, Error>,
    >(
        sgate: &'a SGate,
        pgate: &'a PGate,
        ctx: &mut C,
        xi: <M::G1Affine as CurveAffine>::ScalarExt,
        instances: &[&[&[M::Scalar]]],
        vk: &VerifyingKey<M::G1Affine>,
        params: &ParamsVerifier<M>,
        transcript: &mut T,
    ) -> Result<VerifierParams<C, S, P, Error>, Error> {
        for instances in instances.iter() {
            assert!(instances.len() == vk.cs.num_instance_columns)
        }

        let instance_commitments = instances
            .iter()
            .map(|instance| {
                instance
                    .iter()
                    .map(|instance| {
                        assert!(
                            instance.len() <= params.n as usize - (vk.cs.blinding_factors() + 1)
                        );
                        Ok(params.commit_lagrange(instance.to_vec()).to_affine())
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let num_proofs = instance_commitments.len();

        {
            let mut hasher = Blake2bParams::new()
                .hash_length(64)
                .personal(b"Halo2-Verify-Key")
                .to_state();

            let s = format!("{:?}", vk.pinned());

            hasher.update(&(s.len() as u64).to_le_bytes());
            hasher.update(s.as_bytes());

            let scalar = <M::G1Affine as PrimeCurveAffine>::Scalar::from_bytes_wide(
                hasher.finalize().as_array(),
            );
            let assigned_scalar = sgate.from_constant(ctx, scalar)?;
            transcript
                .common_scalar(ctx, sgate, &assigned_scalar)
                .unwrap();
        }

        let instance_commitments = instance_commitments
            .into_iter()
            .map(|instance| {
                instance
                    .into_iter()
                    .map(|instance| pgate.from_var(ctx, instance))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        for instance_commitments in instance_commitments.iter() {
            // Hash the instance (external) commitments into the transcript
            for commitment in instance_commitments {
                transcript.common_point(ctx, sgate, pgate, commitment)?
            }
        }

        let advice_commitments = (0..num_proofs)
            .map(|_| {
                // Hash the prover's advice commitments into the transcript
                let mut ret = vec![];
                for _ in 0..vk.cs.num_advice_columns {
                    let p = transcript.read_point(ctx, sgate, pgate).unwrap();
                    ret.push(p);
                }
                Ok(ret)
            })
            .collect::<Result<Vec<Vec<P>>, Error>>()
            .unwrap();

        let theta = transcript.squeeze_challenge_scalar(ctx, sgate).unwrap();

        let lookups_permuted = (0..num_proofs)
            .map(|_| -> Result<Vec<PermutationCommitments<P>>, Error> {
                let mut ret = vec![];
                for _ in &vk.cs.lookups {
                    let permuted_input_commitment =
                        transcript.read_point(ctx, sgate, pgate).unwrap();
                    let permuted_table_commitment =
                        transcript.read_point(ctx, sgate, pgate).unwrap();

                    ret.push(PermutationCommitments {
                        permuted_input_commitment,
                        permuted_table_commitment,
                    })
                }
                Ok(ret)
            })
            .collect::<Result<Vec<Vec<_>>, _>>()
            .unwrap();

        let beta = transcript.squeeze_challenge_scalar(ctx, sgate).unwrap();
        let gamma = transcript.squeeze_challenge_scalar(ctx, sgate).unwrap();

        let permutations_committed = (0..num_proofs)
            .map(|_| {
                let mut permutation_product_commitments = vec![];
                let chunk_len = vk.cs.degree() - 2;

                for _ in vk.cs.permutation.columns.chunks(chunk_len) {
                    let p = transcript.read_point(ctx, sgate, pgate).unwrap();
                    permutation_product_commitments.push(p)
                }

                Ok(permutation_product_commitments)
            })
            .collect::<Result<Vec<Vec<P>>, Error>>()
            .unwrap();

        let lookups_committed = lookups_permuted
            .iter()
            .map(|lookups| {
                // Hash each lookup product commitment
                lookups
                    .into_iter()
                    .map(|_| transcript.read_point(ctx, sgate, pgate))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let random_commitment = transcript.read_point(ctx, sgate, pgate).unwrap();

        // Sample y challenge, which keeps the gates linearly independent.
        let y = transcript.squeeze_challenge_scalar(ctx, sgate).unwrap();

        let h_commitments = (0..vk.domain.get_quotient_poly_degree())
            .map(|_| transcript.read_point(ctx, sgate, pgate))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let l = vk.cs.blinding_factors() as u32 + 1;
        let n = params.n as u32;

        let omega = vk.domain.get_omega();

        // Sample x challenge, which is used to ensure the circuit is
        // satisfied with high probability.
        let x = transcript.squeeze_challenge_scalar(ctx, sgate).unwrap();
        let x_next = rotate_omega(sgate, ctx, &x, omega, 1).unwrap();
        let x_last = rotate_omega(sgate, ctx, &x, omega, -(l as i32)).unwrap();
        let x_inv = rotate_omega(sgate, ctx, &x, omega, -1).unwrap();
        let xn = sgate.pow_constant(ctx, &x, n).unwrap();

        let instance_evals = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                (0..vk.cs.instance_queries.len())
                    .map(|_| transcript.read_scalar(ctx, sgate))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let advice_evals = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                (0..vk.cs.advice_queries.len())
                    .map(|_| transcript.read_scalar(ctx, sgate))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let fixed_evals = (0..vk.cs.fixed_queries.len())
            .map(|_| transcript.read_constant_scalar(ctx, sgate))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let random_eval = transcript.read_scalar(ctx, sgate).unwrap();
        let permutation_evals = vk
            .permutation
            .commitments
            .iter()
            .map(|_| transcript.read_scalar(ctx, sgate))
            .collect::<Result<Vec<_>, Error>>()
            .unwrap();

        let permutation_evaluated_sets = permutations_committed
            .into_iter()
            .map(|permutation| {
                let mut sets = vec![];

                let mut iter = permutation.into_iter();
                while let Some(permutation_product_commitment) = iter.next() {
                    let permutation_product_eval = transcript.read_scalar(ctx, sgate).unwrap();
                    let permutation_product_next_eval = transcript.read_scalar(ctx, sgate).unwrap();
                    let permutation_product_last_eval = if iter.len() > 0 {
                        Some(transcript.read_scalar(ctx, sgate)?)
                    } else {
                        None
                    };

                    sets.push(EvaluatedSet {
                        permutation_product_commitment,
                        permutation_product_eval,
                        permutation_product_next_eval,
                        permutation_product_last_eval,
                        chunk_len: vk.cs.degree() - 2,
                    });
                }

                Ok(sets)
            })
            .collect::<Result<Vec<_>, Error>>()
            .unwrap();

        let permutation_evaluated_evals = advice_evals
            .iter()
            .zip(instance_evals.iter())
            .map(|(advice_evals, instance_evals)| {
                vk.cs
                    .permutation
                    .columns
                    .chunks(vk.cs.degree() - 2)
                    .map(|columns| {
                        columns
                            .iter()
                            .map(|column| match column.column_type() {
                                halo2_proofs::plonk::Any::Advice => advice_evals
                                    [vk.cs.get_any_query_index(*column, Rotation::cur())]
                                .clone(),
                                halo2_proofs::plonk::Any::Fixed => fixed_evals
                                    [vk.cs.get_any_query_index(*column, Rotation::cur())]
                                .clone(),
                                halo2_proofs::plonk::Any::Instance => instance_evals
                                    [vk.cs.get_any_query_index(*column, Rotation::cur())]
                                .clone(),
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
                    .concat()
            })
            .collect::<Vec<_>>();

        let permutation_evaluated = permutation_evaluated_sets
            .into_iter()
            .zip(permutation_evaluated_evals.into_iter())
            .map(
                |(permutation_evaluated_set, permutation_evaluated_eval)| permutation::Evaluated {
                    x: x.clone(),
                    sets: permutation_evaluated_set,
                    evals: permutation_evaluated_eval,
                    chunk_len: vk.cs.degree() - 2,
                    _m: PhantomData,
                },
            )
            .collect();

        let lookup_evaluated = lookups_permuted
            .into_iter()
            .zip(lookups_committed.into_iter())
            .map(|(permuted, product_commitment)| {
                permuted
                    .into_iter()
                    .zip(product_commitment.into_iter())
                    .zip(vk.cs.lookups.iter())
                    .map(|((permuted, product_commitment), argument)| {
                        let product_eval = transcript.read_scalar(ctx, sgate).unwrap();
                        let product_next_eval = transcript.read_scalar(ctx, sgate).unwrap();
                        let permuted_input_eval = transcript.read_scalar(ctx, sgate).unwrap();
                        let permuted_input_inv_eval = transcript.read_scalar(ctx, sgate).unwrap();
                        let permuted_table_eval = transcript.read_scalar(ctx, sgate).unwrap();
                        Ok(crate::verify::halo2::lookup::Evaluated {
                            input_expressions: argument
                                .input_expressions
                                .iter()
                                .map(|expr| convert_expression(sgate, pgate, ctx, expr.clone()))
                                .collect::<Result<Vec<_>, _>>()?,
                            table_expressions: argument
                                .table_expressions
                                .iter()
                                .map(|expr| convert_expression(sgate, pgate, ctx, expr.clone()))
                                .collect::<Result<Vec<_>, _>>()?,
                            committed: crate::verify::halo2::lookup::Committed {
                                permuted,
                                product_commitment,
                            },
                            product_eval,
                            product_next_eval,
                            permuted_input_eval,
                            permuted_input_inv_eval,
                            permuted_table_eval,
                            _m: PhantomData,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, Error>>()
            .unwrap();

        let fixed_commitments = vk
            .fixed_commitments
            .iter()
            .map(|&affine| pgate.from_constant(ctx, affine))
            .collect::<Result<Vec<_>, Error>>()
            .unwrap();

        let v = transcript.squeeze_challenge_scalar(ctx, sgate).unwrap();
        let u = transcript.squeeze_challenge_scalar(ctx, sgate).unwrap();

        let mut w = vec![];
        while let Ok(p) = transcript.read_point(ctx, sgate, pgate) {
            //for _ in 0..1 {
            //let p = transcript.read_point(ctx, sgate, pgate).unwrap();
            w.push(p);
        }

        Ok(VerifierParams::<C, S, P, Error> {
            gates: vk
                .cs
                .gates
                .iter()
                .map(|gate| {
                    gate.polys
                        .iter()
                        .map(|expr| convert_expression(sgate, pgate, ctx, expr.clone()))
                        .collect::<Result<Vec<_>, Error>>()
                })
                .collect::<Result<Vec<_>, Error>>()?,
            common: PlonkCommonSetup { l, n },
            lookup_evaluated,
            permutation_evaluated,
            instance_commitments,
            instance_evals,
            instance_queries: vk
                .cs
                .instance_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            advice_commitments,
            advice_evals,
            advice_queries: vk
                .cs
                .advice_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            fixed_commitments,
            fixed_evals,
            fixed_queries: vk
                .cs
                .fixed_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            permutation_commitments: vk
                .permutation
                .commitments
                .iter()
                .map(|commit| pgate.from_var(ctx, *commit))
                .collect::<Result<Vec<_>, Error>>()?,
            permutation_evals,
            vanish_commitments: h_commitments,
            random_commitment,
            random_eval,
            beta,
            gamma,
            theta,
            delta: sgate.from_constant(
                ctx,
                <<M::G1Affine as CurveAffine>::ScalarExt as FieldExt>::DELTA,
            )?,
            x,
            x_next,
            x_last,
            x_inv,
            xn,
            y,
            u,
            v,
            xi: sgate.from_constant(ctx, xi)?,
            omega: sgate.from_constant(ctx, vk.domain.get_omega())?,
            w,
            _ctx: PhantomData,
            _error: PhantomData,
        })
    }

    // used for non-circuit version
    pub fn from_transcript_pure<
        M: MultiMillerLoop,
        E: EncodedChallenge<M::G1Affine>,
        T: halo2_proofs::transcript::TranscriptRead<M::G1Affine, E>,
        SGate: ContextGroup<C, S, S, <M::G1Affine as CurveAffine>::ScalarExt, Error>
            + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, M::G1Affine, Error>,
    >(
        sgate: &'a SGate,
        pgate: &'a PGate,
        ctx: &mut C,
        xi: <M::G1Affine as CurveAffine>::ScalarExt,
        instances: &[&[&[M::Scalar]]],
        vk: &VerifyingKey<M::G1Affine>,
        params: &ParamsVerifier<M>,
        transcript: &mut T,
    ) -> Result<VerifierParams<C, S, P, Error>, Error> {
        for instances in instances.iter() {
            assert!(instances.len() == vk.cs.num_instance_columns)
        }

        let instance_commitments = instances
            .iter()
            .map(|instance| {
                instance
                    .iter()
                    .map(|instance| {
                        assert!(
                            instance.len() <= params.n as usize - (vk.cs.blinding_factors() + 1)
                        );
                        Ok(params.commit_lagrange(instance.to_vec()).to_affine())
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let num_proofs = instance_commitments.len();

        // TODO: replace hash method and add it into circuits
        // Hash verification key into transcript
        vk.hash_into(transcript).unwrap();

        for instance_commitments in instance_commitments.iter() {
            // Hash the instance (external) commitments into the transcript
            for commitment in instance_commitments {
                transcript.common_point(*commitment).unwrap()
            }
        }

        let instance_commitments = instance_commitments
            .into_iter()
            .map(|instance| {
                instance
                    .into_iter()
                    .map(|instance| pgate.from_var(ctx, instance))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let advice_commitments = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                // Hash the prover's advice commitments into the transcript
                let points = read_n_points(transcript, vk.cs.num_advice_columns).unwrap();
                points
                    .into_iter()
                    .map(|advice| pgate.from_var(ctx, advice))
                    .collect()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // TODO: Put hash process of theta into circuit
        // Sample theta challenge for keeping lookup columns linearly independent
        let theta: ChallengeScalar<<M as Engine>::G1Affine, T> =
            transcript.squeeze_challenge_scalar();
        let theta = sgate.from_var(ctx, *theta).unwrap();

        let lookups_permuted = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                // Hash each lookup permuted commitment
                vk.cs
                    .lookups
                    .iter()
                    .map(|argument| argument.read_permuted_commitments(transcript))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // Sample beta challenge
        let beta: ChallengeScalar<<M as Engine>::G1Affine, T> =
            transcript.squeeze_challenge_scalar();
        let beta = sgate.from_var(ctx, *beta).unwrap();

        // Sample gamma challenge
        let gamma: ChallengeScalar<<M as Engine>::G1Affine, T> =
            transcript.squeeze_challenge_scalar();
        let gamma = sgate.from_constant(ctx, *gamma).unwrap();

        let permutations_committed = (0..num_proofs)
            .map(|_| {
                // Hash each permutation product commitment
                vk.cs.permutation.read_product_commitments(vk, transcript)
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let lookups_committed = lookups_permuted
            .into_iter()
            .map(|lookups| {
                // Hash each lookup product commitment
                lookups
                    .into_iter()
                    .map(|lookup| lookup.read_product_commitment(transcript))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let random_poly_commitment = transcript.read_point().unwrap();
        let random_commitment = pgate.from_var(ctx, random_poly_commitment).unwrap();

        // Sample y challenge, which keeps the gates linearly independent.
        let y: ChallengeScalar<<M as Engine>::G1Affine, T> = transcript.squeeze_challenge_scalar();
        let y = sgate.from_var(ctx, *y).unwrap();

        let h_commitments =
            read_n_points(transcript, vk.domain.get_quotient_poly_degree()).unwrap();
        let h_commitments = h_commitments
            .iter()
            .map(|&affine| pgate.from_var(ctx, affine))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let l = vk.cs.blinding_factors() as u32 + 1;
        let n = params.n as u32;

        let omega = vk.domain.get_omega();

        // Sample x challenge, which is used to ensure the circuit is
        // satisfied with high probability.
        let x: ChallengeScalar<<M as Engine>::G1Affine, T> = transcript.squeeze_challenge_scalar();
        let x = sgate.from_var(ctx, *x).unwrap();
        let x_next = rotate_omega(sgate, ctx, &x, omega, 1).unwrap();
        let x_last = rotate_omega(sgate, ctx, &x, omega, -(l as i32)).unwrap();
        let x_inv = rotate_omega(sgate, ctx, &x, omega, -1).unwrap();
        let xn = sgate.pow_constant(ctx, &x, n).unwrap();

        let instance_evals = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                read_n_scalars(transcript, vk.cs.instance_queries.len())
                    .unwrap()
                    .into_iter()
                    .map(|s| sgate.from_var(ctx, s))
                    .collect()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let advice_evals = (0..num_proofs)
            .map(|_| -> Result<Vec<_>, _> {
                read_n_scalars(transcript, vk.cs.advice_queries.len())
                    .unwrap()
                    .into_iter()
                    .map(|s| sgate.from_var(ctx, s))
                    .collect()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let fixed_evals = read_n_scalars(transcript, vk.cs.fixed_queries.len())
            .unwrap()
            .into_iter()
            .map(|s| sgate.from_constant(ctx, s))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let random_eval = transcript.read_scalar().unwrap();
        let random_eval = sgate.from_var(ctx, random_eval).unwrap();

        let permutations_common = vk.permutation.evaluate(transcript).unwrap();

        let permutation_evaluated = permutations_committed
            .into_iter()
            .map(|permutation| permutation.evaluate(transcript))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let permutation_evaluated_sets = permutation_evaluated
            .into_iter()
            .map(|permutation_evals| {
                Ok(permutation_evals
                    .sets
                    .iter()
                    .map(|eval| {
                        Ok(EvaluatedSet {
                            permutation_product_commitment: pgate
                                .from_var(ctx, eval.permutation_product_commitment)?,
                            permutation_product_eval: sgate
                                .from_var(ctx, eval.permutation_product_eval)?,
                            permutation_product_next_eval: sgate
                                .from_var(ctx, eval.permutation_product_next_eval)?,
                            permutation_product_last_eval: eval
                                .permutation_product_last_eval
                                .map(|e| sgate.from_var(ctx, e))
                                .transpose()?,
                            chunk_len: vk.cs.degree() - 2,
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?)
            })
            .collect::<Result<Vec<_>, Error>>()
            .unwrap();
        let permutation_evaluated_evals = advice_evals
            .iter()
            .zip(instance_evals.iter())
            .map(|(advice_evals, instance_evals)| {
                vk.cs
                    .permutation
                    .columns
                    .chunks(vk.cs.degree() - 2)
                    .map(|columns| {
                        columns
                            .iter()
                            .map(|column| match column.column_type() {
                                halo2_proofs::plonk::Any::Advice => advice_evals
                                    [vk.cs.get_any_query_index(*column, Rotation::cur())]
                                .clone(),
                                halo2_proofs::plonk::Any::Fixed => fixed_evals
                                    [vk.cs.get_any_query_index(*column, Rotation::cur())]
                                .clone(),
                                halo2_proofs::plonk::Any::Instance => instance_evals
                                    [vk.cs.get_any_query_index(*column, Rotation::cur())]
                                .clone(),
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
                    .concat()
            })
            .collect::<Vec<_>>();

        let permutation_evaluated = permutation_evaluated_sets
            .into_iter()
            .zip(permutation_evaluated_evals.into_iter())
            .map(
                |(permutation_evaluated_set, permutation_evaluated_eval)| Evaluated {
                    x: x.clone(),
                    sets: permutation_evaluated_set,
                    evals: permutation_evaluated_eval,
                    chunk_len: vk.cs.degree() - 2,
                    _m: PhantomData,
                },
            )
            .collect();

        let lookup_evaluated = lookups_committed
            .into_iter()
            .map(|lookups| -> Result<Vec<_>, _> {
                lookups
                    .into_iter()
                    .map(|lookup| lookup.evaluate(transcript))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let lookup_evaluated = lookup_evaluated
            .into_iter()
            .map(|vec| {
                vec.into_iter()
                    .zip(vk.cs.lookups.iter())
                    .map(|(lookup, argument)| {
                        Ok(crate::verify::halo2::lookup::Evaluated {
                            input_expressions: argument
                                .input_expressions
                                .iter()
                                .map(|expr| convert_expression(sgate, pgate, ctx, expr.clone()))
                                .collect::<Result<Vec<_>, _>>()?,
                            table_expressions: argument
                                .table_expressions
                                .iter()
                                .map(|expr| convert_expression(sgate, pgate, ctx, expr.clone()))
                                .collect::<Result<Vec<_>, _>>()?,
                            committed: crate::verify::halo2::lookup::Committed {
                                permuted: crate::verify::halo2::lookup::PermutationCommitments {
                                    permuted_input_commitment: pgate.from_var(
                                        ctx,
                                        lookup.committed.permuted.permuted_input_commitment,
                                    )?,
                                    permuted_table_commitment: pgate.from_var(
                                        ctx,
                                        lookup.committed.permuted.permuted_table_commitment,
                                    )?,
                                },
                                product_commitment: pgate
                                    .from_var(ctx, lookup.committed.product_commitment)?,
                            },
                            product_eval: sgate.from_constant(ctx, lookup.product_eval)?,
                            product_next_eval: sgate.from_var(ctx, lookup.product_next_eval)?,
                            permuted_input_eval: sgate.from_var(ctx, lookup.permuted_input_eval)?,
                            permuted_input_inv_eval: sgate
                                .from_var(ctx, lookup.permuted_input_inv_eval)?,
                            permuted_table_eval: sgate.from_var(ctx, lookup.permuted_table_eval)?,
                            _m: PhantomData,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, Error>>()
            .unwrap();

        let fixed_commitments = vk
            .fixed_commitments
            .iter()
            .map(|&affine| pgate.from_constant(ctx, affine))
            .collect::<Result<Vec<_>, Error>>()
            .unwrap();

        let v: ChallengeScalar<<M as Engine>::G1Affine, T> = transcript.squeeze_challenge_scalar();
        let u: ChallengeScalar<<M as Engine>::G1Affine, T> = transcript.squeeze_challenge_scalar();

        let mut w = vec![];
        while let Ok(p) = transcript.read_point() {
            let p = pgate.from_var(ctx, p)?;
            w.push(p)
        }

        Ok(VerifierParams::<C, S, P, Error> {
            gates: vk
                .cs
                .gates
                .iter()
                .map(|gate| {
                    gate.polys
                        .iter()
                        .map(|expr| convert_expression(sgate, pgate, ctx, expr.clone()))
                        .collect::<Result<Vec<_>, Error>>()
                })
                .collect::<Result<Vec<_>, Error>>()?,
            common: PlonkCommonSetup { l, n },
            lookup_evaluated,
            permutation_evaluated,
            instance_commitments,
            instance_evals,
            instance_queries: vk
                .cs
                .instance_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            advice_commitments,
            advice_evals,
            advice_queries: vk
                .cs
                .advice_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            fixed_commitments,
            fixed_evals,
            fixed_queries: vk
                .cs
                .fixed_queries
                .iter()
                .map(|column| (column.0.index, column.1 .0 as i32))
                .collect(),
            permutation_commitments: vk
                .permutation
                .commitments
                .iter()
                .map(|commit| pgate.from_var(ctx, *commit))
                .collect::<Result<Vec<_>, Error>>()?,
            permutation_evals: permutations_common
                .permutation_evals
                .into_iter()
                .map(|s| sgate.from_var(ctx, s))
                .collect::<Result<Vec<_>, Error>>()?,
            vanish_commitments: h_commitments,
            random_commitment,
            random_eval,
            beta,
            gamma,
            theta,
            delta: sgate.from_constant(
                ctx,
                <<M::G1Affine as CurveAffine>::ScalarExt as FieldExt>::DELTA,
            )?,
            x,
            x_next,
            x_last,
            x_inv,
            xn,
            y,
            u: sgate.from_constant(ctx, *u)?,
            v: sgate.from_constant(ctx, *v)?,
            xi: sgate.from_constant(ctx, xi)?,
            omega: sgate.from_constant(ctx, vk.domain.get_omega())?,
            w,
            _ctx: PhantomData,
            _error: PhantomData,
        })
    }
}

pub fn sanity_check_fn(
    params: &VerifierParams<
        (),
        <G1Affine as CurveAffine>::ScalarExt,
        <G1Affine as CurveAffine>::CurveExt,
        (),
    >,
    expected_queries: Vec<VerifierQuery<G1Affine>>,
) -> () {
    let sgate = FieldCode::<Fp>::default();
    let pgate = PointCode::<G1Affine>::default();
    let ctx = &mut ();

    let queries = params.queries(&sgate, ctx).unwrap();
    assert_eq!(queries.len(), expected_queries.len());

    queries
        .iter()
        .zip(expected_queries.iter())
        .for_each(|(q, e)| {
            assert_eq!(q.point, e.point);
            let (commit, eval) = q.s.eval(&sgate, &pgate, &mut ()).unwrap();
            let mut msm = MSM::new();
            match e.commitment {
                CommitmentReference::Commitment(c) => {
                    msm.append_term(<G1Affine as CurveAffine>::ScalarExt::one(), *c);
                }
                CommitmentReference::MSM(m) => {
                    msm.add_msm(m);
                }
            };
            let expected_commitment = msm.eval();
            assert_eq!(eval.unwrap(), e.eval);
            assert_eq!(commit.unwrap().to_affine(), expected_commitment);
            // TODO: compare q.s with e.commitment and eval
        })
}
