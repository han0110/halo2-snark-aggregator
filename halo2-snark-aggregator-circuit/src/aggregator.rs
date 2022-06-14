use crate::chips::{ecc_chip::EccChip, encode_chip::PoseidonEncodeChip, scalar_chip::ScalarChip};
use halo2_ecc_circuit_lib::{
    chips::{ecc_chip::AssignedPoint, native_ecc_chip::NativeEccChip},
    five::{
        base_gate::FiveColumnBaseGate, integer_chip::FiveColumnIntegerChip,
        range_gate::FiveColumnRangeGate,
    },
    gates::base_gate::Context,
};
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::Layouter,
    plonk::{Error, VerifyingKey},
};
use halo2_snark_aggregator_api::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip},
    commit, scalar,
    systems::halo2::{
        evaluation::{CommitQuery, EvaluationQuerySchema},
        multiopen::MultiOpenProof,
        transcript::PoseidonTranscriptRead,
        verify::verify_single_proof_no_eval,
    },
    transcript::read::TranscriptRead,
};
use std::fmt::Debug;

const R_F: usize = 8;
const R_P: usize = 33;

type PoseidonTranscript<R, C, A> = PoseidonTranscriptRead<R, C, A, PoseidonEncodeChip<A>, 9, 8>;

#[derive(Clone)]
pub struct RawProof<'a, C, I>
where
    C: CurveAffine,
    I: Clone + Debug,
{
    vk: &'a VerifyingKey<C>,
    // TODO: Use scalar instead of commitment
    instances: Vec<Vec<I>>,
    raw: Vec<u8>,
}

pub struct Proof<'a, C, A, T>
where
    C: CurveAffine,
    A: ArithEccChip<Point = C, Scalar = C::ScalarExt, Native = C::ScalarExt, Error = Error>,
    T: TranscriptRead<A>,
{
    vk: &'a VerifyingKey<C>,
    // TODO: Use scalar instead of commitment
    instances: Vec<Vec<A::AssignedPoint>>,
    transcript: T,
}

#[derive(Clone)]
pub struct AggregatedProof<P>
where
    P: Clone + Debug,
{
    w_x: P,
    w_g: P,
}

pub struct Aggregator<'a, C, const COMMON_RANGE_BITS: usize>
where
    C: CurveAffine,
{
    // TODO: Take mutiple (base_gate, range_gate) to horizontally scale
    base_gate: &'a FiveColumnBaseGate<C::Scalar>,
    range_gate: &'a FiveColumnRangeGate<'a, C::Base, C::Scalar, COMMON_RANGE_BITS>,
}

impl<'a, C, const COMMON_RANGE_BITS: usize> Aggregator<'a, C, COMMON_RANGE_BITS>
where
    C: CurveAffine,
{
    pub fn new(
        base_gate: &'a FiveColumnBaseGate<C::Scalar>,
        range_gate: &'a FiveColumnRangeGate<'a, C::Base, C::Scalar, COMMON_RANGE_BITS>,
    ) -> Self {
        Self {
            base_gate,
            range_gate,
        }
    }

    pub fn aggregate_all(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        raw_proofs: Vec<RawProof<C, AssignedPoint<C, C::Scalar>>>,
        key: String,
    ) -> Result<
        (
            Vec<Vec<Vec<AssignedPoint<C, C::Scalar>>>>,
            AggregatedProof<AssignedPoint<C, C::Scalar>>,
        ),
        Error,
    > {
        let nchip = &ScalarChip::new(self.base_gate);
        let schip = nchip;
        let integer_chip = FiveColumnIntegerChip::new(self.range_gate);
        let ecc_chip = NativeEccChip::<'_, C>::new(&integer_chip);
        let pchip = &EccChip::new(&ecc_chip);

        layouter.assign_region(
            || "",
            move |region| {
                let ctx = &mut Context::new(region, 0);
                let proofs = raw_proofs
                    .iter()
                    .map(|RawProof { vk, instances, raw }| {
                        Ok(Proof {
                            vk,
                            instances: instances.clone(),
                            transcript: PoseidonTranscript::new(
                                raw.as_slice(),
                                ctx,
                                schip,
                                R_F,
                                R_P,
                            )?,
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                aggregate_all(ctx, nchip, schip, pchip, proofs, key.clone())
            },
        )
    }

    pub fn aggregate(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        raw_proof: RawProof<C, AssignedPoint<C, C::Scalar>>,
        key: String,
        prev_aggregated: Option<&AggregatedProof<AssignedPoint<C, C::Scalar>>>,
    ) -> Result<
        (
            Vec<Vec<AssignedPoint<C, C::Scalar>>>,
            AggregatedProof<AssignedPoint<C, C::Scalar>>,
        ),
        Error,
    > {
        let nchip = &ScalarChip::new(self.base_gate);
        let schip = nchip;
        let integer_chip = FiveColumnIntegerChip::new(self.range_gate);
        let ecc_chip = NativeEccChip::<'_, C>::new(&integer_chip);
        let pchip = &EccChip::new(&ecc_chip);

        layouter.assign_region(
            || "",
            move |region| {
                let ctx = &mut Context::new(region, 0);
                let proof = Proof {
                    vk: raw_proof.vk,
                    instances: raw_proof.instances.clone(),
                    transcript: PoseidonTranscript::new(
                        raw_proof.raw.as_slice(),
                        ctx,
                        schip,
                        R_F,
                        R_P,
                    )?,
                };
                aggregate(
                    ctx,
                    nchip,
                    schip,
                    pchip,
                    proof,
                    key.clone(),
                    prev_aggregated,
                )
            },
        )
    }
}

fn aggregate_all<C, A, T>(
    ctx: &mut A::Context,
    nchip: &A::NativeChip,
    schip: &A::ScalarChip,
    pchip: &A,
    proofs: Vec<Proof<C, A, T>>,
    key: String,
) -> Result<
    (
        Vec<Vec<Vec<A::AssignedPoint>>>,
        AggregatedProof<A::AssignedPoint>,
    ),
    Error,
>
where
    C: CurveAffine,
    A: ArithEccChip<Point = C, Scalar = C::ScalarExt, Native = C::ScalarExt, Error = Error>,
    T: TranscriptRead<A>,
{
    assert!(!proofs.is_empty());

    proofs
        .into_iter()
        .enumerate()
        .fold(Ok((Vec::new(), None)), |acc, (idx, proof)| {
            acc.and_then(|(mut params, prev_aggregated)| {
                let (param, aggregated) = aggregate::<C, A, T>(
                    ctx,
                    nchip,
                    schip,
                    pchip,
                    proof,
                    format!("{key}_{idx}"),
                    prev_aggregated.as_ref(),
                )?;
                params.push(param);
                Ok((params, Some(aggregated)))
            })
        })
        .map(|(params, aggregated)| (params, aggregated.unwrap()))
}

fn aggregate<C, A, T>(
    ctx: &mut A::Context,
    nchip: &A::NativeChip,
    schip: &A::ScalarChip,
    pchip: &A,
    mut proof: Proof<C, A, T>,
    key: String,
    prev_aggregated: Option<&AggregatedProof<A::AssignedPoint>>,
) -> Result<
    (
        Vec<Vec<A::AssignedPoint>>,
        AggregatedProof<A::AssignedPoint>,
    ),
    Error,
>
where
    C: CurveAffine,
    A: ArithEccChip<Point = C, Scalar = C::ScalarExt, Native = C::ScalarExt, Error = Error>,
    T: TranscriptRead<A>,
{
    let prev_aggregated = prev_aggregated.map(|prev_aggregated| {
        let w_x = CommitQuery {
            key: format!("{key}_prev_aggregated_w_x"),
            commitment: Some(prev_aggregated.w_x.clone()),
            eval: None,
        };
        let w_g = CommitQuery {
            key: format!("{key}_prev_aggregated_w_g"),
            commitment: Some(prev_aggregated.w_g.clone()),
            eval: None,
        };

        MultiOpenProof {
            w_x: commit!(w_x),
            w_g: commit!(w_g),
        }
    });

    let (param, aggregated) = verify_single_proof_no_eval(
        ctx,
        nchip,
        schip,
        pchip,
        proof.instances.clone(),
        proof.vk,
        &mut proof.transcript,
        key,
    )?;

    let aggregated = evaluate(
        ctx,
        nchip,
        schip,
        pchip,
        &mut proof.transcript,
        aggregated,
        prev_aggregated,
    )?;

    Ok((param.advice_commitments, aggregated))
}

fn evaluate<C, A, T>(
    ctx: &mut A::Context,
    nchip: &A::NativeChip,
    schip: &A::ScalarChip,
    pchip: &A,
    transcript: &mut T,
    mut aggreagted: MultiOpenProof<A>,
    prev_aggreagted: Option<MultiOpenProof<A>>,
) -> Result<AggregatedProof<A::AssignedPoint>, Error>
where
    C: CurveAffine,
    A: ArithEccChip<Point = C, Scalar = C::ScalarExt, Native = C::ScalarExt, Error = Error>,
    T: TranscriptRead<A>,
{
    // Take the same approach of barretenberg.
    // Reference: https://github.com/AztecProtocol/barretenberg/blob/a5ac14bb0e774c400e45c64e5246ed29a2ed4dd8/barretenberg/src/aztec/stdlib/recursion/verifier/verifier.hpp#L331-L339
    if let Some(prev_aggreagted) = prev_aggreagted {
        let u = transcript.squeeze_challenge_scalar(ctx, nchip, schip)?;
        aggreagted.w_x = aggreagted.w_x + scalar!(u) * prev_aggreagted.w_x;
        aggreagted.w_g = aggreagted.w_g + scalar!(u) * prev_aggreagted.w_g;
    }

    let one = schip.assign_one(ctx)?;
    let (w_x_s, w_x_e) = aggreagted.w_x.eval::<_, A>(ctx, schip, pchip, &one)?;
    let (w_g_s, w_g_e) = aggreagted.w_g.eval::<_, A>(ctx, schip, pchip, &one)?;

    let generator = pchip.assign_one(ctx)?;
    let w_x = match w_x_e {
        None => w_x_s,
        Some(eval) => {
            let s = pchip.scalar_mul(ctx, &eval, &generator)?;
            pchip.add(ctx, &w_x_s, &s)?
        }
    };
    let w_g = match w_g_e {
        None => w_g_s,
        Some(eval) => {
            let s = pchip.scalar_mul(ctx, &eval, &generator)?;
            pchip.sub(ctx, &w_g_s, &s)?
        }
    };

    Ok(AggregatedProof { w_x, w_g })
}

#[cfg(test)]
mod test {
    use crate::{
        aggregator::{Aggregator, RawProof},
        chips::ecc_chip::EccChip,
    };
    use halo2_ecc_circuit_lib::{
        chips::native_ecc_chip::NativeEccChip,
        five::{
            base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig},
            integer_chip::FiveColumnIntegerChip,
            range_gate::FiveColumnRangeGate,
        },
        gates::{base_gate::Context, range_gate::RangeGateConfig},
    };
    use halo2_proofs::{
        arithmetic::{CurveAffine, MillerLoopResult, MultiMillerLoop},
        circuit::{floor_planner::V1, Layouter},
        dev::MockProver,
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error,
            SingleVerifier, VerifyingKey,
        },
        poly::commitment::{Params, ParamsVerifier},
        transcript::{Challenge255, PoseidonRead, PoseidonWrite},
    };
    use halo2_snark_aggregator_api::{
        arith::common::ArithCommonChip,
        tests::systems::halo2::lookup_test::test_circuit::test_circuit_builder,
    };
    use pairing_bn256::{
        bn256::{Bn256, Fr, G1Affine},
        group::{Curve, Group},
    };
    use rand_core::OsRng;
    use std::iter;

    const COMMON_RANGE_BITS: usize = 17;

    #[derive(Clone)]
    struct TestConfig {
        base_gate_config: FiveColumnBaseGateConfig,
        range_gate_config: RangeGateConfig,
    }

    struct TestCircuit<'a, M: MultiMillerLoop> {
        param: &'a ParamsVerifier<M>,
        raw_proofs: Vec<RawProof<'a, M::G1Affine, Vec<M::Scalar>>>,
    }

    impl<'a, M: MultiMillerLoop> Circuit<M::Scalar> for TestCircuit<'a, M> {
        type Config = TestConfig;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self {
                param: self.param,
                raw_proofs: self.raw_proofs.clone(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<M::Scalar>) -> Self::Config {
            let base_gate_config = FiveColumnBaseGate::configure(meta);
            let range_gate_config = FiveColumnRangeGate::<
                '_,
                <M::G1Affine as CurveAffine>::Base,
                M::Scalar,
                COMMON_RANGE_BITS,
            >::configure(meta, &base_gate_config);
            Self::Config {
                base_gate_config,
                range_gate_config,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<M::Scalar>,
        ) -> Result<(), Error> {
            let base_gate = FiveColumnBaseGate::new(config.base_gate_config);
            let range_gate = FiveColumnRangeGate::<'_, _, _, COMMON_RANGE_BITS>::new(
                config.range_gate_config,
                &base_gate,
            );
            let integer_chip = FiveColumnIntegerChip::new(&range_gate);
            let ecc_chip = NativeEccChip::<'_, M::G1Affine>::new(&integer_chip);
            let pchip = &EccChip::new(&ecc_chip);

            range_gate
                .init_table(
                    &mut layouter,
                    &FiveColumnIntegerChip::new(&range_gate)
                        .helper
                        .integer_modulus,
                )
                .unwrap();

            let raw_proofs = layouter.assign_region(
                || "",
                |region| {
                    let ctx = &mut Context::new(region, 0);

                    self.raw_proofs
                        .clone()
                        .into_iter()
                        .map(|RawProof { vk, instances, raw }| {
                            let instances = instances
                                .into_iter()
                                .map(|instances| {
                                    instances
                                        .into_iter()
                                        .map(|instances| {
                                            pchip.assign_var(
                                                ctx,
                                                self.param.commit_lagrange(instances).to_affine(),
                                            )
                                        })
                                        .collect::<Result<Vec<_>, Error>>()
                                })
                                .collect::<Result<Vec<_>, Error>>()?;
                            Ok(RawProof { vk, instances, raw })
                        })
                        .collect::<Result<Vec<_>, Error>>()
                },
            )?;

            let aggregator = Aggregator::new(&base_gate, &range_gate);
            let (_, aggregated) =
                aggregator.aggregate_all(&mut layouter, raw_proofs, "".to_string())?;

            // Sanity check
            assert!(bool::from(
                M::multi_miller_loop(&[
                    (
                        &pchip.to_value(&aggregated.w_x)?,
                        &M::G2Prepared::from(self.param.s_g2)
                    ),
                    (
                        &pchip.to_value(&aggregated.w_g)?,
                        &M::G2Prepared::from(-self.param.g2)
                    )
                ])
                .final_exponentiation()
                .is_identity(),
            ));

            Ok(())
        }
    }

    fn gen_vk_and_proof<M: MultiMillerLoop, ConcreteCircuit: Circuit<M::Scalar>>(
        param: &Params<M::G1Affine>,
        circuit: ConcreteCircuit,
        instances: &[&[M::Scalar]],
    ) -> (VerifyingKey<M::G1Affine>, Vec<u8>) {
        let pk = keygen_pk(param, keygen_vk(param, &circuit).unwrap(), &circuit).unwrap();
        let vk = keygen_vk(param, &circuit).unwrap();

        let proof = {
            let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof(
                param,
                &pk,
                &[circuit],
                [instances].as_slice(),
                OsRng,
                &mut transcript,
            )
            .unwrap();
            transcript.finalize()
        };

        let accept = {
            let param = param
                .verifier::<M>(
                    instances
                        .iter()
                        .map(|instances| instances.len())
                        .max()
                        .unwrap_or_default(),
                )
                .unwrap();
            let mut transcript = PoseidonRead::<_, _, Challenge255<_>>::init(proof.as_slice());
            verify_proof(
                &param,
                &vk,
                SingleVerifier::new(&param),
                [instances].as_slice(),
                &mut transcript,
            )
            .is_ok()
        };
        assert!(accept);

        (vk, proof)
    }

    #[test]
    fn test_aggregator() {
        let param = &Params::<G1Affine>::unsafe_setup::<Bn256>(8);
        let vk_and_proofs = iter::repeat_with(|| {
            let circuit = test_circuit_builder();
            let instance = vec![
                Fr::from(1),
                Fr::from(3),
                Fr::from(5),
                Fr::from(7),
                Fr::from(9),
            ];
            let (vk, proof) =
                gen_vk_and_proof::<Bn256, _>(param, circuit, [instance.as_slice()].as_slice());
            (vk, instance, proof)
        })
        .take(3)
        .collect::<Vec<_>>();

        let raw_proofs = vk_and_proofs
            .iter()
            .map(|(vk, instance, proof)| RawProof {
                vk,
                instances: vec![vec![instance.clone()]],
                raw: proof.clone(),
            })
            .collect::<Vec<_>>();

        let circuit = TestCircuit {
            param: &param.verifier::<Bn256>(5).unwrap(),
            raw_proofs,
        };
        assert!(MockProver::run(24, &circuit, Vec::new())
            .unwrap()
            .verify()
            .is_ok());
    }
}
