use eth_types::Field;
use halo2_proofs::{
    arithmetic::{CurveAffine, FieldExt, MultiMillerLoop},
    circuit::{floor_planner::V1, Layouter},
    plonk::{create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
    poly::{commitment::Params, Rotation},
    transcript::{Challenge255, PoseidonWrite},
};
use halo2_snark_aggregator_api::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip, field::ArithFieldChip},
    mock::transcript_encode::PoseidonEncode,
    systems::halo2::{
        transcript::PoseidonTranscriptRead,
        verify::{verify_aggregation_proofs_in_chip, ProofData},
    },
};
use pairing_bn256::{arithmetic::Engine, bn256::Bn256};
use rand::SeedableRng;
use rand_pcg::Pcg32;
use std::marker::PhantomData;
use zkevm_circuits::evm_circuit::test::TestCircuit;

type G1Affine = <Bn256 as Engine>::G1Affine;
type Fr = <G1Affine as CurveAffine>::ScalarExt;

#[derive(Debug, Default)]
pub struct CounterContext {
    n_add: usize,
    n_sub: usize,
    n_assign_zero: usize,
    n_assign_one: usize,
    n_assign_const: usize,
    n_assign_var: usize,
    n_mul: usize,
    n_div: usize,
    n_square: usize,
    n_mul_add_constant: usize,
    w_add: usize,
    w_sub: usize,
    w_assign_zero: usize,
    w_assign_one: usize,
    w_assign_const: usize,
    w_assign_var: usize,
    w_scalar_mul: usize,
}

#[derive(Default)]
pub struct NoopFieldChip<F> {
    _phantom: PhantomData<F>,
}

impl<F: FieldExt> ArithCommonChip for NoopFieldChip<F> {
    type Context = CounterContext;
    type Value = F;
    type AssignedValue = ();
    type Error = Error;

    fn add(
        &self,
        ctx: &mut Self::Context,
        _: &Self::AssignedValue,
        _: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        ctx.n_add += 1;
        Ok(())
    }

    fn sub(
        &self,
        ctx: &mut Self::Context,
        _: &Self::AssignedValue,
        _: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        ctx.n_sub += 1;
        Ok(())
    }

    fn assign_zero(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        ctx.n_assign_zero += 1;
        Ok(())
    }

    fn assign_one(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        ctx.n_assign_one += 1;
        Ok(())
    }

    fn assign_const(
        &self,
        ctx: &mut Self::Context,
        _: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        ctx.n_assign_const += 1;
        Ok(())
    }

    fn assign_var(
        &self,
        ctx: &mut Self::Context,
        _: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        ctx.n_assign_var += 1;
        Ok(())
    }

    fn to_value(&self, _: &Self::AssignedValue) -> Result<Self::Value, Self::Error> {
        Ok(Self::Value::default())
    }
}

impl<F: FieldExt> ArithFieldChip for NoopFieldChip<F> {
    type Field = F;
    type AssignedField = ();

    fn mul(
        &self,
        ctx: &mut Self::Context,
        _: &Self::AssignedField,
        _: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        ctx.n_mul += 1;
        Ok(())
    }

    fn div(
        &self,
        ctx: &mut Self::Context,
        _: &Self::AssignedField,
        _: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        ctx.n_div += 1;
        Ok(())
    }

    fn square(
        &self,
        ctx: &mut Self::Context,
        _: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        ctx.n_square += 1;
        Ok(())
    }

    fn sum_with_coeff_and_constant(
        &self,
        ctx: &mut Self::Context,
        values: Vec<(&Self::AssignedField, Self::Value)>,
        _: Self::Field,
    ) -> Result<Self::AssignedField, Self::Error> {
        // PLONK with 5 wires
        ctx.n_add += (values.len() + 4) / 5;
        Ok(())
    }

    fn mul_add_constant(
        &self,
        ctx: &mut Self::Context,
        _: &Self::AssignedField,
        _: &Self::AssignedField,
        _: Self::Field,
    ) -> Result<Self::AssignedField, Self::Error> {
        ctx.n_mul_add_constant += 1;
        Ok(())
    }
}

#[derive(Default)]
pub struct NoopEccChip<C> {
    _phantom: PhantomData<C>,
}

impl<C: CurveAffine> ArithCommonChip for NoopEccChip<C> {
    type Context = CounterContext;
    type Value = C;
    type AssignedValue = ();
    type Error = Error;

    fn add(
        &self,
        ctx: &mut Self::Context,
        _: &Self::AssignedValue,
        _: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        ctx.w_add += 1;
        Ok(())
    }

    fn sub(
        &self,
        ctx: &mut Self::Context,
        _: &Self::AssignedValue,
        _: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        ctx.w_sub += 1;
        Ok(())
    }

    fn assign_zero(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        ctx.w_assign_zero += 1;
        Ok(())
    }

    fn assign_one(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        ctx.w_assign_one += 1;
        Ok(())
    }

    fn assign_const(
        &self,
        ctx: &mut Self::Context,
        _: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        ctx.w_assign_const += 1;
        Ok(())
    }

    fn assign_var(
        &self,
        ctx: &mut Self::Context,
        _: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        ctx.w_assign_var += 1;
        Ok(())
    }

    fn to_value(&self, _: &Self::AssignedValue) -> Result<Self::Value, Self::Error> {
        Ok(Self::Value::default())
    }
}

impl<C: CurveAffine> ArithEccChip for NoopEccChip<C> {
    type Point = C;
    type AssignedPoint = ();
    type Scalar = C::ScalarExt;
    type AssignedScalar = ();
    type Native = C::ScalarExt;
    type AssignedNative = ();

    type ScalarChip = NoopFieldChip<C::ScalarExt>;
    type NativeChip = NoopFieldChip<C::ScalarExt>;

    fn scalar_mul(
        &self,
        ctx: &mut Self::Context,
        _: &Self::AssignedScalar,
        _: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        ctx.w_scalar_mul += 1;
        Ok(())
    }
}

#[derive(Default)]
struct NoopCircuit<C: CurveAffine> {
    _phantom: PhantomData<C>,
}

impl<C: CurveAffine> Circuit<C::ScalarExt> for NoopCircuit<C> {
    type Config = ();
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Default::default()
    }

    fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
        let columns = [(); 8].map(|_| meta.advice_column());
        meta.create_gate("", |meta| {
            columns
                .iter()
                .flat_map(|&column| {
                    (0..8)
                        .map(|rotation| meta.query_advice(column, Rotation(rotation)))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        });
    }

    fn synthesize(&self, _: Self::Config, _: impl Layouter<C::ScalarExt>) -> Result<(), Error> {
        Ok(())
    }
}

fn run<E: Engine<Scalar = F> + MultiMillerLoop, F: Field>() {
    let (params_verifier, vk, instances, proof) = {
        let circuit = TestCircuit::<E::Scalar>::default();
        let params = Params::<E::G1Affine>::unsafe_setup_rng::<E, _>(9, Pcg32::seed_from_u64(0));
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, keygen_vk(&params, &circuit).unwrap(), &circuit).unwrap();
        let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(Vec::new());
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[&[]],
            Pcg32::seed_from_u64(0),
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();

        (params.verifier::<E>(0).unwrap(), vk, Vec::new(), proof)
    };

    let nchip = &NoopFieldChip::<E::Scalar>::default();
    let schip = nchip;
    let pchip = &NoopEccChip::<E::G1Affine>::default();
    let ctx = &mut CounterContext::default();
    let transcript =
        PoseidonTranscriptRead::<_, E::G1Affine, NoopEccChip<_>, PoseidonEncode, 9, 8>::new(
            proof.as_slice(),
            ctx,
            nchip,
            8,
            33,
        )
        .unwrap();
    let proof_data = ProofData {
        instances: &vec![instances],
        transcript,
        key: String::new(),
        _phantom: PhantomData,
    };

    let mut transcript = PoseidonTranscriptRead::<_, E::G1Affine, _, PoseidonEncode, 9, 8>::new(
        &[][..],
        ctx,
        nchip,
        8,
        33,
    )
    .unwrap();
    verify_aggregation_proofs_in_chip(
        ctx,
        nchip,
        schip,
        pchip,
        &vk,
        &params_verifier,
        vec![proof_data],
        &mut transcript,
    )
    .unwrap();

    println!("{:#?}", ctx);
}

fn main() {
    run::<Bn256, Fr>()
}
