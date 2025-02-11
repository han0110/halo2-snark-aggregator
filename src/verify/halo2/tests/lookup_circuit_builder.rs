use std::marker::PhantomData;

use crate::arith::code::{FieldCode, PointCode};
use crate::field::bn_to_field;
use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};

use crate::verify::halo2::verify::{sanity_check_fn, VerifierParams};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof_check, Advice, Circuit, Column,
    ConstraintSystem, Error, Instance, SingleVerifier,
};
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::Challenge255;
use num_bigint::BigUint;
use pairing_bn256::bn256::{Bn256, G1Affine};
use rand::SeedableRng;
use rand_pcg::Pcg32;

#[derive(Clone, Debug)]
struct MyConfig<F: FieldExt> {
    input: Column<Instance>,
    table: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> MyConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let config = Self {
            input: meta.instance_column(),
            table: meta.advice_column(),
            _marker: PhantomData,
        };

        // Lookup on even numbers
        meta.lookup_any("even number", |meta| {
            let input = meta.query_instance(config.input, Rotation::cur());
            let table = meta.query_advice(config.table, Rotation::cur());

            vec![(input, table)]
        });

        config
    }

    fn load_table(&self, mut layouter: impl Layouter<F>, values: &[F]) -> Result<(), Error> {
        layouter.assign_region(
            || "load values for even lookup table",
            |mut region| {
                for (offset, value) in values.iter().enumerate() {
                    region.assign_advice(
                        || "even table value",
                        self.table,
                        offset,
                        || Ok(*value),
                    )?;
                }

                Ok(())
            },
        )
    }
}

#[derive(Default, Clone)]
struct MyCircuit<F: FieldExt> {
    lookup_table: Vec<F>,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = MyConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::Config::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load_table(layouter.namespace(|| "lookup table"), &self.lookup_table)?;

        Ok(())
    }
}

pub(in crate) fn build_verifier_params(
    sanity_check: bool,
) -> Result<
    VerifierParams<
        (),
        <G1Affine as CurveAffine>::ScalarExt,
        <G1Affine as CurveAffine>::CurveExt,
        (),
    >,
    halo2_proofs::plonk::Error,
> {
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{PoseidonRead, PoseidonWrite};
    use pairing_bn256::bn256::Fr as Fp;

    let fc = FieldCode::<<G1Affine as CurveAffine>::ScalarExt>::default();
    let pc = PointCode::<G1Affine>::default();

    let u = bn_to_field(&BigUint::from_bytes_be(b"0"));

    let lookup_table = vec![
        Fp::from(0),
        Fp::from(2),
        Fp::from(4),
        Fp::from(6),
        Fp::from(8),
    ];

    let circuit = MyCircuit::<Fp> { lookup_table };

    const K: u32 = 4;
    let public_inputs_size = 2;

    let params: Params<G1Affine> =
        Params::<G1Affine>::unsafe_setup_rng::<Bn256, _>(K, Pcg32::seed_from_u64(42));

    let params_verifier: ParamsVerifier<Bn256> = params.verifier(public_inputs_size).unwrap();
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

    let lookup = &vec![Fp::from(0), Fp::from(2)];

    create_proof(
        &params,
        &pk,
        &[circuit.clone()],
        &[&[lookup]],
        Pcg32::seed_from_u64(42),
        &mut transcript,
    )
    .expect("proof generation should not fail");

    let proof = transcript.finalize();
    let instances: &[&[&[Fp]]] = &[&[lookup]];

    let mut transcript = PoseidonRead::<_, G1Affine, Challenge255<G1Affine>>::init(&proof[..]);

    let params = VerifierParams::from_transcript_pure::<Bn256, _, _, _, _>(
        &fc,
        &pc,
        &mut (),
        u,
        instances,
        pk.get_vk(),
        &params_verifier,
        &mut transcript,
    )
    .unwrap();

    let strategy = SingleVerifier::new(&params_verifier);
    let mut transcript = PoseidonRead::<_, _, Challenge255<_>>::init(&proof[..]);

    if sanity_check {
        assert!(verify_proof_check(
            &params_verifier,
            pk.get_vk(),
            strategy,
            instances,
            &mut transcript,
            |queries| sanity_check_fn(&params, queries),
        )
        .is_ok());
    }

    Ok(params)
}
