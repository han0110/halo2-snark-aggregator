use crate::arith::api::ContextGroup;
use crate::circuits::ecc_circuit::AssignedPoint;
use crate::circuits::five::integer_circuit::FiveColumnIntegerCircuit;
use crate::circuits::native_ecc_circuit::NativeEccCircuit;
use crate::circuits::transcript_encode_circuit::PoseidonEncode;
use crate::field::bn_to_field;
use crate::gates::base_gate::{AssignedValue, RegionAux};
use crate::gates::five::base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig};
use crate::gates::five::range_gate::FiveColumnRangeGate;
use crate::gates::range_gate::RangeGateConfig;
use crate::schema::ast::EvaluationAST;
use crate::schema::SchemaGenerator;
use crate::verify::halo2::tests::mul_circuit_builder::MyCircuit;
use crate::verify::halo2::verify::transcript::PoseidonTranscriptRead;
use crate::verify::halo2::verify::VerifierParams;
use group::ff::Field;
use group::Group;
use halo2_proofs::arithmetic::{CurveAffine, MillerLoopResult, MultiMillerLoop};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, VerifyingKey};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::transcript::{Challenge255, PoseidonWrite};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use num_bigint::BigUint;
use pairing_bn256::bn256::{Bn256, Fq, Fr, G1Affine};
use rand::SeedableRng;
use rand_pcg::Pcg32;
use rand_xorshift::XorShiftRng;
use std::marker::PhantomData;

enum TestCase {
    Normal,
}

impl Default for TestCase {
    fn default() -> TestCase {
        TestCase::Normal
    }
}

#[derive(Clone)]
struct TestFiveColumnHalo2VerifyCircuitConfig {
    base_gate_config: FiveColumnBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Default)]
struct TestFiveColumnHalo2VerifyCircuitCircuit<C: CurveAffine> {
    test_case: TestCase,
    _phantom_w: PhantomData<C>,
    _phantom_n: PhantomData<Fr>,
}

const COMMON_RANGE_BITS: usize = 17usize;
const K: u32 = 22u32;

impl TestFiveColumnHalo2VerifyCircuitCircuit<G1Affine> {
    fn random() -> Fr {
        let seed = chrono::offset::Utc::now()
            .timestamp_nanos()
            .try_into()
            .unwrap();
        let rng = XorShiftRng::seed_from_u64(seed);
        Fr::random(rng)
    }

    fn setup_test(
        &self,
        ecc_gate: &NativeEccCircuit<'_, G1Affine>,
        base_gate: &FiveColumnBaseGate<Fr>,
        r: &mut RegionAux<'_, '_, Fr>,
    ) -> Result<(), Error> {
        let public_inputs_size = 1;
        let u = bn_to_field::<Fr>(&BigUint::from_bytes_be(b"0"));

        let circuit = MyCircuit::<Fr> {
            a: Some(Fr::from(1)),
            b: Some(Fr::from(1)),
        };

        let params: Params<G1Affine> =
            Params::<G1Affine>::unsafe_setup_rng::<Bn256, _>(6, Pcg32::seed_from_u64(42));
        let params_verifier: ParamsVerifier<Bn256> = params.verifier(public_inputs_size).unwrap();
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        let mut transcript = PoseidonWrite::<_, _, Challenge255<_>>::init(vec![]);

        let instance = Fr::one();
        create_proof(
            &params,
            &pk,
            &[circuit.clone()],
            &[&[&[instance]]],
            Pcg32::seed_from_u64(42),
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();

        /*
            let mut transcript = PoseidonRead::<_, G1Affine, Challenge255<G1Affine>>::init(&proof[..]);

            let params = VerifierParams::from_transcript_pure::<Bn256, _, _, _, _>(
                base_gate,
                ecc_gate,
                r,
                u,
                &[&[&[instance]]],
                pk.get_vk(),
                &params_verifier,
                &mut transcript,
            )
            .unwrap();
        */

        let mut transcript = PoseidonTranscriptRead::<
            _,
            G1Affine,
            RegionAux<'_, '_, Fr>,
            AssignedValue<Fr>,
            AssignedPoint<G1Affine, Fr>,
            Error,
            FiveColumnBaseGate<Fr>,
            NativeEccCircuit<'_, G1Affine>,
            PoseidonEncode,
            9usize,
            8usize,
        >::new(&proof[..], r, base_gate, 8usize, 33usize)
        .unwrap();

        let params = VerifierParams::from_transcript(
            base_gate,
            ecc_gate,
            r,
            u,
            &[&[&[instance]]],
            pk.get_vk() as &VerifyingKey<G1Affine>,
            &params_verifier,
            &mut transcript,
        )
        .unwrap();

        let guard = params.batch_multi_open_proofs(r, base_gate, ecc_gate)?;

        let (left_s, left_e) = guard.w_x.eval(base_gate, ecc_gate, r)?;
        let (right_s, right_e) = guard.w_g.eval(base_gate, ecc_gate, r)?;

        let one = ecc_gate.one(r)?;
        let left_final = if left_e.is_none() {
            left_s.unwrap()
        } else {
            let left_es = ecc_gate.scalar_mul(r, &left_e.unwrap(), &one)?;
            ecc_gate.add(r, &left_s.unwrap(), &left_es)?
        };

        let right_final = {
            let right_es = ecc_gate.scalar_mul(r, &right_e.unwrap(), &one)?;
            ecc_gate.minus(r, &right_s.unwrap(), &right_es)?
        };

        let left = ecc_gate.to_value(&left_final)?;
        let right = ecc_gate.to_value(&right_final)?;

        let s_g2_prepared = <Bn256 as MultiMillerLoop>::G2Prepared::from(params_verifier.s_g2);
        let n_g2_prepared = <Bn256 as MultiMillerLoop>::G2Prepared::from(-params_verifier.g2);
        let success = bool::from(
            <Bn256 as MultiMillerLoop>::multi_miller_loop(&[
                (&left, &s_g2_prepared),
                (&right, &n_g2_prepared),
            ])
            .final_exponentiation()
            .is_identity(),
        );
        assert!(success);

        Ok(())
    }
}

impl Circuit<Fr> for TestFiveColumnHalo2VerifyCircuitCircuit<G1Affine> {
    type Config = TestFiveColumnHalo2VerifyCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let base_gate_config = FiveColumnBaseGate::<Fr>::configure(meta);
        let range_gate_config = FiveColumnRangeGate::<'_, Fq, Fr, COMMON_RANGE_BITS>::configure(
            meta,
            &base_gate_config,
        );
        TestFiveColumnHalo2VerifyCircuitConfig {
            base_gate_config,
            range_gate_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let base_gate = FiveColumnBaseGate::new(config.base_gate_config);
        let range_gate = FiveColumnRangeGate::<'_, Fq, Fr, COMMON_RANGE_BITS>::new(
            config.range_gate_config,
            &base_gate,
        );
        let integer_gate = FiveColumnIntegerCircuit::new(&range_gate);
        let ecc_gate = NativeEccCircuit::new(&integer_gate);

        range_gate
            .init_table(&mut layouter, &integer_gate.helper.integer_modulus)
            .unwrap();

        layouter.assign_region(
            || "base",
            |mut region| {
                let mut base_offset = 0usize;
                let mut aux = RegionAux::new(&mut region, &mut base_offset);
                let r = &mut aux;
                let round = 1;
                for _ in 0..round {
                    match self.test_case {
                        TestCase::Normal => self.setup_test(&ecc_gate, &base_gate, r),
                    }?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_five_column_halo2_verify() {
    let circuit = TestFiveColumnHalo2VerifyCircuitCircuit::<G1Affine> {
        test_case: TestCase::Normal,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };

    assert_eq!(prover.verify(), Ok(()));
}
