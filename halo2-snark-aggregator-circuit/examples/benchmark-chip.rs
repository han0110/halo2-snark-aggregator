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
    arithmetic::{BaseExt, CurveAffine},
    circuit::{floor_planner::V1, Layouter},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2_snark_aggregator_api::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip},
    hash::poseidon::PoseidonChip,
};
use halo2_snark_aggregator_circuit::chips::{ecc_chip::EccChip, scalar_chip::ScalarChip};
use pairing_bn256::{arithmetic::Engine, bn256::Bn256};
use std::marker::PhantomData;

type G1Affine = <Bn256 as Engine>::G1Affine;

const COMMON_RANGE_BITS: usize = 17usize;

macro_rules! row_usage {
    ($ctx:ident, $operation:expr) => {{
        let offset = *$ctx.offset;
        $operation;
        *$ctx.offset - offset
    }};
}

macro_rules! print_row_usage {
    ($target:expr, $ctx:ident, $operation:expr) => {
        let usage = row_usage!($ctx, $operation);
        let log2_usage = (usage as f64).log2();
        println!(
            "{:?}: {} ({:.2} / {:.2})",
            $target,
            usage,
            log2_usage,
            25f64 - log2_usage
        );
    };
}

#[derive(Debug, Clone, Copy)]
enum BenchmarkTarget {
    EccLoad,
    EccAdd,
    EccMul,
    PoseidonPermutation,
}

#[derive(Default)]
struct BenchmarkCircuit<C: CurveAffine> {
    target: Option<BenchmarkTarget>,
    _phantom: PhantomData<C>,
}

impl<C: CurveAffine> BenchmarkCircuit<C> {
    fn new(target: BenchmarkTarget) -> Self {
        Self {
            target: Some(target),
            _phantom: PhantomData,
        }
    }
}

impl<C: CurveAffine> Circuit<C::ScalarExt> for BenchmarkCircuit<C> {
    type Config = (FiveColumnBaseGateConfig, RangeGateConfig);
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Default::default()
    }

    fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
        let base_gate_config = FiveColumnBaseGate::configure(meta);
        let range_gate_config =
            FiveColumnRangeGate::<'_, C::Base, C::ScalarExt, COMMON_RANGE_BITS>::configure(
                meta,
                &base_gate_config,
            );

        (base_gate_config, range_gate_config)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::ScalarExt>,
    ) -> Result<(), Error> {
        let base_gate = FiveColumnBaseGate::new(config.0);
        let range_gate = FiveColumnRangeGate::<'_, C::Base, C::ScalarExt, COMMON_RANGE_BITS>::new(
            config.1, &base_gate,
        );
        let integer_chip = FiveColumnIntegerChip::new(&range_gate);
        let ecc_chip = NativeEccChip::<C>::new(&integer_chip);

        let nchip = &ScalarChip::new(&base_gate);
        let schip = nchip;
        let pchip = &EccChip::new(&ecc_chip);

        layouter.assign_region(
            || "",
            |region| {
                let ctx = &mut Context::new(region, 0);

                if let Some(target) = self.target {
                    match target {
                        BenchmarkTarget::EccLoad => {
                            print_row_usage!(
                                target,
                                ctx,
                                pchip.assign_var(
                                    ctx,
                                    (C::generator() * C::ScalarExt::rand()).into()
                                )?
                            );
                        }
                        BenchmarkTarget::EccAdd => {
                            let a = pchip
                                .assign_var(ctx, (C::generator() * C::ScalarExt::rand()).into())?;
                            let b = pchip
                                .assign_var(ctx, (C::generator() * C::ScalarExt::rand()).into())?;
                            print_row_usage!(target, ctx, pchip.add(ctx, &a, &b)?);
                        }
                        BenchmarkTarget::EccMul => {
                            let a = schip.assign_var(ctx, C::ScalarExt::rand())?;
                            let b = pchip
                                .assign_var(ctx, (C::generator() * C::ScalarExt::rand()).into())?;
                            print_row_usage!(target, ctx, pchip.scalar_mul(ctx, &a, &b)?);
                        }
                        BenchmarkTarget::PoseidonPermutation => {
                            let mut poseidon_chip =
                                PoseidonChip::<_, 9, 8>::new(ctx, schip, 8, 33)?;
                            print_row_usage!(target, ctx, poseidon_chip.squeeze(ctx, schip)?);
                        }
                    }
                };

                Ok(())
            },
        )?;

        Ok(())
    }
}

fn main() {
    for target in [
        BenchmarkTarget::EccLoad,
        BenchmarkTarget::EccAdd,
        BenchmarkTarget::EccMul,
        BenchmarkTarget::PoseidonPermutation,
    ] {
        let circuit = BenchmarkCircuit::<G1Affine>::new(target);
        MockProver::run(18, &circuit, Vec::new()).unwrap();
    }
}
