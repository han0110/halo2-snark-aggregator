use crate::field::{bn_to_field, field_to_bn, get_d_range_bits_in_mul};
use crate::gates::base_gate::{AssignedCondition, BaseGateOps};
use crate::gates::base_gate::{AssignedValue, RegionAux};
use crate::gates::range_gate::RangeGateOps;
use halo2_proofs::arithmetic::{BaseExt, FieldExt};
use halo2_proofs::plonk::Error;
use num_bigint::BigUint;
use num_integer::Integer;
use std::{marker::PhantomData, vec};

#[derive(Clone, Debug)]
pub struct AssignedInteger<W: BaseExt, N: FieldExt> {
    pub limbs_le: Vec<AssignedValue<N>>,
    pub native: Option<AssignedValue<N>>,
    pub overflows: usize,

    _phantom: PhantomData<W>,
}

impl<W: BaseExt, N: FieldExt> AssignedInteger<W, N> {
    pub fn new(limbs_le: Vec<AssignedValue<N>>, overflows: usize) -> Self {
        Self {
            limbs_le,
            native: None,
            overflows,
            _phantom: PhantomData,
        }
    }

    pub fn set_native(&mut self, native: AssignedValue<N>) {
        self.native = Some(native);
    }

    pub fn bn(&self, limb_modulus: &BigUint) -> BigUint {
        self.limbs_le
            .iter()
            .rev()
            .fold(BigUint::from(0u64), |acc, v| {
                acc * limb_modulus + field_to_bn(&v.value)
            })
    }

    pub fn w(&self, limb_modulus: &BigUint, w_modulus: &BigUint) -> W {
        let v = self.bn(limb_modulus);
        let (_, rem) = v.div_rem(w_modulus);
        bn_to_field(&rem)
    }
}

pub struct IntegerCircuitHelper<
    W: BaseExt,
    N: FieldExt,
    const LIMBS: usize,
    const LIMB_WIDTH: usize,
> {
    pub limb_modulus: BigUint,
    pub integer_modulus: BigUint,
    pub limb_modulus_on_n: N,
    pub limb_modulus_exps: [N; LIMBS],
    pub w_modulus: BigUint,
    pub w_modulus_limbs_le: [BigUint; LIMBS],
    pub n_modulus: BigUint,
    pub w_native: N,
    pub w_ceil_bits: usize,
    pub n_floor_bits: usize,
    pub d_bits: usize,
    pub _phantom_w: PhantomData<W>,
}

impl<W: BaseExt, N: FieldExt, const LIMBS: usize, const LIMB_WIDTH: usize>
    IntegerCircuitHelper<W, N, LIMBS, LIMB_WIDTH>
{
    pub fn w_to_limb_n_le(&self, w: &W) -> [N; LIMBS] {
        let bn = field_to_bn(w);
        self.bn_to_limb_n_le(&bn)
    }

    fn _bn_to_limb_le(bn: &BigUint, limb_modulus: &BigUint) -> [BigUint; LIMBS] {
        let mut ret = vec![];
        let mut n = bn.clone();

        for _ in 0..LIMBS - 1 {
            ret.push(&n % limb_modulus);
            n = n >> LIMB_WIDTH;
        }
        ret.push(n);
        ret.try_into().unwrap()
    }

    pub fn bn_to_limb_n_le(&self, bn: &BigUint) -> [N; LIMBS] {
        Self::_bn_to_limb_le(bn, &self.limb_modulus).map(|v| bn_to_field(&v))
    }

    pub fn bn_to_limb_le(&self, bn: &BigUint) -> [BigUint; LIMBS] {
        Self::_bn_to_limb_le(bn, &self.limb_modulus)
    }

    pub fn new() -> Self {
        let limb_modulus = BigUint::from(1u64) << LIMB_WIDTH;
        let integer_modulus = BigUint::from(1u64) << (LIMB_WIDTH * LIMBS);
        let limb_modulus_on_n: N = bn_to_field(&limb_modulus);
        let w_modulus = field_to_bn(&-W::one()) + 1u64;
        let n_modulus = field_to_bn(&-N::one()) + 1u64;
        let w_native = bn_to_field(&(&w_modulus % &n_modulus));
        let w_modulus_limbs_le = Self::_bn_to_limb_le(&w_modulus, &limb_modulus);
        let w_ceil_bits = w_modulus.bits() as usize + 1;
        let n_floor_bits = n_modulus.bits() as usize;

        let mut limb_modulus_exps = vec![];
        let mut acc = N::one();
        for _ in 0..LIMBS {
            limb_modulus_exps.push(acc);
            acc = acc * limb_modulus_on_n;
        }

        let d_bits = get_d_range_bits_in_mul::<W, N>(&integer_modulus);

        Self {
            _phantom_w: PhantomData,
            limb_modulus,
            integer_modulus,
            limb_modulus_on_n,
            limb_modulus_exps: limb_modulus_exps.try_into().unwrap(),
            w_modulus,
            n_modulus,
            w_native,
            w_modulus_limbs_le,
            w_ceil_bits,
            n_floor_bits,
            d_bits,
        }
    }
}

pub trait IntegerCircuitOps<W: BaseExt, N: FieldExt> {
    fn base_gate(&self) -> &dyn BaseGateOps<N>;
    fn range_gate(&self) -> &dyn RangeGateOps<W, N>;
    fn assign_nonleading_limb(&self, r: &mut RegionAux<N>, n: N)
        -> Result<AssignedValue<N>, Error>;
    fn assign_w_ceil_leading_limb(
        &self,
        r: &mut RegionAux<N>,
        n: N,
    ) -> Result<AssignedValue<N>, Error>;
    fn assign_n_floor_leading_limb(
        &self,
        r: &mut RegionAux<N>,
        n: N,
    ) -> Result<AssignedValue<N>, Error>;
    fn assign_d_leading_limb(&self, r: &mut RegionAux<N>, n: N) -> Result<AssignedValue<N>, Error>;
    fn assign_w(&self, r: &mut RegionAux<N>, w: &W) -> Result<AssignedInteger<W, N>, Error>;
    fn assign_d(&self, r: &mut RegionAux<N>, v: &BigUint) -> Result<Vec<AssignedValue<N>>, Error>;
    fn assign_integer(
        &self,
        r: &mut RegionAux<N>,
        v: &BigUint,
    ) -> Result<Vec<AssignedValue<N>>, Error>;
    fn conditionally_reduce(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N>,
    ) -> Result<(), Error>;
    fn reduce(&self, r: &mut RegionAux<N>, a: &mut AssignedInteger<W, N>) -> Result<(), Error>;
    fn native<'a>(
        &self,
        r: &mut RegionAux<N>,
        a: &'a mut AssignedInteger<W, N>,
    ) -> Result<&'a AssignedValue<N>, Error>;
    fn add(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn sub(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn neg(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn mul(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N>,
        b: &mut AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn div(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N>,
        b: &mut AssignedInteger<W, N>,
    ) -> Result<(AssignedCondition<N>, AssignedInteger<W, N>), Error>;
    fn is_zero(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N>,
    ) -> Result<AssignedCondition<N>, Error>;
    fn is_equal(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N>,
        b: &mut AssignedInteger<W, N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let mut diff = self.sub(r, a, b)?;
        self.is_zero(r, &mut diff)
    }
    fn assign_constant(&self, r: &mut RegionAux<N>, w: W) -> Result<AssignedInteger<W, N>, Error>;
    fn assert_equal(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<(), Error>;
    fn square(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn mul_small_constant(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N>,
        b: usize,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn bisec(
        &self,
        r: &mut RegionAux<N>,
        cond: &AssignedCondition<N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error>;
    fn get_w(&self, a: &AssignedInteger<W, N>) -> Result<W, Error>;
}

pub struct IntegerCircuit<'a, W: BaseExt, N: FieldExt, const LIMBS: usize, const LIMB_WIDTH: usize>
{
    pub range_gate: &'a dyn RangeGateOps<W, N>,
    pub helper: IntegerCircuitHelper<W, N, LIMBS, LIMB_WIDTH>,
}

impl<'a, W: BaseExt, N: FieldExt, const LIMBS: usize, const LIMB_WIDTH: usize>
    IntegerCircuit<'a, W, N, LIMBS, LIMB_WIDTH>
{
    pub fn new(range_gate: &'a dyn RangeGateOps<W, N>) -> Self {
        Self {
            range_gate,
            helper: IntegerCircuitHelper::new(),
        }
    }
}
