use alloc::vec::Vec;
use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::{
    default_babybear_poseidon2_16, BabyBear, GenericPoseidon2LinearLayersBabyBear,
    Poseidon2BabyBear,
};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_field::{extension::BinomialExtensionField, Field};
use p3_fri::{create_benchmark_fri_params_zk, HidingFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::{rngs::SmallRng, SeedableRng};
use spongefish::Permutation;
use spongefish_circuit::permutation::PermutationWitnessBuilder;

use crate::{HashInvocationAir, QueryAnswerPair, StarkRelationBackend};

pub const BABYBEAR_POSEIDON2_WIDTH: usize = 16;
pub const BABYBEAR_POSEIDON2_SBOX_DEGREE: u64 = 7;
pub const BABYBEAR_POSEIDON2_SBOX_REGISTERS: usize = 1;
pub const BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS: usize = 4;
pub const BABYBEAR_POSEIDON2_PARTIAL_ROUNDS: usize = 13;

pub type BabyBearPoseidon2_16Air = Poseidon2Air<
    BabyBear,
    GenericPoseidon2LinearLayersBabyBear,
    BABYBEAR_POSEIDON2_WIDTH,
    BABYBEAR_POSEIDON2_SBOX_DEGREE,
    BABYBEAR_POSEIDON2_SBOX_REGISTERS,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS,
>;

pub type BabyBearPoseidon2_16Cols<T> = Poseidon2Cols<
    T,
    BABYBEAR_POSEIDON2_WIDTH,
    BABYBEAR_POSEIDON2_SBOX_DEGREE,
    BABYBEAR_POSEIDON2_SBOX_REGISTERS,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS,
>;

pub type BabyBearPoseidon2_16RoundConstants = RoundConstants<
    BabyBear,
    BABYBEAR_POSEIDON2_WIDTH,
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS,
>;

pub type BabyBearPoseidon2Challenge = BinomialExtensionField<BabyBear, 4>;
pub type BabyBearTranscriptPerm = Poseidon2BabyBear<16>;
pub type BabyBearTranscriptHash = PaddingFreeSponge<BabyBearTranscriptPerm, 16, 8, 8>;
pub type BabyBearTranscriptCompress = TruncatedPermutation<BabyBearTranscriptPerm, 2, 8, 16>;
pub type BabyBearValMmcs = MerkleTreeHidingMmcs<
    <BabyBear as Field>::Packing,
    <BabyBear as Field>::Packing,
    BabyBearTranscriptHash,
    BabyBearTranscriptCompress,
    SmallRng,
    8,
    8,
>;
pub type BabyBearChallengeMmcs =
    ExtensionMmcs<BabyBear, BabyBearPoseidon2Challenge, BabyBearValMmcs>;
pub type BabyBearChallenger = DuplexChallenger<BabyBear, BabyBearTranscriptPerm, 16, 8>;
pub type BabyBearDft = p3_dft::Radix2DitParallel<BabyBear>;
pub type BabyBearPcs =
    HidingFriPcs<BabyBear, BabyBearDft, BabyBearValMmcs, BabyBearChallengeMmcs, SmallRng>;
pub type BabyBearPoseidon2StarkConfig =
    StarkConfig<BabyBearPcs, BabyBearPoseidon2Challenge, BabyBearChallenger>;

#[derive(Clone, Copy, Default)]
pub struct BabyBearPoseidon2Backend;

#[derive(Clone, Copy)]
pub struct BabyBearPoseidon2RowFrame<'a, Var>(pub &'a [Var]);

#[derive(Clone)]
pub struct BabyBearPoseidon2_16HashAir {
    air: BabyBearPoseidon2_16Air,
}

impl Default for BabyBearPoseidon2_16HashAir {
    fn default() -> Self {
        Self::new()
    }
}

impl BabyBearPoseidon2_16HashAir {
    #[must_use]
    pub fn new() -> Self {
        Self {
            air: BabyBearPoseidon2_16Air::new(round_constants()),
        }
    }

    #[must_use]
    pub fn air(&self) -> &BabyBearPoseidon2_16Air {
        &self.air
    }
}

impl StarkRelationBackend for BabyBearPoseidon2Backend {
    type Config = BabyBearPoseidon2StarkConfig;

    fn config(&self, seed: u64) -> Self::Config {
        let perm = default_babybear_poseidon2_16();
        let hash = BabyBearTranscriptHash::new(perm.clone());
        let compress = BabyBearTranscriptCompress::new(perm.clone());
        let val_mmcs = BabyBearValMmcs::new(hash, compress, SmallRng::seed_from_u64(seed));
        let challenge_mmcs = BabyBearChallengeMmcs::new(val_mmcs.clone());
        let fri_params = create_benchmark_fri_params_zk(challenge_mmcs);
        let pcs = BabyBearPcs::new(
            BabyBearDft::default(),
            val_mmcs,
            fri_params,
            4,
            SmallRng::seed_from_u64(1),
        );
        let challenger = BabyBearChallenger::new(perm);
        StarkConfig::new(pcs, challenger)
    }
}

#[must_use]
pub fn round_constants() -> BabyBearPoseidon2_16RoundConstants {
    RoundConstants::new(
        p3_baby_bear::BABYBEAR_RC16_EXTERNAL_INITIAL,
        p3_baby_bear::BABYBEAR_RC16_INTERNAL,
        p3_baby_bear::BABYBEAR_RC16_EXTERNAL_FINAL,
    )
}

impl HashInvocationAir<BabyBear, BABYBEAR_POSEIDON2_WIDTH> for BabyBearPoseidon2_16HashAir {
    type Frame<'a, Var>
        = BabyBearPoseidon2RowFrame<'a, Var>
    where
        Self: 'a,
        Var: 'a;

    fn main_width(&self) -> usize {
        BaseAir::<BabyBear>::width(&self.air)
    }

    fn eval<AB>(&self, builder: &mut AB)
    where
        AB: AirBuilder<F = BabyBear>,
    {
        Air::<AB>::eval(&self.air, builder);
    }

    fn row_frame<'a, Var>(&self, row: &'a [Var]) -> Self::Frame<'a, Var> {
        BabyBearPoseidon2RowFrame(row)
    }

    fn build_trace<P>(
        &self,
        witness: &PermutationWitnessBuilder<P, BABYBEAR_POSEIDON2_WIDTH>,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<BabyBear>
    where
        P: Permutation<BABYBEAR_POSEIDON2_WIDTH, U = BabyBear>,
    {
        let inputs = witness
            .trace()
            .as_ref()
            .iter()
            .map(|pair| pair.input)
            .collect::<Vec<_>>();

        p3_poseidon2_air::generate_trace_rows::<
            BabyBear,
            GenericPoseidon2LinearLayersBabyBear,
            BABYBEAR_POSEIDON2_WIDTH,
            BABYBEAR_POSEIDON2_SBOX_DEGREE,
            BABYBEAR_POSEIDON2_SBOX_REGISTERS,
            BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
            BABYBEAR_POSEIDON2_PARTIAL_ROUNDS,
        >(inputs, &round_constants(), extra_capacity_bits)
    }

    fn invocation<AB>(
        &self,
        frame: &Self::Frame<'_, AB::Var>,
    ) -> QueryAnswerPair<AB::Expr, BABYBEAR_POSEIDON2_WIDTH>
    where
        AB: AirBuilder<F = BabyBear>,
    {
        let row = frame.0;
        let cols: &BabyBearPoseidon2_16Cols<_> = row.borrow();

        QueryAnswerPair::new(
            cols.inputs.clone().map(Into::into),
            cols.ending_full_rounds[BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS - 1]
                .post
                .clone()
                .map(Into::into),
        )
    }
}
