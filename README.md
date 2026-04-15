# spongefish-stark

`spongefish-stark` provides STARK proof helpers for proving facts about hash
circuits built with the `spongefish` ecosystem.

Today the crate exposes two main proving layers:

- `relation`: prove statements about one or more hash invocations, public lane
  constraints, reused secret inputs, and fixed-width linear equations.
- `preimage_relation`: prove preimage-style statements where the prover knows
  private inputs that hash to publicly constrained outputs.

The crate ships with backend adapters for Poseidon2, and optionally Keccak when
the `keccak` feature is enabled.

## Example

The smallest end-to-end example is in
[`examples/poseidon2_relation.rs`](examples/poseidon2_relation.rs). It:

1. builds a relation instance for a Poseidon2 permutation,
2. exposes a few output lanes as public,
3. adds a simple linear constraint,
4. proves the relation, and
5. verifies the proof.

Run it with:

```bash
cargo run --example poseidon2_relation
```

## Minimal usage

```rust
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use spongefish::Permutation;
use spongefish_circuit::permutation::{
    LinearEquation, PermutationInstanceBuilder, PermutationWitnessBuilder,
};
use spongefish_stark::{
    poseidon2::{
        KoalaBearPoseidon2Backend, KoalaBearPoseidon2_16, KoalaBearPoseidon2_16HashAir,
        POSEIDON2_16_WIDTH,
    },
    relation,
};

const LINEAR_WIDTH: usize = 1;

let backend = KoalaBearPoseidon2Backend::default();
let hash = KoalaBearPoseidon2_16HashAir::default();
let permutation = KoalaBearPoseidon2_16::default();

let input = core::array::from_fn(|i| KoalaBear::from_usize(i + 1));
let expected_output = permutation.permute(&input);

let instance = PermutationInstanceBuilder::<KoalaBear, POSEIDON2_16_WIDTH>::new();
let witness =
    PermutationWitnessBuilder::<KoalaBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);

let input_vars = instance
    .allocator()
    .allocate_public::<POSEIDON2_16_WIDTH>(&input);
let output_vars = instance.allocate_permutation(&input_vars);
let output_vals = witness.allocate_permutation(&input);

instance.allocator().set_public_vars(
    [1usize, 2, 3].into_iter().map(|idx| output_vars[idx]),
    [expected_output[1], expected_output[2], expected_output[3]],
);

instance.add_equation(LinearEquation::new(
    [(KoalaBear::ONE, output_vars[0])],
    output_vals[0],
));
witness.add_equation(LinearEquation::new(
    [(KoalaBear::ONE, output_vals[0])],
    output_vals[0],
));

let proof = relation::prove::<
    KoalaBearPoseidon2Backend,
    KoalaBearPoseidon2_16HashAir,
    KoalaBearPoseidon2_16,
    POSEIDON2_16_WIDTH,
    LINEAR_WIDTH,
>(&backend, &hash, &instance, &witness);

relation::verify::<
    KoalaBearPoseidon2Backend,
    KoalaBearPoseidon2_16HashAir,
    POSEIDON2_16_WIDTH,
    LINEAR_WIDTH,
>(&backend, &hash, &instance, &proof)?;
# Ok::<(), spongefish::VerificationError>(())
```

## Notes

- The `LINEAR_WIDTH` const generic must match the width of every linear equation
  added to the relation instance and witness.
- The public output positions you expose with `set_public_vars` become part of
  the verified statement.
- For more complex relations, see the crate tests in [`src/tests.rs`](src/tests.rs).
