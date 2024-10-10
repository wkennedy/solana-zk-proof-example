# solana-zk-proof-example

## Overview

This is an example of creating a ZK-SNARK proof and verifying it on-chain. This is a technique used for "zk-rollups", among other use cases.

This is the basic order of events:

1. A prover generates a proof.
2. The proof is sent to an on-chain contract.
3. The contract checks the validity of the proof.
4. If the proof is valid, the contract performs some action (like updating account state).

What are some of the challenges associated with verifying ZK proofs on-chain? Here are a few:

1. Computational cost:
   While ZK proofs are generally more efficient to verify than to generate, the verification process still requires significant computational resources.
2. Trusted setup:
   Generally, ZK-SNARK systems require a trusted setup phase. This initial setup generates public parameters used for creating and verifying proofs. This is a security concern as the setup may become compromised.
3. Complexity:
   This stuff is hard...there is a steep learning curve. Correctly implementing ZK proof verification in smart contracts is challenging and requires cryptographic expertise. Fudging it can lead to security vulnerabilities.

Let's get into it!

## Let's Begin

This tutorial will mostly use libraries from [Solana](https://github.com/anza-xyz/agave) and [Arkworks](https://github.com/arkworks-rs)

### Proof

We'll be focusing on ZK-SNARK which stands for “Zero-Knowledge Succinct Non-Interactive Argument of Knowledge”. That sounds totally awesome. Essentially, it's a mathematical way for one party to prove to another that they know a secret without revealing the secret itself.

In this case we're using a Groth16 BN254 proof (Groth16 SK-SNARKs over BN254 elliptic curve constructions). Okay...wtf does that mean?

Groth16 is a (pairing-based) proof system. We aren't gonna get into the weeds here, you can do that on your own time, but here are some things to note:

- Short proofs (only 3 group elements)
- Fast verification (only a few pairing operations)
- Requires a trusted setup (as noted in the concern above)
- Popular with various blockchains

BN254 is a pairing friendly elliptic curve. Again, not gonna get super detailed here, so it's up to you to do research. Here is what's important for this tutorial:
- 254-bit prime field
- Suitable for pairing-based cryptography
- Popular in blockchain and zk proof systems
- Also known as BN128 (128 previously referred to the bits of security) or **alt_bn_128** (foreshadowing)

Enough already, let's see some code...

Okay, in order to generate a proof we need a circuit.

```rust
let circuit = ExampleCircuit {
    some_value: Some(Fr::from(100)),
};
```

Alright, so what? What this really means is:

```rust
///@see circuit.rs
impl ConstraintSynthesizer<Fr> for ExampleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let some_value_var =
            cs.new_input_variable(|| self.some_value.ok_or(SynthesisError::AssignmentMissing))?;

        // Constraint: Ensure computed addresses_hash matches the provided addresses_hash
        cs.enforce_constraint(
            lc!() + some_value_var,
            lc!() + Variable::One,
            lc!() + some_value_var,
        )?;

        Ok(())
    }
}
```

This is where the actual constraints of the circuit are defined. Luckily, this is a simple example:

- It creates a new variable in the constraint system representing some_value.
- It adds a constraint that essentially says "some_value multiplied by 1 should equal some_value". This is a trivial constraint for tutorial purposes, but these can become complicated quickly as noted in the concerns.

Now that we have our circuit, we'll need a verifying key, proving key and random number generator.

```rust
let rng = &mut thread_rng();
let (proving_key, verifying_key) =
    Groth16::<Bn254>::circuit_specific_setup(circuit, rng).unwrap();
```
This creates a mutable reference to a random number generator (rng) via thread_rng() which provides a cryptographically secure random number generator that's local to the current thread.
As a result, we get a proving and verifying key. These keys are specifically for our circuit and will be used in the proving and verifying processes.
We want to hold on to these as they will be used for all future proofs and verifications related to this circuit.

```rust
let rng = &mut thread_rng();

let proof = Groth16::<Bn254>::prove(&proving_key, circuit, rng).unwrap();
```

We call prove with Groth16::<Bn254> where Groth16 is the specific ZK proof protocol used and <Bn254> says that it's using the BN254 elliptic curve.

The resulting proof is a cryptographic object that can be shared publicly. It allows anyone with the corresponding verification key to confirm that the prover knows a valid solution to the circuit, without learning anything about the solution itself beyond what is explicitly allowed by the circuit definition.
For example, in our ExampleCircuit, the proof would demonstrate that the prover knows the value of some_value that satisfies the constraint we defined, without revealing what some_value actually is.
This proof generation step would typically be performed by a party who has some secret information (in this case, the value of some_value) and wants to prove they have a valid value without revealing it. The resulting proof can then be sent to a verifier, who can check its validity using the verification key from the setup phase.

### Beyond a reasonable doubt...the burden of proof

Nice, we have a proof. Now how do we prove this thing? If you aren't in a compute constrained environment then it's relatively straight forward.

```rust
let result = Groth16::<Bn254>::verify(&verifying_key, &[Fr::from(100)], &proof).unwrap();
```

The ark library has a handy function that will prepare the verifying key and public input for you and return a bool (true if valid, false otherwise). But this won't run on-chain as it uses too much CU. Long story short we need to use the alt_bn128_pairing function provided by Solana.
The function essentially checks if a set of pairing products equals 1. If the pairing check passes (result is 1), it typically means the proof is valid.
This allows Solana to support cryptographic operations necessary for using zero-knowledge proofs. We'll have to get into the weeds a little bit here in order to understand what we do next.

- Input Validation: The function first checks if the input length is a multiple of a specific pairing element length. If not, it returns an error.
- Data Preparation:
  - It calculates how many pairing elements are in the input.
  - It creates a vector to store pairs of points (G1 and G2) from the input data.
- Parsing Input: 
  - The function loops through the input data, parsing it into pairs of G1 and G2 points.
  - It uses helper functions (convert_endianness_64 and convert_endianness_128) to handle endianness conversion.
  - The parsed points are converted into the appropriate internal representations (PodG1 and PodG2).
- Pairing Computation: It uses the multi_pairing function from the ark_bn254 library to compute the pairing of all the point pairs.
- Result Processing: If the result of the pairing is equal to one (in the Fq12 field), it sets the result to 1. Otherwise, it remains 0.
- Output: The result (0 or 1) is converted to a big-endian byte representation and returned.

What's we want to focus on is [endianess](https://developer.mozilla.org/en-US/docs/Glossary/Endianness). This is crucial to validating the proof correctly. 

We need to get data from our verifying key, proof and public inputs into the alt_bn128_pairing parameter:

```rust
input: &[u8]
```

First we need to negate 'a' in the proof. The negation of the 'a' component in the Groth16 proof is an optimization that's commonly used in the verification process and many implementations of Groth16 verifiers expect the 'a' component to be negated.

```rust
let proof_with_neg_a = Proof::<Bn254> {
    a: proof.a.neg(),
    b: proof.b,
    c: proof.c,
};
let mut proof_bytes = Vec::with_capacity(proof_with_neg_a.serialized_size(Compress::No));
proof_with_neg_a
    .serialize_uncompressed(&mut proof_bytes)
    .expect("Error serializing proof");
```

The proof components (a, b, c) are serialized and their endianness is converted in order to match Solana.

```rust
let proof_a: [u8; 64] = convert_endianness::<32, 64>(proof_bytes[0..64].try_into().unwrap());
let proof_b: [u8; 128] = convert_endianness::<64, 128>(proof_bytes[64..192].try_into().unwrap());
let proof_c: [u8; 64] = convert_endianness::<32, 64>(proof_bytes[192..256].try_into().unwrap());
```

Now we need to prepare our public input (represented as points on an elliptic curve) We use arks prepare_inputs which takes the public input (the number 100) and combines it with information from the verifying key to create a point on the elliptic curve. This point is then converted into a series of bytes. Finally, these bytes are reordered to match Solana.

```rust
let projective: G1Projective = prepare_inputs(&vk, &[Fr::from(100)]).unwrap();
let mut g1_bytes = Vec::with_capacity(projective.serialized_size(Compress::No));
projective.serialize_uncompressed(&mut g1_bytes).expect("");
let prepared_public_input =
    convert_endianness::<32, 64>(<&[u8; 64]>::try_from(g1_bytes.as_slice()).unwrap());
```

We'll convert the Arkworks verifying key to a stripped down version that's more efficient for Solana.
It will extract the four parts we need for proof verification with prepared inputs, convert each part into bytes and change the endianness for Solana.


```rust

pub fn convert_arkworks_verifying_key_to_solana_verifying_key_prepared(
    ark_vk: &VerifyingKey<Bn254>,
) -> Box<Groth16VerifyingKeyPrepared> {
    // Convert alpha_g1
    let mut vk_alpha_g1 = [0u8; 64];
    ark_vk
        .alpha_g1
        .serialize_uncompressed(&mut vk_alpha_g1[..])
        .unwrap();

    // Convert beta_g2
    let mut vk_beta_g2 = [0u8; 128];
    ark_vk
        .beta_g2
        .serialize_uncompressed(&mut vk_beta_g2[..])
        .unwrap();

    // Convert gamma_g2
    let mut vk_gamma_g2 = [0u8; 128];
    ark_vk
        .gamma_g2
        .serialize_uncompressed(&mut vk_gamma_g2[..])
        .unwrap();

    // Convert delta_g2
    let mut vk_delta_g2 = [0u8; 128];
    ark_vk
        .delta_g2
        .serialize_uncompressed(&mut vk_delta_g2[..])
        .unwrap();

    let vk_alpha_g1_converted = convert_endianness::<32, 64>(&vk_alpha_g1);
    let vk_beta_g2_converted = convert_endianness::<64, 128>(&vk_beta_g2);
    let vk_gamma_g2_converted = convert_endianness::<64, 128>(&vk_gamma_g2);
    let vk_delta_g2_converted = convert_endianness::<64, 128>(&vk_delta_g2);

    Box::new(Groth16VerifyingKeyPrepared {
        vk_alpha_g1: vk_alpha_g1_converted,
        vk_beta_g2: vk_beta_g2_converted,
        vk_gamma_g2: vk_gamma_g2_converted,
        vk_delta_g2: vk_delta_g2_converted,
    })
}
```

Finally, we can create our verifier! This is what will be sent to the Solana program and executed on-chain.

```rust
let mut verifier: Groth16VerifierPrepared = Groth16VerifierPrepared::new(
    proof_a,
    proof_b,
    proof_c,
    prepared_public_input,
    groth_vk_prepared,
)
.unwrap();
```

Now we have these two structs:

```rust
#[derive(PartialEq, Eq, Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Groth16VerifyingKeyPrepared {
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamma_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
}

#[derive(PartialEq, Eq, Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Groth16VerifierPrepared {
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    prepared_public_inputs: [u8; 64],
    verifying_key: Box<Groth16VerifyingKeyPrepared>,
}
```

The Groth16VerifierPrepared has a verify function that we can call on-chain. This will create the pairing input and pass it to alt_bn128_pairing.

```rust
impl Groth16VerifierPrepared {
    pub fn verify(&mut self) -> Result<bool, Groth16Error> {
        let pairing_input = [
            self.proof_a.as_slice(),
            self.proof_b.as_slice(),
            self.prepared_public_inputs.as_slice(),
            self.verifying_key.vk_gamma_g2.as_slice(),
            self.proof_c.as_slice(),
            self.verifying_key.vk_delta_g2.as_slice(),
            self.verifying_key.vk_alpha_g1.as_slice(),
            self.verifying_key.vk_beta_g2.as_slice(),
        ]
        .concat();

        let pairing_res =
            alt_bn128_pairing(pairing_input.as_slice()).map_err(|_| ProofVerificationFailed)?;

        if pairing_res[31] != 1 {
            return Err(ProofVerificationFailed);
        }
        Ok(true)
    }
}
```

The ordering of the pairing inputs matters and follows a specific mathematical structure designed for the Groth16 proof system. Let's break down the reason for this order:

- [self.proof_a, self.proof_b]: These represent the main components of the proof. They're put first because they're the core elements that the verifier needs to check.
- [self.prepared_public_inputs, self.verifying_key.vk_gamma_g2]: This pairing checks the validity of the public inputs against the γ (gamma) element of the verifying key.
- [self.proof_c, self.verifying_key.vk_delta_g2]: This pairing involves the C component of the proof and the δ (delta) element of the verifying key. It's part of ensuring the proof's consistency.
- [self.verifying_key.vk_alpha_g1, self.verifying_key.vk_beta_g2]: This final pairing checks the α (alpha) and β (beta) elements of the verifying key. It's crucial for the overall security of the proof system.

The order corresponds to the Groth16 verification equation, which can be represented as:
```
e(A, B) · e(L, γ) · e(C, δ) = e(α, β) · e(K, γ)
```
Where:

- A, B, C are from the proof
- L represents the prepared public inputs
- α, β, γ, δ are from the verifying key
- K is a computation involving the public inputs and verifying key (prepared earlier)

By arranging the inputs in this specific order, the pairing function can efficiently compute:
```
e(A, B) · e(L, γ) · e(C, δ) · e(-α, β)^-1
```
If this equals 1, it means the original equation holds, and the proof is valid.

Now we are all set! Let's take a look on how we might use this in a Solana program:

```rust

// Program's entrypoint
entrypoint!(process_instruction);

// Define the instruction enum
#[derive(BorshSerialize, BorshDeserialize)]
pub enum ProgramInstruction {
    VerifyProof(Groth16VerifierPrepared),
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = ProgramInstruction::try_from_slice(instruction_data)?;

    match instruction {
        ProgramInstruction::VerifyProof(proof_package) => {
            verify_proof(program_id, accounts, proof_package)
        }
    }
}

fn verify_proof(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    mut groth16_verifier_prepared: Groth16VerifierPrepared,
) -> ProgramResult {

    let result = groth16_verifier_prepared
        .verify()
        .expect("Error deserializing verifier");

    if result {
        msg!("Proof is valid! Inputs verified.");
        update_on_chain_state()?;
        Ok(())
    } else {
        msg!("Proof is invalid!");
        Err(ProgramError::InvalidAccountData.into())
    }
}

fn update_on_chain_state() -> ProgramResult {
    msg!("Updating state account.");

    // Put what action you want to perform based on a successful verification

    Ok(())
}
```

### Random take aways:

See the test "test_alt_bn128_pairing_custom" in main.rs for an example just using pairs not derived from a proof. This could be a good starting place if you are new.

- Input format and endianness are important when dealing with cryptographic functions, especially when working with different libraries or implementations.
- Detailed debugging output is invaluable in understanding how data is being processed and transformed at each step.
- Verifying intermediate results (like the parsed G1 and G2 points) can help catch issues early in the process.
- Comparing the results with a known-good implementation (like the Arkworks pairing check we kept in the test) provides a useful sanity check.

### Other sources to check out

[Risc Zero - Solana] (https://github.com/risc0/risc0-solana/tree/main)
[LightProtocol Groth16 Solana] (https://github.com/Lightprotocol/groth16-solana)