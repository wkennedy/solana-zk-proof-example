**Overview**

This Solana program verifies zero-knowledge proofs using the Groth16 proof system on the BN254 (also known as alt_bn128) elliptic curve. 

The program takes a serialized proof and public inputs (prepared inputs with verifying key), performs the necessary pairing checks, and determines whether the proof is valid.

One thing to note about this program is that the public inputs are prepared before sending it to the contract. This is to reduce compute units during verification. Here is an example of preparing the public inputs:

```rust
    let mut proof_bytes = Vec::new();
    proof.serialize_uncompressed(&mut proof_bytes).expect("Error serializing proof");

    let pvk = prepare_verifying_key(&verifying_key);
    let public_inputs_fr = public_inputs
        .iter()
        .map(|input| bytes_to_field(input))
        .collect::<Result<Vec<Fr>, _>>().expect("");
    let projective: G1Projective = Groth16::<Bn254>::prepare_inputs(&pvk, &public_inputs_fr).expect("Error preparing inputs with public inputs and prepared verifying key");

    let mut projective_bytes = Vec::new();
    let _ = projective.serialize_uncompressed(&mut projective_bytes);
```

**TODOs**

- Add better error handling and logging
- Input validation
- Optimize deser