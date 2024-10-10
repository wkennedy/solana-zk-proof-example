use crate::prove::ProofPackage;
use ark_bn254::{Bn254, G1Projective};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};

pub fn verify(
    proof: &Proof<Bn254>,
    public_inputs: &G1Projective,
    vk: &VerifyingKey<Bn254>,
) -> bool {
    let pvk = prepare_verifying_key(vk);
    Groth16::<Bn254>::verify_proof_with_prepared_inputs(&pvk, proof, public_inputs).unwrap()
}

pub fn verify_proof_package(proof_package: &ProofPackage) -> bool {
    Groth16::<Bn254>::verify_proof_with_prepared_inputs(
        &proof_package.prepared_verifying_key,
        &proof_package.proof,
        &proof_package.public_inputs,
    )
    .unwrap()
}
