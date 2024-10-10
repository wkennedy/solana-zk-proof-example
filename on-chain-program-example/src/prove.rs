use crate::byte_utils::bytes_to_field;
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use borsh::{BorshDeserialize, BorshSerialize};
use rand::thread_rng;
use std::fs::File;
use std::io::Write;

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ProofPackageLite {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub verifying_key: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ProofPackagePrepared {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub verifying_key: Vec<u8>,
}

pub struct ProofPackage {
    pub proof: Proof<Bn254>,
    pub public_inputs: G1Projective,
    pub prepared_verifying_key: PreparedVerifyingKey<Bn254>,
}

pub fn setup<C: ConstraintSynthesizer<Fr>>(
    save_keys: bool,
    circuit: C,
) -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    let rng = &mut thread_rng();
    let (proving_key, verifying_key) =
        Groth16::<Bn254>::circuit_specific_setup(circuit, rng).unwrap();

    if save_keys {
        let mut pk_file = File::create("pk.bin").unwrap();
        let mut pk_bytes = Vec::new();
        proving_key.serialize_uncompressed(&mut pk_bytes).expect("");
        pk_file.write(&pk_bytes).expect("TODO: panic message");

        let mut file = File::create("vk.bin").unwrap();
        let mut vk_bytes = Vec::new();
        verifying_key
            .serialize_uncompressed(&mut vk_bytes)
            .expect("");
        file.write(&vk_bytes).expect("TODO: panic message");
    };

    (proving_key, verifying_key)
}

pub fn generate_proof_package<C: ConstraintSynthesizer<Fr>>(
    proving_key: &ProvingKey<Bn254>,
    verifying_key: &VerifyingKey<Bn254>,
    circuit: C,
    public_inputs: &Vec<[u8; 32]>,
) -> (ProofPackageLite, ProofPackagePrepared, ProofPackage) {
    let rng = &mut thread_rng();

    // Create a proof
    let proof = Groth16::<Bn254>::prove(&proving_key, circuit, rng).unwrap();

    let mut proof_bytes = Vec::with_capacity(proof.serialized_size(Compress::No));
    proof
        .serialize_uncompressed(&mut proof_bytes)
        .expect("Error serializing proof");

    let public_inputs_fr = public_inputs
        .iter()
        .map(|input| bytes_to_field(input))
        .collect::<Result<Vec<Fr>, _>>()
        .expect("");

    let prepared_verifying_key = prepare_verifying_key(&verifying_key);

    let g1_projective: G1Projective =
        Groth16::<Bn254>::prepare_inputs(&prepared_verifying_key, &public_inputs_fr)
            .expect("Error preparing inputs with public inputs and prepared verifying key");

    let mut projective_bytes: Vec<u8> = Vec::new();
    let _ = g1_projective.serialize_uncompressed(&mut projective_bytes);
    let mut verifying_key_bytes: Vec<u8> =
        Vec::with_capacity(verifying_key.serialized_size(Compress::No));
    let _ = verifying_key.serialize_uncompressed(&mut verifying_key_bytes);
    let mut prepared_verifying_key_bytes: Vec<u8> = Vec::new();
    let _ = prepared_verifying_key.serialize_uncompressed(&mut prepared_verifying_key_bytes);

    (
        ProofPackageLite {
            proof: proof_bytes.clone(),
            public_inputs: public_inputs.clone(),
            verifying_key: prepared_verifying_key_bytes.clone(),
        },
        ProofPackagePrepared {
            proof: proof_bytes,
            public_inputs: projective_bytes,
            verifying_key: prepared_verifying_key_bytes,
        },
        ProofPackage {
            proof,
            public_inputs: g1_projective,
            prepared_verifying_key,
        },
    )
}
