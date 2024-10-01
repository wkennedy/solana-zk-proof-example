use crate::account_state::AccountState;
use crate::account_state_circuit::AccountStateCircuit;
use crate::byte_utils::{bytes_to_field, fr_to_g1, g1_affine_to_bytes};
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalSerialize, CanonicalSerializeHashExt, Compress};
use ark_snark::SNARK;
use borsh::{BorshDeserialize, BorshSerialize};
use rand::thread_rng;
use std::fs::File;
use std::io::Write;
use std::ops::Neg;

//TODO we know the size of the proof and vk, so change from vec
#[derive(BorshSerialize, BorshDeserialize)]
pub struct ProofPackageLite {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub verifying_key: Vec<u8>
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ProofPackagePrepared {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub verifying_key: Vec<u8>
}

pub struct ProofPackage {
    pub proof: Proof<Bn254>,
    pub public_inputs: G1Projective,
    pub prepared_verifying_key: PreparedVerifyingKey<Bn254>
}

pub fn setup(save_keys: bool) -> (ProvingKey<Bn254>, VerifyingKey<Bn254>){
    let rng = &mut thread_rng();
    let account_state_circuit = AccountStateCircuit::default();
    let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(account_state_circuit.clone(), rng).unwrap();

    if save_keys {
        let mut pk_file = File::create("pk.bin").unwrap();
        let mut pk_bytes = Vec::new();
        proving_key.serialize_uncompressed(&mut pk_bytes).expect("");
        pk_file.write(&pk_bytes).expect("TODO: panic message");

        let mut file = File::create("vk.bin").unwrap();
        let mut vk_bytes = Vec::new();
        verifying_key.serialize_uncompressed(&mut vk_bytes).expect("");
        file.write(&vk_bytes).expect("TODO: panic message");
    };

    (proving_key, verifying_key)
}

pub fn generate_proof(proving_key: &ProvingKey<Bn254>, verifying_key: &VerifyingKey<Bn254>, accounts: Vec<AccountState>) -> (ProofPackageLite, ProofPackagePrepared, ProofPackage) {
    let rng = &mut thread_rng();

    let account_state_circuit = AccountStateCircuit::new(accounts);
    let public_inputs = account_state_circuit.public_inputs();

    // Create a proof
    let proof = Groth16::<Bn254>::prove(&proving_key,
                                        account_state_circuit,
                                        rng,
    ).unwrap();

    let proof_neg = Proof::<Bn254> {
        a: proof.a.neg(),
        b: proof.b,
        c: proof.c,
    };

    let mut proof_bytes = Vec::with_capacity(proof.serialized_size(Compress::No));
    proof.serialize_uncompressed(&mut proof_bytes).expect("Error serializing proof");

    let public_inputs_fr = public_inputs
        .iter()
        .map(|input| bytes_to_field(input))
        .collect::<Result<Vec<Fr>, _>>().expect("");

    // let g1 = g1_affine_to_bytes(&fr_to_g1(&public_inputs_fr[0]));
    // let g2 = g1_affine_to_bytes(&fr_to_g1(&public_inputs_fr[1]));
    // let mut pi: Vec<[u8; 64]> = Vec::new();
    // pi.push(<[u8; 64]>::try_from(&g1[0..64]).unwrap());
    // pi.push(<[u8; 64]>::try_from(&g2[0..64]).unwrap());

    let prepared_verifying_key = prepare_verifying_key(&verifying_key);

    let g1_projective: G1Projective = Groth16::<Bn254>::prepare_inputs(&prepared_verifying_key, &public_inputs_fr).expect("Error preparing inputs with public inputs and prepared verifying key");

    let mut projective_bytes: Vec<u8> = Vec::new();
    let _ = g1_projective.serialize_uncompressed(&mut projective_bytes);
    let mut verifying_key_bytes: Vec<u8> = Vec::with_capacity(verifying_key.serialized_size(Compress::No));
    let _ = verifying_key.serialize_uncompressed(&mut verifying_key_bytes);
    let mut prepared_verifying_key_bytes: Vec<u8> = Vec::new();
    let _ = prepared_verifying_key.serialize_uncompressed(&mut prepared_verifying_key_bytes);

    (ProofPackageLite {
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
    })
}

// fn deserialize_proof_package(serialized_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
//     // Deserialize the ProofPackage with Borsh
//     let proof_package = ProofPackageLite::try_from_slice(serialized_data)?;
//
//     // let proof = Proof::<Bn254>::deserialize_uncompressed_unchecked(&proof_package.proof[..]).expect("Error deserializing proof");
//
//     Ok((proof_package.proof, proof_package.public_inputs))
// }


// Helper function to convert G1Affine to bytes
// fn g1_to_bytes(point: G1Affine) -> [u8; 64] {
//     let mut bytes = [0u8; 64];
//     bytes[..32].copy_from_slice(&field_to_bytes(point.x));
//     bytes[32..].copy_from_slice(&field_to_bytes(point.y));
//     bytes
// }
//
// // Helper function to convert G2Affine to bytes
// fn g2_to_bytes(point: Fq2) -> [u8; 64] {
//     let mut bytes = [0u8; 64];
//     bytes[..32].copy_from_slice(&field_to_bytes(point.c0));
//     bytes[32..].copy_from_slice(&field_to_bytes(point.c1));
//     bytes
// }

// fn bytes_to_g2_from_slice(slice: &[u8]) -> Result<Fq2, SerializationError> {
//     if slice.len() != 64 {
//         return Err(SerializationError::InvalidData);
//     }
//     let array: [u8; 64] = slice.try_into().map_err(|_| SerializationError::InvalidData)?;
//     bytes_to_g2(&array)
// }
//
// fn bytes_to_g2(bytes: &[u8; 64]) -> Result<Fq2, SerializationError> {
//     let c0 = bytes_to_field(&bytes[..32])?;
//     let c1 = bytes_to_field(&bytes[32..64])?;
//
//     Ok(Fq2::new(c0, c1))
// }

