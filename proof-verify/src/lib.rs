use std::error::Error;
use std::ops::Neg;
use ark_ff::{BigInteger, BigInteger256, PrimeField};
use ark_groth16::Proof;
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
    msg,
};
use solana_program::alt_bn128::prelude::*;
use solana_program::instruction::InstructionError::InvalidInstructionData;
use solana_program::program_error::ProgramError;

#[derive(BorshSerialize, BorshDeserialize)]
struct SerializableProof {
    a: [u8; 64],
    b: [[u8; 64]; 2],
    c: [u8; 64],
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct ProofPackage {
    proof: Vec<u8>,
    public_inputs: Vec<[u8; 32]>,
}

// On-chain verification (Solana program)
entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // msg!("Verifying Solana account zk-SNARK proof");

    // Deserialize proof and public inputs from instruction_data
    // Note: In a real implementation, you'd need to properly deserialize this data
    let (proof, public_inputs) = deserialize_proof_package(instruction_data).unwrap();

    let mut pairing_data = Vec::new(); // 64 + 128 + 64 + 3 * 32

    proof.serialize_uncompressed( pairing_data.clone()).expect("");
    // let mut bytes = Vec::new();
    // &proof.a.serialize_uncompressed(&mut bytes);
    // &proof.b.serialize_uncompressed(&mut bytes);
    // &proof.b[1].serialize_uncompressed(&mut bytes);
    // &proof.c.serialize_uncompressed(&mut bytes);

    // Add proof points
    // pairing_data.extend_from_slice(&proof.a.serialize_uncompressed(&mut bytes));
    // pairing_data.extend_from_slice(&proof.b);
    // pairing_data.extend_from_slice(&proof.b[1]);
    // pairing_data.extend_from_slice(&proof.c);

    let mut pis = Vec::new();

    for pi in &public_inputs {
        pis.extend_from_slice(pi.0.to_bytes_le().as_slice())
    }

    // Verify the proof
    let result = verify_groth16_proof(pairing_data.as_slice(), &pis)?;

    if result {
        msg!("Proof is valid! Account properties verified.");
        // Here you can add additional logic based on the verified account properties
        Ok(())
    } else {
        msg!("Proof is invalid!");
        Err(ProgramError::InvalidAccountData.into())
    }
}

fn verify_groth16_proof(
    proof: &[u8],
    public_inputs: &[u8],
) -> Result<bool, ProgramError> {
    // Prepare the inputs for the pairing check
    let mut pairing_inputs = Vec::new();
    pairing_inputs.extend_from_slice(proof);
    pairing_inputs.extend_from_slice(public_inputs);

    // Perform the pairing check
    let result = alt_bn128_pairing(&pairing_inputs);

    // The result should be a 32-byte array. If it's all zeros, the pairing check succeeded.
    // let int = BigInteger256::from(result.unwrap().as_slice());
    // result.unwrap().last() == Some(&1);
    Ok(result.unwrap().last() == Some(&1))
}

// Helper functions (implementation omitted for brevity)
fn deserialize_proof_and_inputs(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProgramError> {
    // Implementation omitted
    unimplemented!()
}

fn deserialize_proof_package(serialized_data: &[u8]) -> Result<(Proof<Bn254>, Vec<Fr>), Box<dyn std::error::Error>> {
    // Deserialize the ProofPackage
    let proof_package = ProofPackage::try_from_slice(serialized_data)?;

    // msg!("{:?}", &proof_package);

    let proof1 = Proof::<Bn254>::deserialize_uncompressed_unchecked(&proof_package.proof[..]).expect("TODO: panic message");
    // Deserialize the Proof
    // let a = G1Affine::new(
    //     bytes_to_field(&proof_package.proof.a[0..32])?,
    //     bytes_to_field(&proof_package.proof.a[32..64])?,
    // );
    //
    // let b = G2Affine::new(
    //
    //     bytes_to_g2_from_slice(&proof_package.proof.b[0][0..64])?
    //     ,
    //
    //     bytes_to_g2_from_slice(&proof_package.proof.b[1][0..64])?
    //     ,
    // );
    //
    // let c = G1Affine::new(
    //     bytes_to_field(&proof_package.proof.c[0..32])?,
    //     bytes_to_field(&proof_package.proof.c[32..64])?,
    // );
    //
    // let proof = Proof { a, b, c };
    //
    // Deserialize public inputs
    let public_inputs = proof_package.public_inputs
        .iter()
        .map(|input| bytes_to_field(input))
        .collect::<Result<Vec<Fr>, _>>()?;

    // let public_inputs: Vec<Fr> = Vec::new();
    Ok((proof1, public_inputs))
}

// fn bytes_to_field(bytes: &[u8]) -> Result<Fq, Box<dyn std::error::Error>> {
//     let mut bytes_arr = [0u8; 32];
//     bytes_arr.copy_from_slice(bytes);
//     Ok(Fq::from_le_bytes_mod_order(&bytes_arr))
// }


fn bytes_to_g2_from_slice(slice: &[u8]) -> anyhow::Result<Fq2> {
    // if slice.len() != 64 {
    //     return anyhow::(InvalidInstructionData);
    // }
    let array: [u8; 64] = slice.try_into().map_err(|_| InvalidInstructionData)?;
    bytes_to_g2(&array)
}

fn bytes_to_g2(bytes: &[u8; 64]) -> anyhow::Result<Fq2, anyhow::Error> {
    let c0 = bytes_to_field(&bytes[..32])?;
    let c1 = bytes_to_field(&bytes[32..64])?;

    Ok(Fq2::new(c0, c1))
}

// Helper function to convert bytes to a field element
fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> anyhow::Result<F, anyhow::Error> {
    Ok(F::deserialize_uncompressed(bytes)?)
}
//
//
// pub fn prepare_and_verify_proof(proof: &Proof<Bn254>) -> Result<bool, ProgramError> {
//     let mut input = Vec::new();
//
//     // Prepare A (G1 point)
//     let a_x = proof.a.x.into_bigint().to_bytes_le();
//     let a_y = proof.a.y.into_bigint().to_bytes_le();
//     input.extend_from_slice(&pad_to_64_bytes(&a_x));
//     input.extend_from_slice(&pad_to_64_bytes(&a_y));
//
//     // Prepare B (G2 point)
//     let b_x_c0 = proof.b.x.c0.into_bigint().to_bytes_le();
//     let b_x_c1 = proof.b.x.c1.into_bigint().to_bytes_le();
//     let b_y_c0 = proof.b.y.c0.into_bigint().to_bytes_le();
//     let b_y_c1 = proof.b.y.c1.into_bigint().to_bytes_le();
//     input.extend_from_slice(&pad_to_64_bytes(&b_x_c0));
//     input.extend_from_slice(&pad_to_64_bytes(&b_x_c1));
//     input.extend_from_slice(&pad_to_64_bytes(&b_y_c0));
//     input.extend_from_slice(&pad_to_64_bytes(&b_y_c1));
//
//     // Prepare -alpha * A (negation of A)
//     let neg_a = proof.a.neg();
//     let neg_a_x = neg_a.x.into_bigint().to_bytes_le();
//     let neg_a_y = neg_a.y.into_bigint().to_bytes_le();
//     input.extend_from_slice(&pad_to_64_bytes(&neg_a_x));
//     input.extend_from_slice(&pad_to_64_bytes(&neg_a_y));
//
//     // Prepare alpha (G2 generator)
//     let alpha = G2Affine::prime_subgroup_generator();
//     let alpha_x_c0 = alpha.x.c0.into_bigint().to_bytes_le();
//     let alpha_x_c1 = alpha.x.c1.into_bigint().to_bytes_le();
//     let alpha_y_c0 = alpha.y.c0.into_bigint().to_bytes_le();
//     let alpha_y_c1 = alpha.y.c1.into_bigint().to_bytes_le();
//     input.extend_from_slice(&pad_to_64_bytes(&alpha_x_c0));
//     input.extend_from_slice(&pad_to_64_bytes(&alpha_x_c1));
//     input.extend_from_slice(&pad_to_64_bytes(&alpha_y_c0));
//     input.extend_from_slice(&pad_to_64_bytes(&alpha_y_c1));
//
//     // Prepare C (G1 point)
//     let c_x = proof.c.x.into_bigint().to_bytes_le();
//     let c_y = proof.c.y.into_bigint().to_bytes_le();
//     input.extend_from_slice(&pad_to_64_bytes(&c_x));
//     input.extend_from_slice(&pad_to_64_bytes(&c_y));
//
//     // Prepare beta (G2 generator)
//     let beta = E::G2Affine::prime_subgroup_generator();
//     let beta_x_c0 = beta.x.c0.into_bigint().to_bytes_le();
//     let beta_x_c1 = beta.x.c1.into_bigint().to_bytes_le();
//     let beta_y_c0 = beta.y.c0.into_bigint().to_bytes_le();
//     let beta_y_c1 = beta.y.c1.into_bigint().to_bytes_le();
//     input.extend_from_slice(&pad_to_64_bytes(&beta_x_c0));
//     input.extend_from_slice(&pad_to_64_bytes(&beta_x_c1));
//     input.extend_from_slice(&pad_to_64_bytes(&beta_y_c0));
//     input.extend_from_slice(&pad_to_64_bytes(&beta_y_c1));
//
//     // Call the syscall
//     match alt_bn128_pairing(&input) {
//         Ok(1) => Ok(true),
//         Ok(0) => Ok(false),
//         Ok(_) => Err(ProgramError::InvalidAccountData),
//         Err(_) => Err(ProgramError::InvalidAccountData),
//     }
// }

fn pad_to_64_bytes(input: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; 64];
    let len = std::cmp::min(input.len(), 64);
    result[..len].copy_from_slice(&input[..len]);
    result
}

