use ark_bn254::{Bn254, Fq2};
use ark_ff::PrimeField;
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::alt_bn128::prelude::*;
use solana_program::instruction::InstructionError::InvalidInstructionData;
use solana_program::program_error::ProgramError;
use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
};

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct ProofPackage {
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
}

// On-chain verification (Solana program)
entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {

    // Deserialize proof and public inputs from instruction_data
    // Note: In a real implementation, you'd need to properly deserialize this data
    let (proof, public_inputs) = deserialize_proof_package(instruction_data).unwrap();

    let pairing_data = Vec::new();

    proof.serialize_uncompressed(pairing_data.clone()).expect("");

    // Verify the proof
    let result = verify_groth16_proof(pairing_data.as_slice(), &public_inputs)?;

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

    Ok(result.unwrap().last() == Some(&1))
}

fn deserialize_proof_package(serialized_data: &[u8]) -> Result<(Proof<Bn254>, Vec<u8>), Box<dyn std::error::Error>> {
    // Deserialize the ProofPackage
    let proof_package = ProofPackage::try_from_slice(serialized_data)?;

    let proof1 = Proof::<Bn254>::deserialize_uncompressed_unchecked(&proof_package.proof[..]).expect("TODO: panic message");

    Ok((proof1, proof_package.public_inputs))
}

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

fn pad_to_64_bytes(input: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; 64];
    let len = std::cmp::min(input.len(), 64);
    result[..len].copy_from_slice(&input[..len]);
    result
}

// fn vec_array_to_slice(input: &Vec<[u8; 32]>) -> &[u8] {
//     // This works because Vec<[u8; 32]> has the same memory layout as [u8]
//     unsafe { std::slice::from_raw_parts(input.as_ptr() as *const u8, input.len() * 32) }
// }