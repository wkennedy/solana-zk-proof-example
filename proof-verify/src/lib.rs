#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use alloc::{format, vec};
use ark_ec::pairing::Pairing;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::alt_bn128::prelude::*;
use solana_program::program_error::ProgramError;
use solana_program::program_memory::sol_memcpy;
use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
};

const VK: &[u8] = include_bytes!("/home/waggins/projects/solana-zk-proof-example/on-chain-program-example/pvk.bin");

// Define a struct to hold the proof and public inputs
// In this case, the public inputs are "prepared inputs" which include the public data we want to verify as well as the verification key
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct ProofPackage {
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
    verifying_key: Vec<u8>
}

// Program's entrypoint
entrypoint!(process_instruction);

// Main function to process the instruction
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {

    // Deserialize proof and public inputs from instruction_data
    // let (proof, public_inputs) = deserialize_proof_package(instruction_data).unwrap();

    // let mut pairing_data = Vec::new();
    //
    // proof.serialize_uncompressed(&mut pairing_data).expect("Error serializing proof");

    // Verify the proof
    // let result = verify_groth16_proof(proof.as_slice(), &public_inputs)?;
    // let proof_package = ProofPackage::try_from_slice(instruction_data)?;
    //
    // let result = verify_proof3(proof_package).unwrap();
    // let prepared_verifying_key = PreparedVerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(PVK).expect("TODO: panic message");

    let proof_package = ProofPackage::try_from_slice(instruction_data)?;
    let result = verify_proof(&proof_package)?;

    if result {
        msg!("Proof is valid! Account properties verified.");
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
    msg!("{:?}", &result);

    // Ok(true)
    Ok(result.unwrap().last() == Some(&1))
}

fn verify_proof(proof_package: &ProofPackage) -> Result<bool, ProgramError> {
    // Allocate memory on the heap for pairing input
    let mut pairing_input = vec![0u8; 6 * 64 + 2 * 128]; // Adjusted size based on input requirements

    // Copy proof components directly without deserializing
    sol_memcpy(&mut pairing_input[0..64], &proof_package.proof[0..64], 64);    // proof.a
    sol_memcpy(&mut pairing_input[64..192], &proof_package.proof[64..192], 128); // proof.b
    sol_memcpy(&mut pairing_input[192..256], &proof_package.proof[192..256], 64); // proof.c

    // Copy prepared inputs
    sol_memcpy(&mut pairing_input[256..320], &proof_package.public_inputs, 64);

    // Copy relevant parts of prepared verifying key
    // Assuming the layout of prepared_verifying_key is known, adjust indices as needed
    sol_memcpy(&mut pairing_input[320..448], &VK[0..128], 128); // gamma_g2_neg_pc
    sol_memcpy(&mut pairing_input[448..576], &VK[128..256], 128); // delta_g2_neg_pc

    // Perform the pairing check using alt_bn128_pairing
    let result = alt_bn128_pairing(&pairing_input).unwrap();

    // Check if the result indicates a valid proof
    // The exact check might need adjustment based on how alt_bn128_pairing returns its result
    Ok(result == [0u8; 31].iter().chain(&[1u8]).cloned().collect::<Vec<u8>>())
}
