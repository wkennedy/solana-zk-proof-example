use crate::byte_utils::{convert_endianness_128, convert_endianness_64, convert_endianness_64_to_vec};
use crate::prove::ProofPackage;
use ark_bn254::{Bn254, G1Projective};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, BigInteger256};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use solana_program::alt_bn128::prelude::{alt_bn128_pairing, ALT_BN128_PAIRING_ELEMENT_LEN, ALT_BN128_POINT_SIZE};
use solana_program::alt_bn128::{AltBn128Error, PodG1, PodG2};
use solana_program::program_error::ProgramError;

type G1 = ark_bn254::g1::G1Affine;
type G2 = ark_bn254::g2::G2Affine;

pub fn verify(
    proof: &Proof<Bn254>,
    public_inputs: &G1Projective,
    vk: &VerifyingKey<Bn254>,
) -> bool {
    let pvk = prepare_verifying_key(vk);
    Groth16::<Bn254>::verify_proof_with_prepared_inputs(&pvk, proof, public_inputs).unwrap()
}

pub fn verify_proof_package(
    proof_package: &ProofPackage
) -> bool {
    Groth16::<Bn254>::verify_proof_with_prepared_inputs(&proof_package.prepared_verifying_key, &proof_package.proof, &proof_package.public_inputs).unwrap()
}


// Function to verify proof using Solana's alt_bn128_pairing syscall
// pub fn verify_proof_with_prepared_inputs2(
//     pvk: &PreparedVerifyingKey<Bn254>,
//     proof: &Proof<Bn254>,
//     prepared_inputs: &G1Point,
// ) -> Result<bool, ProgramError> {
//     // Perform the first pairing (proof.a, proof.b)
//     let pairing1 = alt_bn128_pairing(
//         &[proof.a.x, proof.a.y],
//         &[proof.b.x[0], proof.b.x[1], proof.b.y[0], proof.b.y[1]],
//     );
//
//     if pairing1.is_err() {
//         msg!("Pairing 1 failed");
//         return Err(pairing1.unwrap_err());
//     }
//
//     // Perform the second pairing (prepared_inputs, pvk.gamma_g2_neg_pc)
//     let pairing2 = alt_bn128_pairing(
//         &[prepared_inputs.x, prepared_inputs.y],
//         &[pvk.gamma_g2_neg_pc.x[0], pvk.gamma_g2_neg_pc.x[1], pvk.gamma_g2_neg_pc.y[0], pvk.gamma_g2_neg_pc.y[1]],
//     );
//
//     if pairing2.is_err() {
//         msg!("Pairing 2 failed");
//         return Err(pairing2.unwrap_err());
//     }
//
//     // Perform the third pairing (proof.c, pvk.delta_g2_neg_pc)
//     let pairing3 = alt_bn128_pairing(
//         &[proof.c.x, proof.c.y],
//         &[pvk.delta_g2_neg_pc.x[0], pvk.delta_g2_neg_pc.x[1], pvk.delta_g2_neg_pc.y[0], pvk.delta_g2_neg_pc.y[1]],
//     );
//
//     if pairing3.is_err() {
//         msg!("Pairing 3 failed");
//         return Err(pairing3.unwrap_err());
//     }
//
//     // All pairings succeeded, now combine the results
//     let final_result = pairing1.unwrap() && pairing2.unwrap() && pairing3.unwrap();
//
//     // Compare with the expected precomputed value in the verifying key
//     if final_result == pvk.alpha_g1_beta_g2 {
//         msg!("Proof verification succeeded");
//         Ok(true)
//     } else {
//         msg!("Proof verification failed");
//         Ok(false)
//     }
// }

pub fn verify_proof_with_prepared_inputs(
    proof_package: &ProofPackage // Using G1 representation for Solana
) -> Result<bool, ProgramError> {
    // Perform pairing checks

    let mut pairing_1 = Vec::new();
    let mut proof_a_bytes = Vec::new();
    proof_package.proof.a.serialize_uncompressed(&mut proof_a_bytes).unwrap();
    pairing_1.extend_from_slice(&proof_a_bytes);

    let mut proof_b_bytes = Vec::new();
    proof_package.proof.b.serialize_uncompressed(&mut proof_b_bytes).unwrap();
    pairing_1.extend_from_slice(&proof_a_bytes);

    // Pairing (proof.a, proof.b)
    let pairing1 = alt_bn128_pairing(&pairing_1).unwrap();

    let mut pairing_2 = Vec::new();
    let mut public_input_bytes = Vec::new();
    proof_package.public_inputs.serialize_uncompressed(&mut public_input_bytes).unwrap();
    pairing_2.extend_from_slice(convert_endianness_64(&public_input_bytes).as_ref());

    let mut gamma_g2_neg_bytes = Vec::new();
    proof_package.prepared_verifying_key.gamma_g2_neg_pc.serialize_uncompressed(&mut gamma_g2_neg_bytes).unwrap();
    pairing_2.extend_from_slice(&gamma_g2_neg_bytes);

    // Pairing (prepared_inputs, pvk.gamma_g2_neg_pc)
    let pairing2 = alt_bn128_pairing(&pairing_2).unwrap();

    let mut pairing_3 = Vec::new();
    let mut proof_c_bytes = Vec::new();
    proof_package.proof.c.serialize_uncompressed(&mut proof_c_bytes).unwrap();
    pairing_3.extend_from_slice(&proof_c_bytes);

    let mut delta_g2_neg_pc_bytes = Vec::new();
    proof_package.prepared_verifying_key.delta_g2_neg_pc.serialize_uncompressed(&mut delta_g2_neg_pc_bytes).unwrap();
    pairing_3.extend_from_slice(&delta_g2_neg_pc_bytes);

    // Pairing (proof.c, pvk.delta_g2_neg_pc)
    let pairing3 = alt_bn128_pairing(&delta_g2_neg_pc_bytes).unwrap();

    // Final result
    // let final_result = pairing1 && pairing2 && pairing3;

    // Ensure the result matches the expected value in the prepared verifying key
    // Ok(final_result == proof_package.prepared_verifying_key.alpha_g1_beta_g2)
    Ok(true)
}

// TODO These are just tests trying to get verify to work correctly
pub fn alt_bn128_pairing2(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
    // Check if input length is divisible by the pairing element size
    if input.len() % ALT_BN128_PAIRING_ELEMENT_LEN != 0 {
        return Err(AltBn128Error::InvalidInputData);
    }

    let ele_len = input.len() / ALT_BN128_PAIRING_ELEMENT_LEN; // Number of pairs
    let mut vec_pairs: Vec<(G1, G2)> = Vec::new();

    for i in 0..ele_len {
        let g1_start = i * ALT_BN128_PAIRING_ELEMENT_LEN;
        let g1_end = g1_start + ALT_BN128_POINT_SIZE;
        let g2_start = g1_end;
        let g2_end = g2_start + ALT_BN128_PAIRING_ELEMENT_LEN - ALT_BN128_POINT_SIZE;

        // Extract and convert G1 bytes
        let g1_bytes = &input[g1_start..g1_end];
        let g1_converted = convert_endianness_64_to_vec(g1_bytes);
        let g1 = PodG1(g1_converted.try_into().map_err(AltBn128Error::TryIntoVecError)?).try_into()?;

        // Extract and convert G2 bytes
        let g2_bytes = &input[g2_start..g2_end];
        let g2_converted = convert_endianness_128(g2_bytes);
        let g2 = PodG2(g2_converted.try_into().map_err(AltBn128Error::TryIntoVecError)?).try_into()?;

        vec_pairs.push((g1, g2));
    }

    // Perform the pairing check
    let mut result = BigInteger256::from(0u64);
    let res = <Bn254 as Pairing>::multi_miller_loop(
        vec_pairs.iter().map(|pair| pair.0),
        vec_pairs.iter().map(|pair| pair.1),
    );

    // Check the result of the pairing
    if res.0 == ark_bn254::Fq12::one() {
        result = BigInteger256::from(1u64);
    }

    let output = result.to_bytes_be();
    Ok(output)
}

//
// fn verify_proof3(
//     proof_package: ProofPackageLite
// ) -> Result<bool, AltBn128Error> {
//     // Convert VerifyingKey to PreparedVerifyingKey
//     // let pvk = PreparedVerifyingKey::from(verifying_key);
//
//     // Extract proof components
//     // let proof = Proof::<Bn254> {
//     //     a: proof_package.proof[0..64].try_into().map_err(|_| AltBn128Error::InvalidInputData)?,
//     //     b: proof_package.proof[64..192].try_into().map_err(|_| AltBn128Error::InvalidInputData)?,
//     //     c: proof_package.proof[192..256].try_into().map_err(|_| AltBn128Error::InvalidInputData)?,
//     // };
//
//     let proof = Proof::<Bn254>::deserialize_uncompressed_unchecked(&proof_package.proof[..]).expect("TODO: panic message");
//     let prepared_verifying_key = PreparedVerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(&proof_package.verifying_key[..]).expect("TODO: panic message");
//     let prepared_inputs = G1Projective::deserialize_uncompressed_unchecked(&proof_package.public_inputs).expect("TODO: panic message");
//
//     // Perform the pairing check
//     let qap = <Bn254 as Pairing>::multi_miller_loop(
//         [
//             proof.a.into_group(),
//             prepared_inputs.into_affine().into(),
//             proof.c.into(),
//         ],
//         [proof.b.into(),
//             prepared_verifying_key.gamma_g2_neg_pc.clone(),
//             prepared_verifying_key.delta_g2_neg_pc.clone(),]);
//
//     let test = Bn254::final_exponentiation(qap).ok_or(AltBn128Error::UnexpectedError)?;
//
//     Ok(test.0 == prepared_verifying_key.alpha_g1_beta_g2)
// }


