use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalSerialize, SerializationError};

// Helper function to convert a field element to bytes
pub fn field_to_bytes<F: PrimeField>(field: F) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    field.serialize_uncompressed(&mut bytes[..]).unwrap();
    bytes
}

// Helper function to convert bytes to a field element
pub fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> Result<F, SerializationError> {
    F::deserialize_uncompressed(bytes)
}

pub fn reverse_endianness(input: &mut [u8]) {
    for chunk in input.chunks_mut(32) {
        chunk.reverse();
    }
}

pub fn convert_endianness_64_to_vec(bytes: &[u8]) -> Vec<u8> {
    bytes.chunks(32)
        .flat_map(|chunk| chunk.iter().rev().cloned().collect::<Vec<u8>>())
        .collect()
}

pub fn convert_endianness_128(bytes: &[u8]) -> Vec<u8> {
    bytes.chunks(64)
        .flat_map(|chunk| chunk.iter().rev().cloned().collect::<Vec<u8>>())
        .collect()
}

pub fn convert_endianness_64(input: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    for (i, &byte) in input.iter().enumerate().take(64) {
        output[i] = byte.swap_bytes(); // This swaps endianness for each byte
    }
    output
}

pub fn convert_endianness_32(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (i, &byte) in input.iter().enumerate().take(32) {
        output[i] = byte.swap_bytes(); // This swaps endianness for each byte
    }
    output
}

pub fn change_endianness(bytes: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for b in bytes.chunks(32) {
        for byte in b.iter().rev() {
            vec.push(*byte);
        }
    }
    vec
}

pub fn fr_to_g1(scalar: &Fr) -> G1Affine {
    let generator = G1Affine::generator();
    let point = G1Projective::from(generator) * scalar;
    point.into_affine()
}

// The generator point of G1 in uncompressed form
// const G1_GENERATOR: [u8; 64] = [
//     1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//     2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// ];
//
// fn fr_to_g1_solana(scalar: &[u8; 32]) -> Result<[u8; 64], ProgramError> {
//     let mut result = [0u8; 64];
//     alt_bn128_multiplication(&[&G1_GENERATOR[..], scalar].concat(), &mut result)
//         .map_err(|_| ProgramError::InvalidAccountData)?;
//
//     Ok(result)
// }

pub fn g1_affine_to_bytes(point: &G1Affine) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    point.serialize_uncompressed(&mut bytes[..])
        .expect("Serialization should not fail");
    bytes
}