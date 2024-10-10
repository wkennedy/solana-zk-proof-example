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

pub fn convert_endianness_128(input: &[u8]) -> [u8; 128] {
    let mut output = [0u8; 128];
    for (i, &byte) in input.iter().enumerate().take(128) {
        output[i] = byte.swap_bytes(); // This swaps endianness for each byte
    }
    output
}