use crate::byte_utils::convert_endianness_32;
use crate::errors::Groth16Error;
use crate::errors::Groth16Error::{PairingVerificationError, ProofVerificationFailed};
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use num_bigint::BigUint;
use solana_program::alt_bn128::compression::prelude::convert_endianness;
use solana_program::alt_bn128::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing};
use std::ops::AddAssign;

#[derive(PartialEq, Eq, Debug)]
pub struct Groth16VerifyingKey<'a> {
    pub nr_pubinputs: usize,
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamma_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: &'a [[u8; 64]],
}

#[derive(PartialEq, Eq, Debug)]
pub struct Groth16Verifier<'a, const NR_INPUTS: usize> {
    proof_a: &'a [u8; 64],
    proof_b: &'a [u8; 128],
    proof_c: &'a [u8; 64],
    public_inputs: &'a [[u8; 32]; NR_INPUTS],
    prepared_public_inputs: [u8; 64],
    verifying_key: &'a Groth16VerifyingKey<'a>,
}

#[derive(PartialEq, Eq, Debug)]
pub struct Groth16VerifierPrepared<'a> {
    proof_a: &'a [u8; 64],
    proof_b: &'a [u8; 128],
    proof_c: &'a [u8; 64],
    prepared_public_inputs: [u8; 64],
    verifying_key: &'a Groth16VerifyingKey<'a>,
}

impl Groth16VerifierPrepared<'_> {
    pub fn new<'a>(
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        prepared_public_inputs: [u8; 64],
        verifying_key: &'a Groth16VerifyingKey<'a>,
    ) -> Result<Groth16VerifierPrepared<'a>, Groth16Error> {
        if proof_a.len() != 64 {
            return Err(Groth16Error::InvalidG1Length);
        }

        if proof_b.len() != 128 {
            return Err(Groth16Error::InvalidG2Length);
        }

        if proof_c.len() != 64 {
            return Err(Groth16Error::InvalidG1Length);
        }
        
        Ok(Groth16VerifierPrepared {
            proof_a,
            proof_b,
            proof_c,
            prepared_public_inputs,
            verifying_key,
        })
    }
    
    pub fn verify(&mut self) -> Result<bool, Groth16Error> {
        let pairing_input = [
            self.proof_a.as_slice(),
            self.proof_b.as_slice(),
            self.prepared_public_inputs.as_slice(),
            self.verifying_key.vk_gamma_g2.as_slice(),
            self.proof_c.as_slice(),
            self.verifying_key.vk_delta_g2.as_slice(),
            self.verifying_key.vk_alpha_g1.as_slice(),
            self.verifying_key.vk_beta_g2.as_slice(),
        ]
            .concat();

        let pairing_res = alt_bn128_pairing(pairing_input.as_slice())
            .map_err(|_| ProofVerificationFailed)?;

        if pairing_res[31] != 1 {
            return Err(ProofVerificationFailed);
        }
        Ok(true)
    }
}


impl<const NR_INPUTS: usize> Groth16Verifier<'_, NR_INPUTS> {
    pub fn new<'a>(
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        public_inputs: &'a [[u8; 32]; NR_INPUTS],
        verifying_key: &'a Groth16VerifyingKey<'a>,
    ) -> Result<Groth16Verifier<'a, NR_INPUTS>, Groth16Error> {
        if proof_a.len() != 64 {
            return Err(Groth16Error::InvalidG1Length);
        }

        if proof_b.len() != 128 {
            return Err(Groth16Error::InvalidG2Length);
        }

        if proof_c.len() != 64 {
            return Err(Groth16Error::InvalidG1Length);
        }

        if public_inputs.len() + 1 != verifying_key.vk_ic.len() {
            return Err(Groth16Error::InvalidPublicInputsLength);
        }

        Ok(Groth16Verifier {
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            prepared_public_inputs: [0u8; 64],
            verifying_key,
        })
    }

    pub fn prepare_inputs<const CHECK: bool>(&mut self) -> Result<(), Groth16Error> {
        let mut prepared_public_inputs = self.verifying_key.vk_ic[0];

        for (i, input) in self.public_inputs.iter().enumerate() {
            if CHECK && !is_less_than_bn254_field_size_be(input) {
                return Err(Groth16Error::PublicInputGreaterThenFieldSize);
            }
            let x = [&self.verifying_key.vk_ic[i + 1][..], &input[..]].concat();
            let mul_res = alt_bn128_multiplication(
                &x
            )
                .map_err(|error|{ println!("{:?}", error);Groth16Error::PreparingInputsG1MulFailed})?;
            prepared_public_inputs =
                alt_bn128_addition(&[&mul_res[..], &prepared_public_inputs[..]].concat())
                    .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?[..]
                    .try_into()
                    .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?;
        }

        self.prepared_public_inputs = prepared_public_inputs;

        Ok(())
    }

    /// Verifies the proof, and checks that public inputs are smaller than
    /// field size.
    pub fn prepare_and_verify(&mut self) -> Result<bool, Groth16Error> {
        self.prepare_and_verify_common::<true>()
    }

    /// Verifies the proof, and does not check that public inputs are smaller
    /// than field size.
    pub fn prepare_and_verify_unchecked(&mut self) -> Result<bool, Groth16Error> {
        self.prepare_and_verify_common::<false>()
    }

    fn prepare_and_verify_common<const CHECK: bool>(&mut self) -> Result<bool, Groth16Error> {
        self.prepare_inputs::<CHECK>()?;

        let pairing_input = [
            self.proof_a.as_slice(),
            self.proof_b.as_slice(),
            self.prepared_public_inputs.as_slice(),
            self.verifying_key.vk_gamma_g2.as_slice(),
            self.proof_c.as_slice(),
            self.verifying_key.vk_delta_g2.as_slice(),
            self.verifying_key.vk_alpha_g1.as_slice(),
            self.verifying_key.vk_beta_g2.as_slice(),
        ]
            .concat();
        
        let pairing_res = alt_bn128_pairing(pairing_input.as_slice())
            .map_err(|_| PairingVerificationError)?;
        println!("Pairing result: {:?}", pairing_res);
        if pairing_res[31] != 1 {
            return Ok(false)
        }

        Ok(true)
    }
}

pub fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
    let bigint = BigUint::from_bytes_le(bytes);
    bigint < ark_bn254::Fr::MODULUS.into()
}

pub fn convert_arkworks_vk_to_solana_example(ark_vk: &VerifyingKey<Bn254>) -> Groth16VerifyingKey<'static> {
    // Convert alpha_g1
    let mut vk_alpha_g1 = [0u8; 64];
    ark_vk.alpha_g1
        .serialize_uncompressed(&mut vk_alpha_g1[..])
        .unwrap();

    // Convert beta_g2
    let mut vk_beta_g2 = [0u8; 128];
    ark_vk.beta_g2
        .serialize_uncompressed(&mut vk_beta_g2[..])
        .unwrap();

    // Convert gamma_g2
    let mut vk_gamma_g2 = [0u8; 128];
    ark_vk.gamma_g2
        .serialize_uncompressed(&mut vk_gamma_g2[..])
        .unwrap();

    // Convert delta_g2
    let mut vk_delta_g2 = [0u8; 128];
    ark_vk.delta_g2
        .serialize_uncompressed(&mut vk_delta_g2[..])
        .unwrap();

    // Convert gamma_abc_g1 (vk_ic)
    let vk_ic: Vec<[u8; 64]> = ark_vk.gamma_abc_g1
        .iter()
        .map(|point| {
            let mut buf = [0u8; 64];
            point.serialize_uncompressed(&mut buf[..]).unwrap();
            convert_endianness::<32, 64>(&buf)
        })
        .collect();

    let vk_alpha_g1_converted = convert_endianness::<32, 64>(&vk_alpha_g1);
    let vk_beta_g2_converted = convert_endianness::<64, 128>(&vk_beta_g2);
    let vk_gamma_g2_converted = convert_endianness::<64, 128>(&vk_gamma_g2);
    let vk_delta_g2_converted = convert_endianness::<64, 128>(&vk_delta_g2);

    println!("VK Alpha G1 (before conversion): {:?}", vk_alpha_g1);
    println!("VK Alpha G1 (after conversion): {:?}", vk_alpha_g1);

    Groth16VerifyingKey {
        nr_pubinputs: 2, // Subtract 1 for the constant term
        vk_alpha_g1: vk_alpha_g1_converted,
        vk_beta_g2: vk_beta_g2_converted,
        vk_gamma_g2: vk_gamma_g2_converted,
        vk_delta_g2: vk_delta_g2_converted,
        vk_ic: Box::leak(vk_ic.into_boxed_slice()), // Convert to 'static lifetime
    }
}

const NR_INPUTS: usize = 1; // Replace with your actual NR_INPUTS value
pub fn convert_ark_public_input(vec: &Vec<[u8; 32]>) -> Result<[[u8; 32]; NR_INPUTS], String> {
    if vec.len() != NR_INPUTS {
        return Err(format!("Expected {} elements, but got {}", NR_INPUTS, vec.len()));
    }

    println!("Input vector: {:?}", vec);
    let converted_endian: Vec<[u8; 32]> = vec.iter().map(|bytes| convert_endianness_32(bytes)).collect();
    let arr: [[u8; 32]; NR_INPUTS] = converted_endian.try_into()
        .map_err(|_| "Conversion failed")?;
    println!("Converted array: {:?}", arr);

    Ok(arr)
}

// Not used on chain, move to sdk
pub fn prepare_inputs(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> Result<G1Projective, SynthesisError> {
    if (public_inputs.len() + 1) != vk.gamma_abc_g1.len() {
        return Err(SynthesisError::MalformedVerifyingKey);
    }

    let mut g_ic = vk.gamma_abc_g1[0].into_group();
    for (i, b) in public_inputs.iter().zip(vk.gamma_abc_g1.iter().skip(1)) {
        g_ic.add_assign(&b.mul_bigint(i.into_bigint()));
    }

    Ok(g_ic)
}