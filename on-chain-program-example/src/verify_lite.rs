use std::ops::Neg;
use crate::byte_utils::{change_endianness, convert_endianness_128, convert_endianness_32, convert_endianness_64};
use crate::errors::Groth16Error;
use crate::prove::{ProofPackageLite, ProofPackagePrepared};
use ark_bn254::Bn254;
use ark_ff::PrimeField;
use ark_groth16::{PreparedVerifyingKey, Proof, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use num_bigint::BigUint;
use solana_program::alt_bn128::compression::prelude::convert_endianness;
use solana_program::alt_bn128::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing, ALT_BN128_PAIRING_ELEMENT_LEN};
use solana_program::alt_bn128::AltBn128Error;
use crate::errors::Groth16Error::{PairingVerificationError, ProofVerificationFailed};

type G1 = ark_bn254::g1::G1Affine;

// TODO THIS ONE WORKS FOR PREPARED PUBLIC INPUT - Sort of
pub fn verify_proof(proof_package: ProofPackagePrepared) -> Result<bool, AltBn128Error> {
    let mut pairing_input = Vec::new();

    // Check proof size
    if proof_package.proof.len() != 256 {
        println!("Proof size is incorrect: {} bytes", proof_package.proof.len());
        return Err(AltBn128Error::InvalidInputData);
    }

    // Check public inputs size
    if proof_package.public_inputs.len() != 64 {
        println!("Public inputs size is incorrect: {} bytes", proof_package.public_inputs.len());
        return Err(AltBn128Error::InvalidInputData);
    }

    let verifying_key = VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(&proof_package.verifying_key[..]).unwrap();

    // self.proof_a.as_slice(),
    // self.proof_b.as_slice(),
    // self.prepared_public_inputs.as_slice(),
    // self.verifyingkey.vk_gamma_g2.as_slice(),
    // self.proof_c.as_slice(),
    // self.verifyingkey.vk_delta_g2.as_slice(),
    // self.verifyingkey.vk_alpha_g1.as_slice(),
    // self.verifyingkey.vk_beta_g2.as_slice(),

    // Pair 1: proof.a (G1) and proof.b (G2)
    pairing_input.extend_from_slice(&convert_endianness_64(&proof_package.proof[0..64]));
    pairing_input.extend_from_slice(&convert_endianness_128(&proof_package.proof[64..192]));

    // Pair 2: alpha_g1 (G1) and beta_g2 (G2)
    let mut alpha_g1_bytes = Vec::new();
    verifying_key.alpha_g1.serialize_uncompressed(&mut alpha_g1_bytes).expect("Failed to serialize alpha_g1");
    pairing_input.extend_from_slice(&convert_endianness_64(&alpha_g1_bytes));

    let mut beta_g2_bytes = Vec::new();
    verifying_key.beta_g2.serialize_uncompressed(&mut beta_g2_bytes).expect("Failed to serialize beta_g2");
    pairing_input.extend_from_slice(&convert_endianness_128(&beta_g2_bytes));

    // Pair 3: public_inputs (G1) and gamma_g2 (G2)
    let public_inputs = convert_endianness_64(&proof_package.public_inputs);
    pairing_input.extend_from_slice(&public_inputs);
    // pairing_input.extend_from_slice(public_inputs[0].as_slice());
    // pairing_input.extend_from_slice(public_inputs[1].as_slice());

    let mut gamma_g2_bytes = Vec::new();
    verifying_key.gamma_g2.serialize_uncompressed(&mut gamma_g2_bytes).expect("Failed to serialize gamma_g2");
    pairing_input.extend_from_slice(&convert_endianness_128(&gamma_g2_bytes));

    // Pair 4: proof.c (G1) and delta_g2 (G2)
    pairing_input.extend_from_slice(&convert_endianness_64(&proof_package.proof[192..256]));

    let mut delta_g2_bytes = Vec::new();
    verifying_key.delta_g2.serialize_uncompressed(&mut delta_g2_bytes).expect("Failed to serialize delta_g2");
    pairing_input.extend_from_slice(&convert_endianness_128(&delta_g2_bytes));

    // Check that we have the correct number of pairing elements
    if pairing_input.len() != 4 * ALT_BN128_PAIRING_ELEMENT_LEN {
        println!("Incorrect pairing input size: {} bytes", pairing_input.len());
        return Err(AltBn128Error::InvalidInputData);
    }

    // Perform the pairing check
    let result = alt_bn128_pairing(&pairing_input)?;

    // Check if the result indicates a valid proof
    Ok(result == [0u8; 31].iter().chain(&[1u8]).cloned().collect::<Vec<u8>>())
}


// On-chain verify
pub fn verify_groth16_proof(
    proof_package: &ProofPackageLite
) -> Result<bool, AltBn128Error> {

    // Check proof size
    if proof_package.proof.len() != 256 {
        println!("Proof size is incorrect: {} bytes", &proof_package.proof.len());
        return Err(AltBn128Error::InvalidInputData);
    }

    // Check public inputs size
    // if public_inputs.len() != 64 {
    //     println!("Public inputs size is incorrect: {} bytes", public_inputs.len());
    //     return Err(AltBn128Error::InvalidInputData);
    // }

    // let proof_a: &[u8; 64] = convert_endianness_64(&proof_package.proof[0..64]).as_slice().into();
    // let proof_b: &[u8; 128] = proof_package.proof[64..192].try_into().unwrap();
    // let proof_c: &[u8; 64] = proof_package.proof[64..192].try_into().unwrap();

    let converted_proof = extract_and_convert_proof(&proof_package).expect("TODO: panic message");
    // let arr: [[u8; 32]; NR_INPUTS] = converted_endian.try_into()
    //     .map_err(|_| "Conversion failed")?;
    // let converted_pic: &[u8; 64] = &proof_package.public_inputs.try_into().unwrap();

    // let proof_a = change_endianness(&proof_a_neg[..64]).try_into().unwrap();
    // let proof_b = PROOF[64..192].try_into().unwrap();
    // let proof_c = PROOF[192..256].try_into().unwrap();

    // 1. Extract points from proof_bytes
    // let a = extract_g1_point(&proof_package.proof[0..64])?;
    // let b = extract_g2_point(&proof_package.proof[64..192])?;
    // let c = extract_g1_point(&proof_package.proof[64..192])?;


    let vk = convert_bytes_vk(&proof_package.verifying_key);
    let pi = convert_vec_to_array(&proof_package.public_inputs).unwrap();

    let mut verifier = Groth16Verifier::new(
        &converted_proof.0,
        &converted_proof.1,
        &converted_proof.2,
        &pi,
        &vk,
    ).unwrap();

    match verifier.verify_unchecked() {
        Ok(true) => {
            println!("Proof verification succeeded");
            Ok(true)
        }
        Ok(false) | Err(_) => {
            println!("Proof verification failed");
            Ok(false)
        }
    }

}

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
    verifyingkey: &'a Groth16VerifyingKey<'a>,
}

impl<const NR_INPUTS: usize> Groth16Verifier<'_, NR_INPUTS> {
    pub fn new<'a>(
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        public_inputs: &'a [[u8; 32]; NR_INPUTS],
        verifyingkey: &'a Groth16VerifyingKey<'a>,
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

        if public_inputs.len() + 1 != verifyingkey.vk_ic.len() {
            return Err(Groth16Error::InvalidPublicInputsLength);
        }

        Ok(Groth16Verifier {
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            prepared_public_inputs: [0u8; 64],
            verifyingkey,
        })
    }

    pub fn new_prepared<'a>(
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        public_inputs: &'a [[u8; 32]; NR_INPUTS],
        prepared_public_inputs: [u8; 64],
        verifyingkey: &'a Groth16VerifyingKey<'a>,
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

        if public_inputs.len() + 1 != verifyingkey.vk_ic.len() {
            return Err(Groth16Error::InvalidPublicInputsLength);
        }

        Ok(Groth16Verifier {
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            prepared_public_inputs,
            verifyingkey,
        })
    }

    // pub fn prepare_inputs(
    //     pvk: &PreparedVerifyingKey<E>,
    //     public_inputs: &[E::ScalarField],
    // ) -> R1CSResult<E::G1> {
    //     if (public_inputs.len() + 1) != pvk.vk.gamma_abc_g1.len() {
    //         return Err(SynthesisError::MalformedVerifyingKey);
    //     }
    //
    //     let mut g_ic = pvk.vk.gamma_abc_g1[0].into_group();
    //     for (i, b) in public_inputs.iter().zip(pvk.vk.gamma_abc_g1.iter().skip(1)) {
    //         g_ic.add_assign(&b.mul_bigint(i.into_bigint()));
    //     }
    //
    //     Ok(g_ic)
    // }

    pub fn prepare_inputs<const CHECK: bool>(&mut self) -> Result<(), Groth16Error> {
        let mut prepared_public_inputs = self.verifyingkey.vk_ic[0];

        for (i, input) in self.public_inputs.iter().enumerate() {
            if CHECK && !is_less_than_bn254_field_size_be(input) {
                return Err(Groth16Error::PublicInputGreaterThenFieldSize);
            }
            let x = [&self.verifyingkey.vk_ic[i + 1][..], &input[..]].concat();
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
    pub fn verify(&mut self) -> Result<bool, Groth16Error> {
        self.verify_common::<true>()
    }

    /// Verifies the proof, and does not check that public inputs are smaller
    /// than field size.
    pub fn verify_unchecked(&mut self) -> Result<bool, Groth16Error> {
        self.prepare_and_verify_common::<false>()
    }

    fn prepare_and_verify_common<const CHECK: bool>(&mut self) -> Result<bool, Groth16Error> {
        self.prepare_inputs::<CHECK>()?;

        let pairing_input = [
            self.proof_a.as_slice(),
            self.proof_b.as_slice(),
            self.prepared_public_inputs.as_slice(),
            self.verifyingkey.vk_gamma_g2.as_slice(),
            self.proof_c.as_slice(),
            self.verifyingkey.vk_delta_g2.as_slice(),
            self.verifyingkey.vk_alpha_g1.as_slice(),
            self.verifyingkey.vk_beta_g2.as_slice(),
        ]
            .concat();

        let converted_input: Vec<u8> = pairing_input
            .chunks(ALT_BN128_PAIRING_ELEMENT_LEN)
            .flat_map(|chunk| {
                let mut converted = Vec::new();
                converted.extend_from_slice(&convert_endianness_64(&chunk[..64]));
                converted.extend_from_slice(&convert_endianness_128(&chunk[64..]));
                converted
            })
            .collect();
        let pairing_res = alt_bn128_pairing(pairing_input.as_slice())
            .map_err(|_| PairingVerificationError)?;
        println!("Pairing result: {:?}", pairing_res);
        if pairing_res[31] != 1 {
            return Ok(false)
        }

        Ok(true)
    }

    fn verify_common<const CHECK: bool>(&mut self) -> Result<bool, Groth16Error> {
        let pairing_input = [
            self.proof_a.as_slice(),
            self.proof_b.as_slice(),
            self.prepared_public_inputs.as_slice(),
            self.verifyingkey.vk_gamma_g2.as_slice(),
            self.proof_c.as_slice(),
            self.verifyingkey.vk_delta_g2.as_slice(),
            self.verifyingkey.vk_alpha_g1.as_slice(),
            self.verifyingkey.vk_beta_g2.as_slice(),
        ]
            .concat();

        let pairing_res = alt_bn128_pairing(pairing_input.as_slice())
            .map_err(|_| Groth16Error::ProofVerificationFailed)?;

        if pairing_res[31] != 1 {
            return Err(Groth16Error::ProofVerificationFailed);
        }
        Ok(true)
    }
}

pub fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
    let bigint = BigUint::from_bytes_le(bytes);
    bigint < ark_bn254::Fr::MODULUS.into()
}

pub fn convert_bytes_vk(verifying_key: &[u8]) -> Groth16VerifyingKey<'static> {
    //TODO
    let vk = VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(verifying_key).unwrap();
    let vk_alpha_g1_converted = convert_endianness::<32, 64>(<&[u8; 64]>::try_from(&verifying_key[0..64]).unwrap());
    let vk_beta_g2_converted = convert_endianness::<64, 128>(<&[u8; 128]>::try_from(&verifying_key[64..192]).unwrap());
    let vk_gamma_g2_converted = convert_endianness::<64, 128>(<&[u8; 128]>::try_from(&verifying_key[192..320]).unwrap());
    let vk_delta_g2_converted = convert_endianness::<64, 128>(<&[u8; 128]>::try_from(&verifying_key[320..448]).unwrap());

    // Convert gamma_abc_g1 (vk_ic)
    // let vk_ic: Vec<[u8; 64]> = verifying_key[448..]
    //     .chunks(64)
    //     .map(|chunk| {
    //         let mut buf = [0u8; 64];
    //         buf.copy_from_slice(chunk);
    //         convert_endianness::<32, 64>(&buf)
    //     })
    //     .collect();

    // Convert gamma_abc_g1 (vk_ic)
    let vk_ic: Vec<[u8; 64]> = vk.gamma_abc_g1
        .iter()
        .map(|point| {
            let mut buf = [0u8; 64];
            point.serialize_uncompressed(&mut buf[..]).unwrap();
            convert_endianness::<32, 64>(&buf)
        })
        .collect();

    Groth16VerifyingKey {
        nr_pubinputs: vk_ic.len() - 1, // Subtract 1 for the constant term
        vk_alpha_g1: vk_alpha_g1_converted,
        vk_beta_g2: vk_beta_g2_converted,
        vk_gamma_g2: vk_gamma_g2_converted,
        vk_delta_g2: vk_delta_g2_converted,
        vk_ic: Box::leak(vk_ic.into_boxed_slice()), // Convert to 'static lifetime
    }
}

fn convert_arkworks_vk_to_solana(ark_vk: &VerifyingKey<Bn254>) -> Groth16VerifyingKey<'static> {
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

    Groth16VerifyingKey {
        nr_pubinputs: 2, // Subtract 1 for the constant term
        vk_alpha_g1: vk_alpha_g1_converted,
        vk_beta_g2: vk_beta_g2_converted,
        vk_gamma_g2: vk_gamma_g2_converted,
        vk_delta_g2: vk_delta_g2_converted,
        vk_ic: Box::leak(vk_ic.into_boxed_slice()), // Convert to 'static lifetime
    }
}

const NR_INPUTS: usize = 2; // Replace with your actual NR_INPUTS value
fn convert_vec_to_array(vec: &Vec<[u8; 32]>) -> Result<[[u8; 32]; NR_INPUTS], String> {
    if vec.len() != NR_INPUTS {
        return Err(format!("Expected {} elements, but got {}", NR_INPUTS, vec.len()));
    }

    let converted_endian: Vec<[u8; 32]> = vec.iter().map(|bytes| convert_endianness_32(bytes)).collect();
    let arr: [[u8; 32]; NR_INPUTS] = converted_endian.try_into()
        .map_err(|_| "Conversion failed")?;

    Ok(arr)
}



fn extract_and_convert_proof(proof_package: &ProofPackageLite) -> Result<([u8; 64], [u8; 128], [u8; 64]), &'static str> {
    // Ensure the proof is at least 64 bytes long
    if proof_package.proof.len() < 64 {
        return Err("Proof is too short");
    }

    // let proof = Proof::<Bn254>::deserialize_uncompressed_unchecked(&proof_package.proof[..]).unwrap();
    // let mut proof_a_bytes = Vec::with_capacity(proof.a.serialized_size(Compress::No));
    // let _ = proof.a.serialize_uncompressed(&mut proof_a_bytes);
    //
    // let proof_a: G1 = G1::deserialize_with_mode(
    //         &*[&change_endianness(&proof_a_bytes[0..64]), &[0u8][..]].concat(),
    //         Compress::No,
    //     Validate::Yes,
    // ).unwrap();
    //
    // let mut proof_a_neg = [0u8; 65];
    //
    // proof_a
    //     .neg()
    //     .x
    //     .serialize_with_mode(&mut proof_a_neg[..32], Compress::No).unwrap();
    //
    // proof_a
    //     .neg()
    //     .y
    //     .serialize_with_mode(&mut proof_a_neg[32..], Compress::No).unwrap();

    // let proof_a = convert_endianness::<32, 64>(<&[u8; 64]>::try_from(&proof_a_neg[..64]).unwrap());


    // let proof = Proof::<Bn254>::deserialize_uncompressed_unchecked(&proof_package.proof[..]).expect("TODO: panic message");
    // let mut proof_a_neg_bytes = Vec::new();
    // let _ = proof.a.neg().serialize_uncompressed(&mut proof_a_neg_bytes).unwrap();

    // Convert to fixed-size array and change endianness
    // let proof_a: [u8; 64] = convert_endianness::<32, 64>(proof_a_neg_bytes.as_slice().try_into().unwrap());
    let proof_a: [u8; 64] = convert_endianness::<32, 64>(proof_package.proof[0..64].try_into().unwrap());
    let proof_b: [u8; 128] = convert_endianness::<64, 128>(proof_package.proof[64..192].try_into().unwrap());
    let proof_c: [u8; 64] = convert_endianness::<32, 64>(proof_package.proof[192..256].try_into().unwrap());

    // let proof_a: [u8; 64] = proof_package.proof[0..64].try_into().unwrap();
    // let proof_b: [u8; 128] = proof_package.proof[64..192].try_into().unwrap();
    // let proof_c: [u8; 64] = proof_package.proof[192..256].try_into().unwrap();

    Ok((proof_a, proof_b, proof_c))
}