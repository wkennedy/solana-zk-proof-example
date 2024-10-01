use crate::byte_utils::{convert_endianness_32, field_to_bytes};
use crate::verify_lite::Groth16VerifyingKey;
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::Zero;
use light_poseidon::PoseidonHasher;
use num_bigint::BigUint;
use sha2::Digest;
use solana_program::alt_bn128::compression::prelude::convert_endianness;
use std::io::Error;

// Circuit for proving knowledge of a Solana account's state changes
// The idea behind this example circuit is that the rollup that generates this proof for a batch of
// account changes, which this circuit representing the state change for the accounts in the batch
// collectively. The merkle_node_hash is a hash of the account leaf hashes (different from the Merkle root);
// The account_hash is a hash of the account addresses and data and the lamports sum is the sum of all account lamports.
#[derive(Clone)]
pub struct ExampleCircuit {
    pub some_value: Option<Fr>,
}

impl ExampleCircuit {

    pub fn default() -> Self {
        ExampleCircuit {
            some_value: None,
        }
    }

    pub fn new() -> Self {

        // Compute addresses_hash and lamports_sum
        // let mut poseidon = Poseidon::<Fr>::new_circom(1).unwrap();
        // addresses_hash = poseidon.hash(&[addresses_hash, address_fr, datum_fr]).unwrap();

        let circuit = ExampleCircuit {
            some_value: Some(Fr::from(100)),
        };

        circuit
    }

    pub fn public_inputs_fr(&self) -> Vec<[u8; 32]> {
        let public_inputs: Vec<[u8; 32]> = vec![
            field_to_bytes(self.some_value.unwrap()),
        ];

        public_inputs
    }

    pub fn public_inputs(&self) -> Vec<[u8; 32]> {
        let public_inputs: Vec<[u8; 32]> = vec![
            field_to_bytes(self.some_value.unwrap()),
        ];

        public_inputs
    }
}

impl ConstraintSynthesizer<Fr> for ExampleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {

        // Allocate public inputs
        let some_value_var = cs.new_input_variable(|| {
            self.some_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint: Ensure computed addresses_hash matches the provided addresses_hash
        cs.enforce_constraint(
            lc!() + some_value_var,
            lc!() + Variable::One,
            lc!() + some_value_var,
        )?;

        Ok(())
    }
}

fn convert_arkworks_vk_to_solana_example(ark_vk: &VerifyingKey<Bn254>) -> Groth16VerifyingKey<'static> {
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
    // Convert gamma_abc_g1
    let vk_ic: Vec<[u8; 64]> = ark_vk.gamma_abc_g1
        .iter()
        .map(|point| {
            let mut buf = [0u8; 64];
            point.serialize_uncompressed(&mut buf[..]).unwrap();
            buf
        })
        .collect();
    // let mut vk_ic = Vec::new();
    // for point in &ark_vk.gamma_abc_g1 {
    //     let mut buf = [0u8; 64];
    //     point.serialize_uncompressed(&mut buf[..]).unwrap();
    //     vk_ic.push(buf);
    // }

    // let vk_alpha_g1_converted = convert_endianness::<32, 64>(&vk_alpha_g1);
    // let vk_beta_g2_converted = convert_endianness::<64, 128>(&vk_beta_g2);
    // let vk_gamma_g2_converted = convert_endianness::<64, 128>(&vk_gamma_g2);
    // let vk_delta_g2_converted = convert_endianness::<64, 128>(&vk_delta_g2);

    println!("VK Alpha G1 (before conversion): {:?}", vk_alpha_g1);
    println!("VK Alpha G1 (after conversion): {:?}", vk_alpha_g1);

    Groth16VerifyingKey {
        nr_pubinputs: 2, // Subtract 1 for the constant term
        vk_alpha_g1: vk_alpha_g1,
        vk_beta_g2: vk_beta_g2,
        vk_gamma_g2: vk_gamma_g2,
        vk_delta_g2: vk_delta_g2,
        vk_ic: Box::leak(vk_ic.into_boxed_slice()), // Convert to 'static lifetime
    }
}

fn convert_arkworks_vk_to_solana_example2(ark_vk: &VerifyingKey<Bn254>) -> Groth16VerifyingKey<'static> {

    let mut vk_bytes = Vec::with_capacity(ark_vk.serialized_size(Compress::No));
    ark_vk.serialize_uncompressed(&mut vk_bytes).expect("");
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
    // let vk_ic: Vec<[u8; 64]> = ark_vk.gamma_abc_g1
    //     .iter()
    //     .map(|point| {
    //         let mut buf = [0u8; 64];
    //         point.serialize_uncompressed(&mut buf[..]).unwrap();
    //         // convert_endianness::<32, 64>(&buf)
    //     })
    //     .collect();
    let mut vk_ic = Vec::new();
    for point in &ark_vk.gamma_abc_g1 {
        let mut buf = [0u8; 64];
        point.serialize_uncompressed(&mut buf[..]).unwrap();
        vk_ic.push(buf);
    }

    // let vk_alpha_g1_converted = convert_endianness::<32, 64>(&vk_alpha_g1);
    // let vk_beta_g2_converted = convert_endianness::<64, 128>(&vk_beta_g2);
    // let vk_gamma_g2_converted = convert_endianness::<64, 128>(&vk_gamma_g2);
    // let vk_delta_g2_converted = convert_endianness::<64, 128>(&vk_delta_g2);

    println!("VK Alpha G1 (before conversion): {:?}", vk_alpha_g1);
    println!("VK Alpha G1 (after conversion): {:?}", vk_alpha_g1);

    Groth16VerifyingKey {
        nr_pubinputs: 2, // Subtract 1 for the constant term
        vk_alpha_g1: vk_alpha_g1,
        vk_beta_g2: vk_beta_g2,
        vk_gamma_g2: vk_gamma_g2,
        vk_delta_g2: vk_delta_g2,
        vk_ic: Box::leak(vk_ic.into_boxed_slice()), // Convert to 'static lifetime
    }
}

const NR_INPUTS: usize = 1; // Replace with your actual NR_INPUTS value
fn convert_vec_to_array_example(vec: &Vec<[u8; 32]>) -> Result<[[u8; 32]; NR_INPUTS], String> {
    if vec.len() != NR_INPUTS {
        return Err(format!("Expected {} elements, but got {}", NR_INPUTS, vec.len()));
    }

    println!("Input vector: {:?}", vec);

    // let converted_endian: Vec<[u8; 32]> = vec.into_iter()
    //     .map(|bytes| convert_endianness_32(&bytes))
    //     .collect();
    let arr: [[u8; 32]; NR_INPUTS] = [vec[0]];
    println!("Converted array: {:?}", arr);

    Ok(arr)
}

// Base field modulus `q` for BN254
// https://docs.rs/ark-bn254/latest/ark_bn254/
pub(crate) const BASE_FIELD_MODULUS_Q: [u8; 32] = [
    0x30, 0x64, 0x4E, 0x72, 0xE1, 0x31, 0xA0, 0x29, 0xB8, 0x50, 0x45, 0xB6, 0x81, 0x81, 0x58, 0x5D,
    0x97, 0x81, 0x6A, 0x91, 0x68, 0x71, 0xCA, 0x8D, 0x3C, 0x20, 0x8C, 0x16, 0xD8, 0x7C, 0xFD, 0x47,
];


pub fn negate_g1(point: &[u8; 64]) -> Result<[u8; 64], Error> {
    let x = &point[..32];
    let y = &point[32..];

    let mut y_big = BigUint::from_bytes_le(y);
    let field_modulus = BigUint::from_bytes_le(&BASE_FIELD_MODULUS_Q);

    // Negate the y-coordinate to get -g1.
    y_big = field_modulus - y_big;

    // Reconstruct the point with the negated y-coordinate
    let mut result = [0u8; 64];
    result[..32].copy_from_slice(x);
    let y_bytes = y_big.to_bytes_le();
    result[64 - y_bytes.len()..].copy_from_slice(&y_bytes);

    Ok(result)
}

#[cfg(test)]
mod test {
    use crate::verify_lite::Groth16Verifier;
    use ark_bn254::{Bn254, Fr, G1Projective};
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_serialize::{CanonicalSerialize, Compress};
    use ark_snark::SNARK;
    use rand::thread_rng;
    use solana_program::alt_bn128::compression::prelude::convert_endianness;
    use crate::byte_utils::bytes_to_field;
    use crate::example2::{convert_arkworks_vk_to_solana_example, convert_vec_to_array_example, ExampleCircuit};

    #[test]
    fn should_verify_basic_circuit_groth16() {
        if cfg!(target_endian = "big") {
            println!("Big endian");
        } else {
            println!("Little endian");
        }
        let rng = &mut thread_rng();
        // let bn = Bn254::rand(rng);
        let c = ExampleCircuit {
            some_value: Some(Fr::from(100))
        };

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c, rng).unwrap();

        let c2 = ExampleCircuit {
            some_value: Some(Fr::from(100))
        };

        let public_input = &c2.public_inputs();

        let mut proof = Groth16::<Bn254>::prove(&pk, c2, rng).unwrap();

        // Log Arkworks inputs
        println!("Arkworks Verification:");
        println!("Public Input: {:?}", Fr::from(100));
        println!("Proof A: {:?}", proof.a);
        println!("Proof B: {:?}", proof.b);
        println!("Proof C: {:?}", proof.c);

        let res = Groth16::<Bn254>::verify(&vk, &[Fr::from(100)], &proof).unwrap();
        println!("{:?}", res);
        // assert!(res);

        // let proof2 = Proof::<Bn254> {
        //     a: proof.a.neg(),
        //     b: proof.b,
        //     c: proof.c,
        // };
        let mut proof_bytes = Vec::with_capacity(proof.serialized_size(Compress::No));
        proof.serialize_uncompressed(&mut proof_bytes).expect("Error serializing proof");

        // let proof_a1: [u8; 64] = proof_bytes[0..64].try_into().unwrap();
        // let proof_b1: [u8; 128] = proof_bytes[64..192].try_into().unwrap();
        // let proof_c1: [u8; 64] = proof_bytes[192..256].try_into().unwrap();

        // let proof_a: [u8; 64] = convert_endianness::<32, 64>(proof_bytes[0..64].try_into().unwrap());
        // let proof_b: [u8; 128] = convert_endianness::<64, 128>(proof_bytes[64..192].try_into().unwrap());
        // let proof_c: [u8; 64] = convert_endianness::<32, 64>(proof_bytes[192..256].try_into().unwrap());
        // let proof_a = negate_g1(&proof_a1).unwrap();

        let proof_a: [u8; 64] = proof_bytes[0..64].try_into().unwrap();
        let proof_b: [u8; 128] =proof_bytes[64..192].try_into().unwrap();
        let proof_c: [u8; 64] = proof_bytes[192..256].try_into().unwrap();

        let mut vk_bytes = Vec::with_capacity(vk.serialized_size(Compress::No));
        vk.serialize_uncompressed(&mut vk_bytes).expect("");

        let pvk = prepare_verifying_key(&vk);
        let mut pvk_bytes = Vec::with_capacity(pvk.serialized_size(Compress::No));
        pvk.serialize_uncompressed(&mut pvk_bytes).expect("");
        // let public_inputs_fr = public_input
        //     .iter()
        //     .map(|input| bytes_to_field(input))
        //     .collect::<Result<Vec<Fr>, _>>().expect("");
        let projective: G1Projective = Groth16::<Bn254>::prepare_inputs(&pvk, &[Fr::from(100)]).expect("Error preparing inputs with public inputs and prepared verifying key");
        let mut g1_bytes = Vec::with_capacity(projective.serialized_size(Compress::No));
        projective.serialize_uncompressed(&mut g1_bytes).expect("");


        let groth_vk = convert_arkworks_vk_to_solana_example(&vk);
        let mut gamma_abc_g1_bytes = Vec::with_capacity(vk.gamma_abc_g1.serialized_size(Compress::No));
        &vk.gamma_abc_g1.serialize_uncompressed(&mut gamma_abc_g1_bytes);
        let from1 = <&[u8; 64]>::try_from(gamma_abc_g1_bytes.as_slice());
        println!("gamma_abc_g1_bytes: {:?}", from1);
        println!("vk_ic: {:?}", &groth_vk.vk_ic);

        // let g1 = g1_affine_to_bytes(&fr_to_g1(&Fr::from(100)));
        // let mut pi: Vec<[u8; 64]> = Vec::new();
        // pi.push(<[u8; 64]>::try_from(&g1[0..64]).unwrap());
        // let pip = convert_vec_to_array_example(&public_input).unwrap();
        let mut bytes = [0u8; 32];
        let _ = Fr::from(100).serialize_uncompressed(&mut bytes[..]).expect("");
        let pip = [bytes];

        // Log custom verifier inputs
        println!("\nCustom Verifier:");
        println!("Public Input1: {:?}", &public_input);
        // println!("Proof A1: {:?}", proof_a1);
        // println!("Proof B1: {:?}", proof_b1);
        // println!("Proof C1: {:?}", proof_c1);

        println!("Public Input: {:?}", pip);
        println!("Proof A: {:?}", proof_a);
        println!("Proof B: {:?}", proof_b);
        println!("Proof C: {:?}", proof_c);

        let mut verifier: Groth16Verifier<1> = Groth16Verifier::new(
            &proof_a,
            &proof_b,
            &proof_c,
            &pip,
            &groth_vk,
        ).unwrap();

        match verifier.verify() {
            Ok(true) => {
                println!("Proof verification succeeded");
                // Ok(true)
            }
            Ok(false) => {
                println!("Proof verification failed");
                // Ok(false)
            }
            Err(error) => {
                println!("Proof verification failed with error: {:?}", error);

            }
        }
    }
}