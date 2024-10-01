use crate::byte_utils::{convert_endianness_32, field_to_bytes};
use crate::verify_lite::Groth16VerifyingKey;
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_serialize::CanonicalSerialize;
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
fn convert_vec_to_array_example(vec: &Vec<[u8; 32]>) -> Result<[[u8; 32]; NR_INPUTS], String> {
    if vec.len() != NR_INPUTS {
        return Err(format!("Expected {} elements, but got {}", NR_INPUTS, vec.len()));
    }

    println!("Input vector: {:?}", vec);
    // ... (existing code)
    let converted_endian: Vec<[u8; 32]> = vec.iter().map(|bytes| convert_endianness_32(bytes)).collect();
    let arr: [[u8; 32]; NR_INPUTS] = converted_endian.try_into()
        .map_err(|_| "Conversion failed")?;
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

    let mut y_big = BigUint::from_bytes_be(y);
    let field_modulus = BigUint::from_bytes_be(&BASE_FIELD_MODULUS_Q);

    // Negate the y-coordinate to get -g1.
    y_big = field_modulus - y_big;

    // Reconstruct the point with the negated y-coordinate
    let mut result = [0u8; 64];
    result[..32].copy_from_slice(x);
    let y_bytes = y_big.to_bytes_be();
    result[64 - y_bytes.len()..].copy_from_slice(&y_bytes);

    Ok(result)
}

#[cfg(test)]
mod test {
    use std::ops::{AddAssign, Mul, Neg};
    use crate::example::{convert_arkworks_vk_to_solana_example, convert_vec_to_array_example, ExampleCircuit};
    use crate::verify_lite::{verify_proof, Groth16Verifier};
    use ark_bn254::{Bn254, Fr, G1Projective, G1Affine, G2Affine};
    use ark_bn254::g1::Config;
    use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
    use ark_serialize::{CanonicalSerialize, Compress};
    use ark_snark::SNARK;
    use rand::thread_rng;
    use solana_program::alt_bn128::compression::prelude::convert_endianness;
    use solana_program::alt_bn128::prelude::{alt_bn128_pairing, ALT_BN128_PAIRING_ELEMENT_LEN};
    use crate::byte_utils::{bytes_to_field, convert_endianness_128, convert_endianness_64};
    use crate::prove::ProofPackagePrepared;
    // use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ec::pairing::Pairing;
    use ark_ec::short_weierstrass::Projective;
    use ark_ff::{BigInteger, PrimeField, UniformRand};
    use ark_relations::r1cs::SynthesisError;

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

        let proof2 = Proof::<Bn254> {
            a: proof.a.neg(),
            b: proof.b,
            c: proof.c,
        };
        let mut proof_bytes = Vec::with_capacity(proof2.serialized_size(Compress::No));
        proof2.serialize_uncompressed(&mut proof_bytes).expect("Error serializing proof");

        let proof_a1: [u8; 64] = proof_bytes[0..64].try_into().unwrap();
        let proof_b1: [u8; 128] = proof_bytes[64..192].try_into().unwrap();
        let proof_c1: [u8; 64] = proof_bytes[192..256].try_into().unwrap();

        let proof_a: [u8; 64] = convert_endianness::<32, 64>(proof_bytes[0..64].try_into().unwrap());
        let proof_b: [u8; 128] = convert_endianness::<64, 128>(proof_bytes[64..192].try_into().unwrap());
        let proof_c: [u8; 64] = convert_endianness::<32, 64>(proof_bytes[192..256].try_into().unwrap());
        // let proof_a = negate_g1(&proof_a1).unwrap();

        // let proof_a: [u8; 64] = proof_package.proof[0..64].try_into().unwrap();
        // let proof_b: [u8; 128] = proof_package.proof[64..192].try_into().unwrap();
        // let proof_c: [u8; 64] = proof_package.proof[192..256].try_into().unwrap();

        let mut vk_bytes = Vec::with_capacity(vk.serialized_size(Compress::No));
        vk.serialize_uncompressed(&mut vk_bytes).expect("");

        let pvk = prepare_verifying_key(&vk);
        let mut pvk_bytes = Vec::with_capacity(pvk.serialized_size(Compress::No));
        pvk.serialize_uncompressed(&mut pvk_bytes).expect("");
        // let public_inputs_fr = public_inputs
        //     .iter()
        //     .map(|input| bytes_to_field(input))
        //     .collect::<Result<Vec<Fr>, _>>().expect("");
        let projective: G1Projective = Groth16::<Bn254>::prepare_inputs(&pvk, &[Fr::from(100)]).expect("Error preparing inputs with public inputs and prepared verifying key");
        let mut g1_bytes = Vec::with_capacity(projective.serialized_size(Compress::No));
        projective.serialize_uncompressed(&mut g1_bytes).expect("");
        let g1_endian = convert_endianness::<32, 64>(<&[u8; 64]>::try_from(g1_bytes.as_slice()).unwrap());

        // let ppp = ProofPackagePrepared {
        //     proof: proof_bytes,
        //     public_inputs: g1_bytes,
        //     verifying_key: pvk_bytes,
        // };
        // let x = verify_proof(ppp).expect("TODO: panic message");
        // println!("other verify: {}", x);


        let groth_vk = convert_arkworks_vk_to_solana_example(&vk);
        // let mut gamma_abc_g1_bytes = Vec::with_capacity(vk.gamma_abc_g1.serialized_size(Compress::No));
        // &vk.gamma_abc_g1.serialize_uncompressed(&mut gamma_abc_g1_bytes);
        // let from1 = <&[u8; 64]>::try_from(gamma_abc_g1_bytes.as_slice());
        // println!("gamma_abc_g1_bytes: {:?}", from1);
        println!("vk_ic: {:?}", &groth_vk.vk_ic);

        // let g1 = g1_affine_to_bytes(&fr_to_g1(&Fr::from(100)));
        // let mut pi: Vec<[u8; 64]> = Vec::new();
        // pi.push(<[u8; 64]>::try_from(&g1[0..64]).unwrap());
        let pip = convert_vec_to_array_example(&public_input).unwrap();
        // let mut bytes = [0u8; 32];
        // let _ = Fr::from(100).serialize_uncompressed(&mut bytes[..]).expect("");
        // let pip = [bytes];

        // Log custom verifier inputs
        println!("\nCustom Verifier:");
        println!("Public Input1: {:?}", &public_input);
        println!("Proof A1: {:?}", proof_a1);
        println!("Proof B1: {:?}", proof_b1);
        println!("Proof C1: {:?}", proof_c1);

        println!("Public Input: {:?}", pip);
        println!("Proof A: {:?}", proof_a);
        println!("Proof B: {:?}", proof_b);
        println!("Proof C: {:?}", proof_c);

        let mut verifier: Groth16Verifier<1> = Groth16Verifier::new_prepared(
            &proof_a,
            &proof_b,
            &proof_c,
            &pip,
            g1_endian,
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

    pub fn prepare_inputs(
        vk: &VerifyingKey<Bn254>,
        public_inputs: &[Fr],
    ) -> Result<Projective<Config>, SynthesisError> {
        if (public_inputs.len() + 1) != vk.gamma_abc_g1.len() {
            return Err(SynthesisError::MalformedVerifyingKey);
        }

        let mut g_ic = vk.gamma_abc_g1[0].into_group();
        for (i, b) in public_inputs.iter().zip(vk.gamma_abc_g1.iter().skip(1)) {
            g_ic.add_assign(&b.mul_bigint(i.into_bigint()));
        }

        Ok(g_ic)
    }
    
    #[test]
    fn test_alt_bn128_pairing_true() {
        // This input represents a valid pairing that should return true
        let input = hex::decode("1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa").unwrap();

        let result = alt_bn128_pairing(&input).unwrap();

        // The expected result for a valid pairing is a 32-byte array with the last byte set to 1
        let expected = vec![0; 31].into_iter().chain(vec![1]).collect::<Vec<u8>>();

        assert_eq!(result, expected, "The pairing should be valid (return true)");
    }

    #[test]
    fn test_alt_bn128_pairing_custom() {
        // Generate random points
        let mut rng = ark_std::test_rng();

        // Generate a random scalar
        let s = Fr::rand(&mut rng);

        // Generate points on G1 and G2
        let p1 = G1Affine::generator();
        let q1 = G2Affine::generator();

        // Create the second pair of points
        let p2 = p1.mul(s).into_affine();
        let q2 = q1.mul(s).into_affine();

        // Prepare the input for alt_bn128_pairing
        let mut input = Vec::new();

        // Serialize points
        serialize_g1(&mut input, &p1);
        serialize_g2(&mut input, &q1);
        serialize_g1(&mut input, &p2);
        serialize_g2(&mut input, &q2);

        println!("Input length: {}", input.len());
        println!("ALT_BN128_PAIRING_ELEMENT_LEN: {}", ALT_BN128_PAIRING_ELEMENT_LEN);

        // Print the input for debugging
        println!("Original input: {:?}", input);

        // Apply endianness conversion to input and print
        let converted_input: Vec<u8> = input
            .chunks(ALT_BN128_PAIRING_ELEMENT_LEN)
            .flat_map(|chunk| {
                let mut converted = Vec::new();
                converted.extend_from_slice(&convert_endianness_64(&chunk[..64]));
                converted.extend_from_slice(&convert_endianness_128(&chunk[64..]));
                converted
            })
            .collect();

        println!("Converted input: {:?}", converted_input);

        // Call alt_bn128_pairing with the converted input
        let result = alt_bn128_pairing(&converted_input);

        match result {
            Ok(output) => {
                println!("Pairing result: {:?}", output);
                // The expected result for a valid pairing is a 32-byte array with the last byte set to 1
                let expected = vec![0; 31].into_iter().chain(vec![1]).collect::<Vec<u8>>();
                assert_eq!(output, expected, "The custom pairing should be valid (return true)");
            },
            Err(e) => {
                panic!("alt_bn128_pairing returned an error: {:?}", e);
            }
        }

        // Verify the pairing using arkworks
        let ark_result = Bn254::pairing(p1, q2) == Bn254::pairing(p2, q1);
        assert!(ark_result, "The arkworks pairing check should return true");

        // Additional debug information
        println!("p1: {:?}", p1);
        println!("q1: {:?}", q1);
        println!("p2: {:?}", p2);
        println!("q2: {:?}", q2);
    }

    fn serialize_g1(output: &mut Vec<u8>, point: &G1Affine) {
        let mut serialized = Vec::new();
        point.serialize_uncompressed(&mut serialized).unwrap();

        // Reverse bytes for each coordinate (32 bytes each for x and y)
        // for chunk in serialized.chunks_exact(32) {
        //     output.extend(chunk.iter().rev());
        // }
    }

    fn serialize_g2(output: &mut Vec<u8>, point: &G2Affine) {
        let mut serialized = Vec::new();
        point.serialize_uncompressed(&mut serialized).unwrap();

        // Reverse bytes for each coordinate (64 bytes each for x and y, as they are elements of Fp2)
        // for chunk in serialized.chunks_exact(64) {
        //     output.extend(chunk.iter().rev());
        // }
    }
}