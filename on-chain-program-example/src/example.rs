use crate::byte_utils::field_to_bytes;
use ark_bn254::Fr;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};

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
        let circuit = ExampleCircuit {
            some_value: Some(Fr::from(100)),
        };

        circuit
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

#[cfg(test)]
mod test {
    use crate::byte_utils::{convert_endianness_128, convert_endianness_64};
    use crate::example::ExampleCircuit;
    use crate::verify_lite::{convert_ark_public_input, convert_arkworks_vk_to_solana_example, prepare_inputs, Groth16Verifier, Groth16VerifierPrepared};
    use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{UniformRand};
    use ark_groth16::{prepare_verifying_key, Groth16, Proof};
    use ark_serialize::{CanonicalSerialize, Compress};
    use ark_snark::SNARK;
    use rand::thread_rng;
    use solana_program::alt_bn128::compression::prelude::convert_endianness;
    use solana_program::alt_bn128::prelude::{alt_bn128_pairing, ALT_BN128_PAIRING_ELEMENT_LEN};
    use std::ops::{Mul, Neg};

    #[test]
    fn should_verify_basic_circuit_groth16() {
        if cfg!(target_endian = "big") {
            println!("Big endian");
        } else {
            println!("Little endian");
        }
        let rng = &mut thread_rng();
        let c = ExampleCircuit {
            some_value: Some(Fr::from(100))
        };

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c, rng).unwrap();

        let c2 = ExampleCircuit {
            some_value: Some(Fr::from(100))
        };

        let public_input = &c2.public_inputs();

        let proof = Groth16::<Bn254>::prove(&pk, c2, rng).unwrap();

        println!("Arkworks Verification:");
        println!("Public Input: {:?}", Fr::from(100));
        println!("Proof A: {:?}", proof.a);
        println!("Proof B: {:?}", proof.b);
        println!("Proof C: {:?}", proof.c);

        let res = Groth16::<Bn254>::verify(&vk, &[Fr::from(100)], &proof).unwrap();
        println!("{:?}", res);

        let proof_with_neg_a = Proof::<Bn254> {
            a: proof.a.neg(),
            b: proof.b,
            c: proof.c,
        };
        let mut proof_bytes = Vec::with_capacity(proof_with_neg_a.serialized_size(Compress::No));
        proof_with_neg_a.serialize_uncompressed(&mut proof_bytes).expect("Error serializing proof");

        let proof_a: [u8; 64] = convert_endianness::<32, 64>(proof_bytes[0..64].try_into().unwrap());
        let proof_b: [u8; 128] = convert_endianness::<64, 128>(proof_bytes[64..192].try_into().unwrap());
        let proof_c: [u8; 64] = convert_endianness::<32, 64>(proof_bytes[192..256].try_into().unwrap());

        let mut vk_bytes = Vec::with_capacity(vk.serialized_size(Compress::No));
        vk.serialize_uncompressed(&mut vk_bytes).expect("");

        let pvk = prepare_verifying_key(&vk);
        let mut pvk_bytes = Vec::with_capacity(pvk.serialized_size(Compress::No));
        pvk.serialize_uncompressed(&mut pvk_bytes).expect("");

        let projective: G1Projective = prepare_inputs(&vk, &[Fr::from(100)]).expect("Error preparing inputs with public inputs and prepared verifying key");
        let mut g1_bytes = Vec::with_capacity(projective.serialized_size(Compress::No));
        projective.serialize_uncompressed(&mut g1_bytes).expect("");
        let prepared_public_input = convert_endianness::<32, 64>(<&[u8; 64]>::try_from(g1_bytes.as_slice()).unwrap());

        let groth_vk = convert_arkworks_vk_to_solana_example(&vk);

        let public_inputs = convert_ark_public_input(&public_input).unwrap();

        // Log custom verifier inputs
        println!("Custom Verifier:");

        println!("Public Input: {:?}", public_inputs);
        println!("Proof A: {:?}", proof_a);
        println!("Proof B: {:?}", proof_b);
        println!("Proof C: {:?}", proof_c);

        let mut verifier: Groth16VerifierPrepared = Groth16VerifierPrepared::new(
            &proof_a,
            &proof_b,
            &proof_c,
            prepared_public_input,
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
            }
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