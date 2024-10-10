
#[tokio::main]
async fn main() {}

#[cfg(test)]
mod test {
    use ark_bn254::g2::G2Affine;
    use ark_bn254::{Bn254, Fr, G1Affine, G1Projective};
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
    use ark_serialize::{CanonicalSerialize, Compress};
    use ark_snark::SNARK;
    use ark_std::UniformRand;
    use borsh::{to_vec, BorshDeserialize, BorshSerialize};
    use log::{info, LevelFilter};
    use rand::thread_rng;
    use solana_client::nonblocking::rpc_client::RpcClient;
    use solana_program::alt_bn128::compression::prelude::convert_endianness;
    use solana_program::alt_bn128::prelude::{alt_bn128_pairing, ALT_BN128_PAIRING_ELEMENT_LEN};
    use solana_program::instruction::{AccountMeta, Instruction};
    use solana_program::pubkey::Pubkey;
    use solana_sdk::commitment_config::CommitmentConfig;
    use solana_sdk::signature::{Keypair, Signer};
    use solana_sdk::transaction::Transaction;
    use solana_zk_client_example::byte_utils::{convert_endianness_128, convert_endianness_64};
    use solana_zk_client_example::circuit::ExampleCircuit;
    use solana_zk_client_example::prove::{generate_proof_package, setup};
    use solana_zk_client_example::verify::verify_proof_package;
    use solana_zk_client_example::verify_lite::{build_verifier, convert_ark_public_input, convert_arkworks_verifying_key_to_solana_verifying_key, convert_arkworks_verifying_key_to_solana_verifying_key_prepared, prepare_inputs, Groth16VerifierPrepared, Groth16VerifyingKeyPrepared};
    use std::ops::{Mul, Neg};
    use std::str::FromStr;

    fn init() {
        let _ = env_logger::builder().filter_level(LevelFilter::Info).is_test(true).try_init();
    }

    #[derive(BorshSerialize, BorshDeserialize)]
    pub enum ProgramInstruction {
        VerifyProof(Groth16VerifierPrepared),
    }

    async fn request_airdrop(
        client: &RpcClient,
        pubkey: &Pubkey,
        amount: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signature = client.request_airdrop(pubkey, amount).await?;

        // Wait for the transaction to be confirmed
        loop {
            let confirmation = client.confirm_transaction(&signature).await.unwrap();
            if confirmation {
                break;
            }
        }
        Ok(())
    }
    
    #[tokio::test]
    async fn test_verify_off_chain() -> Result<(), Box<dyn std::error::Error>> {
        init();
        let circuit = ExampleCircuit {
            some_value: Some(Fr::from(100)),
        };

        let public_inputs = circuit.public_inputs();

        let (proving_key, verifying_key) = setup(true, circuit.clone());
        let (_, _, proof_package) = generate_proof_package(
            &proving_key,
            &verifying_key,
            circuit.clone(),
            &public_inputs,
        );

        let verify_groth16_proof_result = verify_proof_package(&proof_package);

        info!("{:?}", &verify_groth16_proof_result);
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_on_chain() -> Result<(), Box<dyn std::error::Error>> {
        init();
        // Connect to the Solana local
        let rpc_url = "http://127.0.0.1:8899".to_string();
        let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

        // Load or create a keypair for the payer
        let payer = Keypair::new();
        let airdrop_amount = 1_000_000_000; // 1 SOL in lamports
        match request_airdrop(&client, &payer.pubkey(), airdrop_amount).await {
            Ok(_) => info!("Airdrop successful!"),
            Err(err) => info!("Airdrop failed: {}", err),
        }

        // Define the program ID (replace with your actual program ID)
        let program_id = Pubkey::from_str("9PMYmoKdNk67c9Gumo8WWNFpGwmmHfZ4BvFR2rh1winq").unwrap(); // Replace with your actual program ID

        // Generate the proof
        let circuit = ExampleCircuit {
            some_value: Some(Fr::from(100)),
        };

        let public_inputs = circuit.public_inputs();
        let (proving_key, verifying_key) = setup(true, circuit.clone());
        let (_, _, proof_package) = generate_proof_package(
            &proving_key,
            &verifying_key,
            circuit.clone(),
            &public_inputs,
        );

        let verifier_prepared = build_verifier(proof_package);

        // Serialize and encode the proof package
        let instruction_data = to_vec(&ProgramInstruction::VerifyProof(verifier_prepared)).unwrap();
        let instruction = Instruction::new_with_bytes(
            program_id,
            instruction_data.as_slice(),
            vec![AccountMeta::new(payer.pubkey(), true)],
        );

        // Create and send the transaction
        let recent_blockhash = client.get_latest_blockhash().await.unwrap();
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );

        // Send and confirm transaction
        match client
            .send_and_confirm_transaction_with_spinner(&transaction)
            .await
        {
            Ok(signature) => info!("Transaction succeeded! Signature: {}", signature),
            Err(err) => info!("Transaction failed: {:?}", err),
        }

        Ok(())
    }

    #[test]
    fn should_verify_basic_circuit_groth16() {
        init();

        let rng = &mut thread_rng();
        let c = ExampleCircuit {
            some_value: Some(Fr::from(100)),
        };

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c, rng).unwrap();

        let c2 = ExampleCircuit {
            some_value: Some(Fr::from(100)),
        };

        let public_input = &c2.public_inputs();

        let proof = Groth16::<Bn254>::prove(&pk, c2, rng).unwrap();

        info!("Arkworks Verification:");
        info!("Public Input: {:?}", Fr::from(100));
        info!("Proof A: {:?}", proof.a);
        info!("Proof B: {:?}", proof.b);
        info!("Proof C: {:?}", proof.c);

        let res = Groth16::<Bn254>::verify(&vk, &[Fr::from(100)], &proof).unwrap();
        info!("{:?}", res);

        let proof_with_neg_a = Proof::<Bn254> {
            a: proof.a.neg(),
            b: proof.b,
            c: proof.c,
        };
        
        let mut proof_bytes = Vec::with_capacity(proof_with_neg_a.serialized_size(Compress::No));
        proof_with_neg_a
            .serialize_uncompressed(&mut proof_bytes)
            .expect("Error serializing proof");

        let proof_a: [u8; 64] =
            convert_endianness::<32, 64>(proof_bytes[0..64].try_into().unwrap());
        let proof_b: [u8; 128] =
            convert_endianness::<64, 128>(proof_bytes[64..192].try_into().unwrap());
        let proof_c: [u8; 64] =
            convert_endianness::<32, 64>(proof_bytes[192..256].try_into().unwrap());

        let mut vk_bytes = Vec::with_capacity(vk.serialized_size(Compress::No));
        vk.serialize_uncompressed(&mut vk_bytes).expect("");

        let pvk = prepare_verifying_key(&vk);
        let mut pvk_bytes = Vec::with_capacity(pvk.serialized_size(Compress::No));
        pvk.serialize_uncompressed(&mut pvk_bytes).expect("");

        let projective: G1Projective = prepare_inputs(&vk, &[Fr::from(100)])
            .expect("Error preparing inputs with public inputs and prepared verifying key");
        let mut g1_bytes = Vec::with_capacity(projective.serialized_size(Compress::No));
        projective.serialize_uncompressed(&mut g1_bytes).expect("");
        let prepared_public_input =
            convert_endianness::<32, 64>(<&[u8; 64]>::try_from(g1_bytes.as_slice()).unwrap());

        let groth_vk_prepared = convert_arkworks_verifying_key_to_solana_verifying_key_prepared(&vk);

        let public_inputs = convert_ark_public_input(&public_input).unwrap();

        // Log custom verifier inputs
        info!("Custom Verifier:");

        info!("Public Input: {:?}", public_inputs);
        info!("Proof A: {:?}", proof_a);
        info!("Proof B: {:?}", proof_b);
        info!("Proof C: {:?}", proof_c);

        let mut verifier: Groth16VerifierPrepared = Groth16VerifierPrepared::new(
            proof_a,
            proof_b,
            proof_c,
            prepared_public_input,
            groth_vk_prepared,
        )
        .unwrap();

        match verifier.verify() {
            Ok(true) => {
                info!("Proof verification succeeded");
            }
            Ok(false) => {
                info!("Proof verification failed");
            }
            Err(error) => {
                info!("Proof verification failed with error: {:?}", error);
            }
        }
    }

    #[test]
    fn test_alt_bn128_pairing_custom() {
        init();

        if cfg!(target_endian = "big") {
            info!("Big endian");
        } else {
            info!("Little endian");
        }
        
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

        info!("Input length: {}", input.len());
        info!(
            "ALT_BN128_PAIRING_ELEMENT_LEN: {}",
            ALT_BN128_PAIRING_ELEMENT_LEN
        );

        // Print the input for debugging
        info!("Original input: {:?}", input);

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

        info!("Converted input: {:?}", converted_input);

        // Call alt_bn128_pairing with the converted input
        let result = alt_bn128_pairing(&converted_input);

        match result {
            Ok(output) => {
                info!("Pairing result: {:?}", output);
                // The expected result for a valid pairing is a 32-byte array with the last byte set to 1
                let expected = vec![0; 31].into_iter().chain(vec![1]).collect::<Vec<u8>>();
                assert_eq!(
                    output, expected,
                    "The custom pairing should be valid (return true)"
                );
            }
            Err(e) => {
                panic!("alt_bn128_pairing returned an error: {:?}", e);
            }
        }

        // Verify the pairing using arkworks
        let ark_result = Bn254::pairing(p1, q2) == Bn254::pairing(p2, q1);
        assert!(ark_result, "The arkworks pairing check should return true");

        // Additional debug information
        info!("p1: {:?}", p1);
        info!("q1: {:?}", q1);
        info!("p2: {:?}", p2);
        info!("q2: {:?}", q2);
    }

    fn serialize_g1(_output: &mut Vec<u8>, point: &G1Affine) {
        let mut serialized = Vec::new();
        point.serialize_uncompressed(&mut serialized).unwrap();

        // Reverse bytes for each coordinate (32 bytes each for x and y)
        // for chunk in serialized.chunks_exact(32) {
        //     output.extend(chunk.iter().rev());
        // }
    }

    fn serialize_g2(_output: &mut Vec<u8>, point: &G2Affine) {
        let mut serialized = Vec::new();
        point.serialize_uncompressed(&mut serialized).unwrap();

        // Reverse bytes for each coordinate (64 bytes each for x and y, as they are elements of Fp2)
        // for chunk in serialized.chunks_exact(64) {
        //     output.extend(chunk.iter().rev());
        // }
    }
}
