use ark_bn254::{Bn254, Fq2, Fr, G1Affine};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_snark::SNARK;
use ark_std::{rand::thread_rng, UniformRand};
use borsh::{to_vec, BorshDeserialize, BorshSerialize};
use light_poseidon::{Poseidon, PoseidonHasher};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::str::FromStr;


#[derive(BorshSerialize, BorshDeserialize)]
struct SerializableProof {
    a: [u8; 64],
    b: [[u8; 64]; 2],
    c: [u8; 64],
}

#[derive(BorshSerialize, BorshDeserialize)]
struct ProofPackage {
    proof: Vec<u8>,
    public_inputs: Vec<[u8; 32]>,
}

#[derive(Clone)]
pub struct SolanaAccount {
    pub balance: u64,
    pub data: Vec<u8>,
    pub owner: [u8; 32],
}

// Circuit for proving knowledge of a Solana account's private key and properties
#[derive(Clone)]
pub struct SolanaAccountCircuit {
    pub private_key: Option<Fr>,
    pub public_key: Option<Fr>,
    pub balance: Option<u64>,
    pub data_hash: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SolanaAccountCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate private key as a private input
        let private_key = cs.new_witness_variable(|| self.private_key.ok_or(SynthesisError::AssignmentMissing))?;

        // Allocate public key as a public input
        let public_key = cs.new_input_variable(|| self.public_key.ok_or(SynthesisError::AssignmentMissing))?;

        // Constrain the public key to be the scalar multiplication of the private key with the generator point
        // Note: This is a simplified representation. In practice, you'd need to implement the full Ed25519 derivation.
        cs.enforce_constraint(
            lc!() + private_key,
            lc!() + (Fr::from(8u64), Variable::One),
            lc!() + public_key,
        )?;

        // Allocate balance as a public input
        let balance = cs.new_input_variable(|| self.balance.map(Fr::from).ok_or(SynthesisError::AssignmentMissing))?;

        // Ensure balance is non-negative (always true for u64, but demonstrated for completeness)
        cs.enforce_constraint(
            lc!() + balance,
            lc!() + Variable::One,
            lc!() + balance,
        )?;

        // Allocate data hash as a public input
        let data_hash = cs.new_input_variable(|| self.data_hash.ok_or(SynthesisError::AssignmentMissing))?;

        // In a real implementation, you might add more constraints here, such as:
        // - Proving that the balance is within a certain range
        // - Proving properties about the account's data

        Ok(())
    }
}

#[tokio::main]
async fn main2() {
    // Connect to the Solana devnet
    let rpc_url = "http://127.0.0.1:8899".to_string();
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Load your Solana wallet keypair
    let payer = Keypair::new();
    let airdrop_amount = 1_000_000_000; // 1 SOL in lamports
    match request_airdrop(&client, &payer.pubkey(), airdrop_amount).await {
        Ok(_) => println!("Airdrop successful!"),
        Err(err) => eprintln!("Airdrop failed: {}", err),
    }

    // Program ID of your deployed Solana program
    let program_id = Pubkey::from_str("GuEomGmECeM5T13vkgUvxwvNL5eSjQsvmo5RRQV73q6L").unwrap(); // Replace with your actual program ID

    // Create a sample Solana account
    let account = SolanaAccount {
        balance: 1000000000, // 1 SOL
        data: vec![1, 2, 3, 4, 5],
        owner: payer.pubkey().to_bytes(),
    };

    // Generate a random private key (in a real scenario, this would be your actual private key)
    let private_key = Fr::rand(&mut thread_rng());

    // Generate the proof
    let (proof_package, vk) = generate_proof(&account, private_key);

    // Serialize and encode the proof package
    let serialized_proof = to_vec(&proof_package).unwrap();

    // Create the instruction
    let instruction = Instruction::new_with_bytes(
        program_id,
        serialized_proof.as_slice(),
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
    match client.send_and_confirm_transaction(&transaction).await {
        Ok(signature) => println!("Transaction succeeded! Signature: {}", signature),
        Err(err) => println!("Transaction failed: {:?}", err),
    }
}

async fn request_airdrop(client: &RpcClient, pubkey: &Pubkey, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
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

fn main() {
    let payer = Keypair::new();

    let account = SolanaAccount {
        balance: 1000000000, // 1 SOL
        data: vec![1, 2, 3, 4, 5],
        owner: payer.pubkey().to_bytes(),
    };

    // Generate a random private key (in a real scenario, this would be your actual private key)
    let private_key = Fr::rand(&mut thread_rng());

    // Generate the proof
    let (proof_package, vk) = generate_proof(&account, private_key);

    let proof_package_ser = to_vec(&proof_package).expect("TODO: panic message");
    let (proof_package_deser, pi_deser) = deserialize_proof_package(&proof_package_ser).expect("TODO: panic message");
    let chain = verify_off_chain(&proof_package_deser, &pi_deser, &vk);
    println!("{}", &chain);

}

fn generate_proof(account: &SolanaAccount, private_key: Fr) -> (ProofPackage, VerifyingKey<Bn254>) {
    let rng = &mut thread_rng();

    // Compute public key (simplified, not actual Ed25519)
    let public_key = private_key * Fr::from(8u64);

    // Compute data hash using Poseido
    let mut poseidon = Poseidon::<Fr>::new_circom(account.data.len()).unwrap();
    let data_hash = poseidon.hash(&account.data.iter().map(|&b| Fr::from(b as u64)).collect::<Vec<_>>()).expect("");

    // Set up the circuit
    let circuit = SolanaAccountCircuit {
        private_key: Some(private_key),
        public_key: Some(public_key),
        balance: Some(account.balance),
        data_hash: Some(data_hash),
    };

    // Generate parameters
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();

    // Create a proof
    let proof = Groth16::<Bn254>::prove(&pk,
                                        circuit,
                                        rng,
    ).unwrap();


    let mut proof_bytes = Vec::new();
    proof.serialize_uncompressed(&mut proof_bytes).expect("TODO: panic message");

    // Convert the proof to our serializable format
    // let serializable_proof = SerializableProof {
    //     a: g1_to_bytes(proof.a),
    //     b: [g2_to_bytes(proof.b.x), g2_to_bytes(proof.b.y)],
    //     c: g1_to_bytes(proof.c),
    // };

    let public_inputs: Vec<[u8; 32]> = vec![
        field_to_bytes(public_key),
        field_to_bytes(Fr::from(account.balance)),
        field_to_bytes(data_hash),
    ];

    (ProofPackage {
        proof: proof_bytes.clone(),
        public_inputs,
    }, vk)
}

// Helper function to convert G1Affine to bytes
fn g1_to_bytes(point: G1Affine) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&field_to_bytes(point.x));
    bytes[32..].copy_from_slice(&field_to_bytes(point.y));
    bytes
}

// Helper function to convert G2Affine to bytes
fn g2_to_bytes(point: Fq2) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&field_to_bytes(point.c0));
    bytes[32..].copy_from_slice(&field_to_bytes(point.c1));
    bytes
}

// Helper function to convert a field element to bytes
fn field_to_bytes<F: PrimeField>(field: F) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    field.serialize_uncompressed(&mut bytes[..]).unwrap();
    bytes
}


fn deserialize_proof_package(serialized_data: &[u8]) -> Result<(Proof<Bn254>, Vec<Fr>), Box<dyn std::error::Error>> {
    // Deserialize the ProofPackage
    let proof_package = ProofPackage::try_from_slice(serialized_data)?;
    let proof = Proof::<Bn254>::deserialize_uncompressed_unchecked(&proof_package.proof[..]).expect("TODO: panic message");

    // Deserialize the Proof
    // let a = G1Affine::new(
    //     bytes_to_field(&proof_package.proof.a[0..32])?,
    //     bytes_to_field(&proof_package.proof.a[32..64])?,
    // );
    //
    // let b = G2Affine::new(
    //         bytes_to_g2_from_slice(&proof_package.proof.b[0][0..64])?,
    //         bytes_to_g2_from_slice(&proof_package.proof.b[1][0..64])?
    // );
    //
    // let c = G1Affine::new(
    //     bytes_to_field(&proof_package.proof.c[0..32])?,
    //     bytes_to_field(&proof_package.proof.c[32..64])?,
    // );
    //
    // let proof = Proof { a, b, c };

    // Deserialize public inputs
    let public_inputs = proof_package.public_inputs
        .iter()
        .map(|input| bytes_to_field(input))
        .collect::<Result<Vec<Fr>, _>>()?;

    Ok((proof, public_inputs))
}


fn bytes_to_g2_from_slice(slice: &[u8]) -> Result<Fq2, SerializationError> {
    if slice.len() != 64 {
        return Err(SerializationError::InvalidData);
    }
    let array: [u8; 64] = slice.try_into().map_err(|_| SerializationError::InvalidData)?;
    bytes_to_g2(&array)
}

fn bytes_to_g2(bytes: &[u8; 64]) -> Result<Fq2, SerializationError> {
    let c0 = bytes_to_field(&bytes[..32])?;
    let c1 = bytes_to_field(&bytes[32..64])?;

    Ok(Fq2::new(c0, c1))
}

// Helper function to convert bytes to a field element
fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> Result<F, SerializationError> {
    F::deserialize_uncompressed(bytes)
}

fn verify_off_chain(
    proof: &Proof<Bn254>,
    public_inputs: &[Fr],
    vk: &VerifyingKey<Bn254>,
) -> bool {
    let pvk = prepare_verifying_key(vk);
    Groth16::<Bn254>::verify_proof(&pvk, proof, public_inputs).unwrap()
}