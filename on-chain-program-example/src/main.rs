use std::fs;
use std::fs::File;
use std::io::Write;
use ark_bn254::{Bn254, Fq2, Fr, G1Affine};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_snark::SNARK;
use ark_std::{rand::thread_rng, UniformRand};
use borsh::{to_vec, BorshDeserialize, BorshSerialize};
use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonHasher};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::str::FromStr;
use sha2::{Digest, Sha256};
use solana_sdk::clock::Epoch;
use solana_sdk::signer::EncodableKey;

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

/// Represents the state of an account.
#[derive(Debug, BorshDeserialize, BorshSerialize, Clone)]
pub struct AccountState {
    pub address: Pubkey,
    /// lamports in the account
    pub lamports: u64,
    /// data held in this account
    pub data: Vec<u8>,
    /// the program that owns this account. If executable, the program that loads this account.
    pub owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    pub executable: bool,
    /// the epoch at which this account will next owe rent
    pub rent_epoch: Epoch,
}

// Circuit for proving knowledge of a Solana account's private key and properties
#[derive(Clone)]
pub struct AccountStateCircuit {
    // hash: [u8; 32] - merkle tree hash for each account that changed state - this is private input
    pub merkle_node_hash: Option<Fr>,
    pub account_states: Vec<AccountState>,
    pub account_hash: Option<Fr>,
    pub lamports_sum: Option<u64>,
    // pub datum_hash: Option<Fr>,
}

impl AccountStateCircuit {

    pub fn new_2(account_states: Vec<AccountState>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&Pubkey::new_unique().to_bytes());
        let merkle_node_hash: [u8; 32] = hasher.finalize().into();

        // Compute addresses_hash and lamports_sum
        let mut poseidon = Poseidon::<Fr>::new_circom(3).unwrap();

        let mut addresses_hash = Fr::zero();
        let mut lamports_sum = 0u64;

        for account in &account_states {
            let address_fr = Fr::from_le_bytes_mod_order(&account.address.to_bytes());
            let datum_fr = Fr::from_le_bytes_mod_order(&account.data.as_slice());
            addresses_hash = poseidon.hash(&[addresses_hash, address_fr, datum_fr]).unwrap();
            lamports_sum += account.lamports;
        }

        // let merkle_node_hash = /* compute your merkle node hash */;

        let circuit = AccountStateCircuit {
            merkle_node_hash: Some(Fr::from_le_bytes_mod_order(&merkle_node_hash)),
            account_states,
            account_hash: Some(addresses_hash),
            lamports_sum: Some(lamports_sum),
            // datum_hash: Some(datum_hash),
        };

        circuit
    }
    // pub fn new(merkle_node_hashes: Vec<[u8; 32]>, account_states: Vec<AccountState> ) -> Self {
    //      let merkle_node_hash = Self::hash_vec_u8_32(&merkle_node_hashes);
    //
    //     // let datum_size = account_states.iter().map(|account| &account.data).map(|data| data.len()).sum();
    //     // let mut poseidon = PoseidonHasher::<Bn254>::default();
    //     let address_hash = Self::hash_vec_u8_32(&account_states.iter().map(|account| account.address.to_bytes()).collect::<Vec<_>>());
    //     // let fp = Fr::from_le_bytes_mod_order(&ah);
    //     // let ah  = poseidon.hash_bytes_le(ah);
    //     // let addresses_hash = poseidon.hash(&account_states.iter().map(|account| Fr::from_le_bytes_mod_order(&account.address.to_bytes())).collect::<Vec<_>>()).unwrap();
    //     let lamports_sum = account_states.iter().map(|account| account.lamports).sum();
    //     // let mut poseidon = Poseidon::<Fr>::new_circom(account_states.len()).unwrap();
    //     // let datum_hash = poseidon.hash(&account_states.iter().flat_map(|account| account.data.iter()).map(|&b| Fr::from(b as u64)).collect::<Vec<_>>()).unwrap();
    //     // let mut poseidon = Poseidon::<Fr>::new_circom(account_states[0].data.len()).unwrap();
    //     // let datum_hash = poseidon.hash(&account_states[0].data.iter().map(|&b| Fr::from(b as u64)).collect::<Vec<_>>()).expect("");
    //     // let rng = &mut thread_rng();
    //
    //
    //     // Pubkey::new_unique();
    //     // Compute public key (simplified, not actual Ed25519)
    //     // let public_key = private_key * Fr::from(8u64);
    //
    //     // Compute data hash using Poseido
    //     // let data_hash = poseidon.hash(&account.data.iter().map(|&b| Fr::from(b as u64)).collect::<Vec<_>>()).expect("");
    //     Self {
    //         merkle_node_hash: Some(Fr::from_le_bytes_mod_order(&merkle_node_hash)),
    //         addresses_hash: Some(Fr::from_le_bytes_mod_order(&address_hash)),
    //         lamports_sum: Some(lamports_sum),
    //         // datum_hash: Some(datum_hash),
    //     }
    // }

    pub fn public_inputs(&self) -> Vec<[u8; 32]> {
        let public_inputs: Vec<[u8; 32]> = vec![
            field_to_bytes(self.account_hash.unwrap()),
            field_to_bytes(Fr::from(self.lamports_sum.unwrap())),
            // field_to_bytes(self.datum_hash.unwrap()),
        ];

        public_inputs
    }

    fn hash_vec_u8_32(input: &Vec<[u8; 32]>) -> [u8; 32] {
        let mut hasher = Sha256::new();

        for array in input {
            hasher.update(array);
        }

        hasher.finalize().into()
    }
}

impl ConstraintSynthesizer<Fr> for AccountStateCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate merkle_node_hash as a private input
        let merkle_node_hash = cs.new_witness_variable(|| {
            self.merkle_node_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Initialize Poseidon hasher
        let mut poseidon = Poseidon::<Fr>::new_circom(3).unwrap();

        // Allocate variables for each account state
        let mut address_vars = Vec::new();
        let mut lamport_vars = Vec::new();
        for account in &self.account_states {
            let address_fr = Fr::from_le_bytes_mod_order(&account.address.to_bytes());
            let datum_fr = Fr::from_le_bytes_mod_order(&account.data.as_slice());
            let address_var = cs.new_witness_variable(|| Ok(address_fr))?;
            address_vars.push((address_fr, datum_fr));

            let lamport_fr = Fr::from(account.lamports);
            let lamport_var = cs.new_witness_variable(|| Ok(lamport_fr))?;
            lamport_vars.push(lamport_fr);
        }

        // Compute addresses_hash
        let mut current_hash = Fr::zero();
        for &address_var in &address_vars {
            current_hash = poseidon.hash(&[current_hash, address_var.0, address_var.1]).unwrap();
        }
        let computed_addresses_hash_var = cs.new_witness_variable(|| Ok(current_hash))?;

        // Compute lamports_sum
        let mut lamports_sum = Fr::zero();
        for &lamport_var in &lamport_vars {
            lamports_sum += lamport_var;
        }
        let computed_lamports_sum_var = cs.new_witness_variable(|| Ok(lamports_sum))?;

        // Allocate public inputs
        let addresses_hash = cs.new_input_variable(|| {
            self.account_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let lamports_sum_public = cs.new_input_variable(|| {
            self.lamports_sum.map(Fr::from).ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint: Ensure computed addresses_hash matches the provided addresses_hash
        cs.enforce_constraint(
            lc!() + computed_addresses_hash_var,
            lc!() + Variable::One,
            lc!() + addresses_hash,
        )?;

        // Constraint: Ensure computed lamports_sum matches the provided lamports_sum
        cs.enforce_constraint(
            lc!() + computed_lamports_sum_var,
            lc!() + Variable::One,
            lc!() + lamports_sum_public,
        )?;

        // Add a constraint linking merkle_node_hash and addresses_hash
        // This is a placeholder constraint; replace with actual relationship if known
        cs.enforce_constraint(
            lc!() + merkle_node_hash,
            lc!() + Variable::One,
            lc!() + merkle_node_hash,
        )?;

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
    let program_id = Pubkey::from_str("AMTxH3qhF3ovFfVodUv5YFiCDtMb7W8W3MYctFGFZHcB").unwrap(); // Replace with your actual program ID

    // Create a sample Solana account
    let account = AccountState {
        address: Pubkey::new_unique(), // 1 SOL
        lamports: 100,
        data: vec![1, 2, 3, 4, 5, 6, 7, 8],
        owner: payer.pubkey(),
        executable: false,
        rent_epoch: 0,
    };

    let keypair = Keypair::from_bytes(&[102, 65, 240, 4, 165, 188, 24, 208, 195, 210, 69, 79, 177, 151, 41, 61, 187, 215, 169, 103, 232, 151, 100, 174, 111, 71, 230, 69, 134, 83, 190, 138, 56, 251, 106, 56, 230, 253, 235, 109, 233, 254, 126, 1, 142, 210, 202, 20, 156, 148, 127, 46, 232, 170, 84, 84, 35, 53, 93, 159, 205, 0, 128, 77]).expect("");
    // Generate a random private key (in a real scenario, this would be your actual private key)
    let private_key = Fr::from_le_bytes_mod_order(&keypair.secret().to_bytes());// Fr::rand(&mut thread_rng());

    // Generate the proof
    let mut hasher = Sha256::new();
    hasher.update(account.address);

    let (proof_package, vk) = generate_proof(vec![hasher.finalize().into()], vec![account], private_key);
    let mut file = File::create("vk.bin").unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes).expect("");
    file.write_all(&vk_bytes).expect("TODO: panic message");

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

    let account = AccountState {
        address: Pubkey::new_unique(), // 1 SOL
        lamports: 100,
        data: vec![1, 2, 3, 4, 5, 6, 7, 8],
        owner: payer.pubkey(),
        executable: false,
        rent_epoch: 0,
    };

    // Generate a random private key (in a real scenario, this would be your actual private key)
    let private_key = Fr::rand(&mut thread_rng());

    // Generate the proof
    // let (proof_package, vk) = generate_proof(&account, private_key);
    let keypair = Keypair::new();
    // Generate a random private key (in a real scenario, this would be your actual private key)
    let private_key = Fr::from_le_bytes_mod_order(&keypair.secret().to_bytes());// Fr::rand(&mut thread_rng());

    // Generate the proof
    let mut hasher = Sha256::new();
    hasher.update(account.address);
    let (proof_package, vk) = generate_proof(vec![hasher.finalize().into()],vec![account], private_key);

    let proof_package_ser = to_vec(&proof_package).expect("TODO: panic message");
    let (proof_package_deser, pi_deser) = deserialize_proof_package(&proof_package_ser).expect("TODO: panic message");
    let is_valid = verify_off_chain(&proof_package_deser, &pi_deser, &vk);
    println!("{}", &is_valid);
}

fn generate_proof(merkle_node_hashes: Vec<[u8; 32]>, accounts: Vec<AccountState>, private_key: Fr) -> (ProofPackage, VerifyingKey<Bn254>) {
    let account_state_circuit = AccountStateCircuit::new_2( accounts);
    let rng = &mut thread_rng();
    //
    // Pubkey::new_unique();
    // // Compute public key (simplified, not actual Ed25519)
    // let public_key = private_key * Fr::from(8u64);
    //
    // // Compute data hash using Poseido
    // let mut poseidon = Poseidon::<Fr>::new_circom(account.data.len()).unwrap();
    // let data_hash = poseidon.hash(&account.data.iter().map(|&b| Fr::from(b as u64)).collect::<Vec<_>>()).expect("");
    //
    // // Set up the circuit
    // let circuit = AccountStateCircuit {
    //     address: Some(account.address),
    //     owner: Some(public_key),
    //     lamports: Some(account.lamports),
    //     data_hash: Some(data_hash),
    // };


    // let mut pk_from_file = fs::read("/home/waggins/projects/solana-zk-proof-example/on-chain-program-example/pk.bin").expect("TODO: panic message");
    // let proving_key = ProvingKey::<Bn254>::deserialize_uncompressed(&pk_from_file.clone()[..]).expect("TODO: panic message");
    //
    // let vk_from_file = fs::read("/home/waggins/projects/solana-zk-proof-example/on-chain-program-example/vk.bin").expect("TODO: panic message");
    // let verifying_key = VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(&vk_from_file[..]).expect("TODO: panic message");
    // Generate parameters
    let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(account_state_circuit.clone(), rng).unwrap();
    // let mut file = File::create("vk.bin").unwrap();
    // let mut vk_bytes = Vec::new();
    // vk.serialize_uncompressed(&mut vk_bytes).expect("");
    // file.write(&vk_bytes).expect("TODO: panic message");
    //
    // let mut pk_file = File::create("pk.bin").unwrap();
    // let mut pk_bytes = Vec::new();
    // vk.serialize_uncompressed(&mut pk_bytes).expect("");
    // pk_file.write(&pk_bytes).expect("TODO: panic message");

    let public_inputs = account_state_circuit.public_inputs();

    // Create a proof
    let proof = Groth16::<Bn254>::prove(&proving_key,
                                        account_state_circuit,
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
    //
    // let public_inputs: Vec<[u8; 32]> = vec![
    //     field_to_bytes(public_key),
    //     field_to_bytes(Fr::from(account.balance)),
    //     field_to_bytes(data_hash),
    // ];


    (ProofPackage {
        proof: proof_bytes.clone(),
        public_inputs,
    }, verifying_key)
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