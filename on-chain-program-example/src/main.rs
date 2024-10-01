use ark_ec::pairing::Pairing;
use ark_snark::SNARK;
use sha2::Digest;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer}
};
use solana_zk_client_example::account_state::AccountState;
use solana_zk_client_example::prove::{generate_proof, setup};
use solana_zk_client_example::verify::verify_proof_package;
use solana_zk_client_example::verify_lite::verify_groth16_proof;

//
// #[tokio::main]
// async fn main() {
//     // Connect to the Solana devnet
//     let rpc_url = "http://127.0.0.1:8899".to_string();
//     let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
//
//     // Load your Solana wallet keypair
//     let payer = Keypair::new();
//     let airdrop_amount = 1_000_000_000; // 1 SOL in lamports
//     match request_airdrop(&client, &payer.pubkey(), airdrop_amount).await {
//         Ok(_) => println!("Airdrop successful!"),
//         Err(err) => eprintln!("Airdrop failed: {}", err),
//     }
//
//     // Program ID of your deployed Solana program
//     let program_id = Pubkey::from_str("GTFvqaHy4zM5792t223NMgqrqJzXvCQA8SYLw1hqLwyF").unwrap(); // Replace with your actual program ID
//
//     // Create a sample Solana account
//     let account = AccountState {
//         address: Pubkey::new_unique(), // 1 SOL
//         lamports: 100,
//         data: vec![1, 2, 3, 4, 5, 6, 7, 8],
//         owner: payer.pubkey(),
//         executable: false,
//         rent_epoch: 0,
//     };
//
//     // Generate the proof
//     let mut hasher = Sha256::new();
//     hasher.update(account.address);
//
//     let (proof_package, vk) = generate_proof(vec![account]).await;
//
//     // Serialize and encode the proof package
//     let serialized_proof = to_vec(&proof_package).unwrap();
//
//     // Create the instruction
//     let instruction = Instruction::new_with_bytes(
//         program_id,
//         serialized_proof.as_slice(),
//         vec![AccountMeta::new(payer.pubkey(), true)],
//     );
//
//     // Create and send the transaction
//     let recent_blockhash = client.get_latest_blockhash().await.unwrap();
//     let transaction = Transaction::new_signed_with_payer(
//         &[instruction],
//         Some(&payer.pubkey()),
//         &[&payer],
//         recent_blockhash,
//     );
//
//     // Send and confirm transaction
//     match client.send_and_confirm_transaction(&transaction).await {
//         Ok(signature) => println!("Transaction succeeded! Signature: {}", signature),
//         Err(err) => println!("Transaction failed: {:?}", err),
//     }
// }

// If you want to run an example of verifying a proof off chain, comment out the main function above
// and uncomment this and run. You don't need to deploy any Solana program.
#[tokio::main]
async fn main() {
    let payer = Keypair::new();

    let account = AccountState {
        address: Pubkey::new_unique(), // 1 SOL
        lamports: 1,
        data: vec![0],
        owner: payer.pubkey(),
        executable: false,
        rent_epoch: 0,
    };

    // Generate the proof

    let (proving_key, verifying_key) = setup(true);
    let (proof_package_lite, proof_package_prepared, proof_package) = generate_proof(&proving_key, &verifying_key, vec![account]);
    let off_chain_verify = verify_proof_package(&proof_package);
    println!("off chain result: {:?}", off_chain_verify);

    let verify_groth16_proof_result = verify_groth16_proof(&proof_package_lite).expect("TODO: panic message");

    println!("{:?}", &verify_groth16_proof_result);
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