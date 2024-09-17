use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_std::Zero;
use light_poseidon::{Poseidon, PoseidonHasher};
use sha2::{Digest, Sha256};
use solana_program::pubkey::Pubkey;
use crate::account_state::AccountState;
use crate::byte_utils::field_to_bytes;

// Circuit for proving knowledge of a Solana account's state changes
// The idea behind this example circuit is that the rollup that generates this proof for a batch of
// account changes, which this circuit representing the state change for the accounts in the batch
// collectively. The merkle_node_hash is a hash of the account leaf hashes (different from the Merkle root);
// The account_hash is a hash of the account addresses and data and the lamports sum is the sum of all account lamports.
#[derive(Clone)]
pub struct AccountStateCircuit {
    // hash: [u8; 32] - merkle tree hash for each account that changed state - this is private input
    pub merkle_node_hash: Option<Fr>,
    pub account_states: Vec<AccountState>,
    pub account_hash: Option<Fr>,
    pub lamports_sum: Option<Fr>,
}

impl AccountStateCircuit {

    pub fn default() -> Self {
        AccountStateCircuit {
            merkle_node_hash: None,
            account_states: vec![],
            account_hash: None,
            lamports_sum: None,
        }
    }

    pub fn new(account_states: Vec<AccountState>) -> Self {

        let mut hasher = Sha256::new();
        hasher.update(&Pubkey::new_unique().to_bytes());
        let merkle_node_hash: [u8; 32] = hasher.finalize().into();

        // Compute addresses_hash and lamports_sum
        let mut poseidon = Poseidon::<Fr>::new_circom(3).unwrap();

        let mut addresses_hash = Fr::zero();
        let mut lamports_sum = 0u64;

        for account in &account_states {
            let address_fr = Fr::from_be_bytes_mod_order(&account.address.to_bytes());
            let datum_fr = Fr::from_be_bytes_mod_order(&account.data.as_slice());
            addresses_hash = poseidon.hash(&[addresses_hash, address_fr, datum_fr]).unwrap();
            lamports_sum += account.lamports;
        }

        let circuit = AccountStateCircuit {
            merkle_node_hash: Some(Fr::from_be_bytes_mod_order(&merkle_node_hash)),
            account_states,
            account_hash: Some(addresses_hash),
            lamports_sum: Some(Fr::from(lamports_sum)),
        };

        circuit
    }

    pub fn public_inputs(&self) -> Vec<[u8; 32]> {
        let public_inputs: Vec<[u8; 32]> = vec![
            field_to_bytes(self.account_hash.unwrap()),
            field_to_bytes(self.lamports_sum.unwrap()),
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
            let address_fr = Fr::from_be_bytes_mod_order(&account.address.to_bytes());
            let datum_fr = Fr::from_be_bytes_mod_order(&account.data.as_slice());
            address_vars.push((address_fr, datum_fr));

            let lamport_fr = Fr::from(account.lamports);
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