use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::clock::Epoch;
use solana_program::pubkey::Pubkey;

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