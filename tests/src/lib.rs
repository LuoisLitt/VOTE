//! Test-suite for testing the Vote smart contract
//!
//! Uses piecrust VM for direct contract testing.
//! Note: Functions requiring sender authentication need the full
//! network session with transactions (see EMT test framework).

use std::sync::LazyLock;

use dusk_core::abi::ContractId;
use dusk_core::signatures::bls::{
    PublicKey as AccountPublicKey, SecretKey as AccountSecretKey,
};
use piecrust::{ContractData, Session, SessionData, VM};

use rand::rngs::StdRng;
use rand::SeedableRng;

// Re-export types from the vote contract
pub use vote_contract::{Account, Proposal};

// Contract bytecode - include at compile time
const VOTE_BYTECODE: &[u8] = include_bytes!(
    "../../target/wasm64-unknown-unknown/release/vote_contract.wasm"
);
const TOKEN_BYTECODE: &[u8] = include_bytes!(
    "../../target/wasm64-unknown-unknown/release/mock_token.wasm"
);

pub const VOTE_CONTRACT_ID: ContractId = ContractId::from_bytes([1; 32]);
pub const TOKEN_CONTRACT_ID: ContractId = ContractId::from_bytes([2; 32]);

const DEPLOYER: [u8; 64] = [0u8; 64];
const GAS_LIMIT: u64 = 0x10_000_000;

/// Test session for vote contract testing
pub struct TestSession {
    session: Session,
}

impl TestSession {
    // Test account keys (deterministic from seeds)
    pub const SK_ADMIN: LazyLock<AccountSecretKey> = LazyLock::new(|| {
        let mut rng = StdRng::seed_from_u64(0xADM1N);
        AccountSecretKey::random(&mut rng)
    });

    pub const PK_ADMIN: LazyLock<AccountPublicKey> =
        LazyLock::new(|| AccountPublicKey::from(&*Self::SK_ADMIN));

    pub const SK_VOTER1: LazyLock<AccountSecretKey> = LazyLock::new(|| {
        let mut rng = StdRng::seed_from_u64(0xV0TE1);
        AccountSecretKey::random(&mut rng)
    });

    pub const PK_VOTER1: LazyLock<AccountPublicKey> =
        LazyLock::new(|| AccountPublicKey::from(&*Self::SK_VOTER1));

    pub const SK_VOTER2: LazyLock<AccountSecretKey> = LazyLock::new(|| {
        let mut rng = StdRng::seed_from_u64(0xV0TE2);
        AccountSecretKey::random(&mut rng)
    });

    pub const PK_VOTER2: LazyLock<AccountPublicKey> =
        LazyLock::new(|| AccountPublicKey::from(&*Self::SK_VOTER2));

    pub const SK_NO_TOKENS: LazyLock<AccountSecretKey> = LazyLock::new(|| {
        let mut rng = StdRng::seed_from_u64(0xN0T0K);
        AccountSecretKey::random(&mut rng)
    });

    pub const PK_NO_TOKENS: LazyLock<AccountPublicKey> =
        LazyLock::new(|| AccountPublicKey::from(&*Self::SK_NO_TOKENS));

    /// Create a new test session with contracts deployed
    pub fn new() -> Self {
        let vm = VM::ephemeral().expect("Creating VM should succeed");
        let mut session = vm
            .session(SessionData::builder())
            .expect("Creating session should succeed");

        // Deploy mock token contract with initial balances
        let initial_balances: Vec<(AccountPublicKey, u64)> = vec![
            (*Self::PK_ADMIN, 1000),
            (*Self::PK_VOTER1, 500),
            (*Self::PK_VOTER2, 200),
        ];

        session
            .deploy(
                TOKEN_BYTECODE,
                ContractData::builder()
                    .owner(DEPLOYER)
                    .init_arg(&initial_balances)
                    .contract_id(TOKEN_CONTRACT_ID),
                GAS_LIMIT,
            )
            .expect("Deploying token contract should succeed");

        // Deploy vote contract with admin and token contract
        let admin = Account::External(*Self::PK_ADMIN);
        session
            .deploy(
                VOTE_BYTECODE,
                ContractData::builder()
                    .owner(DEPLOYER)
                    .init_arg(&(admin, TOKEN_CONTRACT_ID))
                    .contract_id(VOTE_CONTRACT_ID),
                GAS_LIMIT,
            )
            .expect("Deploying vote contract should succeed");

        Self { session }
    }

    // Helper methods for query functions

    pub fn get_proposal(&mut self, id: u32) -> Option<Proposal> {
        self.session
            .call::<u32, Option<Proposal>>(VOTE_CONTRACT_ID, "get_proposal", &id, GAS_LIMIT)
            .expect("Getting proposal should succeed")
            .data
    }

    pub fn get_all_proposals(&mut self) -> Vec<Proposal> {
        self.session
            .call::<(), Vec<Proposal>>(VOTE_CONTRACT_ID, "get_all_proposals", &(), GAS_LIMIT)
            .expect("Getting all proposals should succeed")
            .data
    }

    pub fn proposal_count(&mut self) -> u32 {
        self.session
            .call::<(), u32>(VOTE_CONTRACT_ID, "proposal_count", &(), GAS_LIMIT)
            .expect("Getting proposal count should succeed")
            .data
    }

    pub fn token_balance(&mut self, pk: &AccountPublicKey) -> u64 {
        self.session
            .call::<AccountPublicKey, u64>(TOKEN_CONTRACT_ID, "balance_of", pk, GAS_LIMIT)
            .expect("Getting balance should succeed")
            .data
    }

    pub fn get_balance(&mut self, pk: &AccountPublicKey) -> u64 {
        self.session
            .call::<AccountPublicKey, u64>(VOTE_CONTRACT_ID, "get_balance", pk, GAS_LIMIT)
            .expect("Getting balance from vote contract should succeed")
            .data
    }

    pub fn token_contract(&mut self) -> ContractId {
        self.session
            .call::<(), ContractId>(VOTE_CONTRACT_ID, "token_contract", &(), GAS_LIMIT)
            .expect("Getting token contract should succeed")
            .data
    }
}

#[cfg(test)]
mod tests;
