//! Voting System Contract for Dusk Network
//!
//! Features:
//! - Admin-managed proposals (only admin can create/close proposals)
//! - stDUSK token holders can vote (balance queried from stDUSK contract)
//! - Weighted voting (1 stDUSK = 1 vote)
//! - Double-vote prevention
//! - Secure sender verification via call stack

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use dusk_core::abi;
use dusk_core::abi::ContractId;
use dusk_core::signatures::bls::PublicKey;

use rkyv::{Archive, Deserialize, Serialize};
use bytecheck::CheckBytes;

/// Maximum length for proposal descriptions
const MAX_PROPOSAL_DESC_LEN: usize = 256;
/// Maximum number of proposals
const MAX_PROPOSALS: usize = 100;

/// Error messages
mod error {
    pub const SHIELDED_NOT_SUPPORTED: &str = "Shielded transactions not supported";
    pub const NOT_ADMIN: &str = "Caller is not admin";
    pub const CANNOT_PROPOSE_SELF: &str = "Cannot propose self as new admin";
    pub const NOT_PENDING_ADMIN: &str = "Caller is not pending admin";
    pub const NO_PENDING_TRANSFER: &str = "No pending admin transfer";
    pub const MAX_PROPOSALS_REACHED: &str = "Maximum proposals reached";
    pub const DESCRIPTION_TOO_LONG: &str = "Description too long";
    pub const PROPOSAL_NOT_FOUND: &str = "Proposal not found";
    pub const CONTRACTS_CANNOT_VOTE: &str = "Contracts cannot vote";
    pub const NO_VOTING_POWER: &str = "No tokens to vote with";
    pub const PROPOSAL_NOT_ACTIVE: &str = "Proposal is not active";
    pub const ALREADY_VOTED: &str = "Already voted on this proposal";
}

/// Account type - can be either an external account (user) or a contract
#[derive(Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize, Debug)]
#[archive_attr(derive(CheckBytes))]
pub enum Account {
    /// An externally owned account (user with BLS public key)
    External(PublicKey),
    /// A contract account
    Contract(ContractId),
}

impl Default for Account {
    fn default() -> Self {
        Account::External(PublicKey::default())
    }
}

// Implement ordering for BTreeMap usage
impl PartialOrd for Account {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Account {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match (self, other) {
            (Account::External(a), Account::External(b)) => {
                a.to_raw_bytes().cmp(&b.to_raw_bytes())
            }
            (Account::Contract(a), Account::Contract(b)) => a.as_bytes().cmp(b.as_bytes()),
            (Account::External(_), Account::Contract(_)) => core::cmp::Ordering::Less,
            (Account::Contract(_), Account::External(_)) => core::cmp::Ordering::Greater,
        }
    }
}

/// Get the sender account from the call stack
/// - If called directly by a user, returns External with their public key
/// - If called by another contract, returns Contract with caller ID
#[cfg(target_family = "wasm")]
fn sender_account() -> Account {
    if abi::callstack().len() == 1 {
        Account::External(
            abi::public_sender().expect(error::SHIELDED_NOT_SUPPORTED),
        )
    } else {
        Account::Contract(abi::caller().expect("ICC expects a caller"))
    }
}

/// Mock implementation for tests - returns a default account
/// This allows the contract to compile for unit tests
#[cfg(not(target_family = "wasm"))]
fn sender_account() -> Account {
    Account::External(PublicKey::default())
}

/// Proposal structure
#[derive(Clone, Default, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct Proposal {
    pub id: u32,
    pub description: String,
    pub yes_votes: u64,
    pub no_votes: u64,
    pub active: bool,
}

/// The main contract state
pub struct VoteContract {
    /// Admin account that can add/close proposals
    admin: Account,
    /// Pending admin for two-step transfer (None if no transfer pending)
    pending_admin: Option<Account>,
    /// Token contract used for voting weight (e.g., stDUSK)
    token_contract: ContractId,
    /// List of proposals
    proposals: Vec<Proposal>,
    /// Track who voted on which proposal (proposal_id -> account -> vote_weight)
    votes: BTreeMap<u32, BTreeMap<Account, u64>>,
    /// Next proposal ID
    next_proposal_id: u32,
}

/// Contract state - persisted automatically by Piecrust
static mut STATE: VoteContract = VoteContract {
    admin: Account::Contract(ContractId::from_bytes([0u8; 32])),
    pending_admin: None,
    token_contract: ContractId::from_bytes([0u8; 32]),
    proposals: Vec::new(),
    votes: BTreeMap::new(),
    next_proposal_id: 0,
};

/// Query token balance for an account
#[cfg(target_family = "wasm")]
fn get_token_balance(token_contract: ContractId, public_key: &PublicKey) -> u64 {
    // Call token contract's balance_of function
    match abi::call(token_contract, "balance_of", public_key) {
        Ok(balance) => balance,
        Err(_) => 0, // Return 0 if call fails
    }
}

/// Mock implementation for tests (non-WASM)
#[cfg(not(target_family = "wasm"))]
fn get_token_balance(_token_contract: ContractId, _public_key: &PublicKey) -> u64 {
    0 // Return 0 in test mode - tests should test contract state directly
}

impl VoteContract {
    /// Initialize the contract with specified admin and token contract
    pub fn init(&mut self, admin: Account, token_contract: ContractId) {
        self.admin = admin;
        self.token_contract = token_contract;
        self.pending_admin = None;
        self.next_proposal_id = 0;
    }

    // ==================== Admin Transfer Functions (Two-Step Process) ====================

    /// Propose a new admin (admin only)
    /// The new admin must call accept_admin() to complete the transfer
    pub fn propose_admin(&mut self, new_admin: Account) {
        let caller = sender_account();
        assert!(caller == self.admin, "{}", error::NOT_ADMIN);
        assert!(new_admin != self.admin, "{}", error::CANNOT_PROPOSE_SELF);
        self.pending_admin = Some(new_admin);
    }

    /// Accept admin role (pending admin only)
    /// Completes the two-step admin transfer process
    pub fn accept_admin(&mut self) {
        let caller = sender_account();
        let pending = self.pending_admin.expect(error::NO_PENDING_TRANSFER);
        assert!(pending == caller, "{}", error::NOT_PENDING_ADMIN);
        self.admin = caller;
        self.pending_admin = None;
    }

    /// Cancel pending admin transfer (admin only)
    pub fn cancel_admin_proposal(&mut self) {
        let caller = sender_account();
        assert!(caller == self.admin, "{}", error::NOT_ADMIN);
        assert!(self.pending_admin.is_some(), "{}", error::NO_PENDING_TRANSFER);
        self.pending_admin = None;
    }

    /// Get the pending admin (if any)
    pub fn pending_admin(&self) -> Option<Account> {
        self.pending_admin
    }

    // ==================== Proposal Functions (Admin Only) ====================

    /// Add a new proposal (admin only)
    /// Caller is determined from the call stack
    pub fn add_proposal(&mut self, description: String) -> u32 {
        let caller = sender_account();
        assert!(caller == self.admin, "{}", error::NOT_ADMIN);
        assert!(self.proposals.len() < MAX_PROPOSALS, "{}", error::MAX_PROPOSALS_REACHED);
        assert!(description.len() <= MAX_PROPOSAL_DESC_LEN, "{}", error::DESCRIPTION_TOO_LONG);

        let id = self.next_proposal_id;
        self.next_proposal_id += 1;

        self.proposals.push(Proposal {
            id,
            description,
            yes_votes: 0,
            no_votes: 0,
            active: true,
        });

        self.votes.insert(id, BTreeMap::new());
        id
    }

    /// Close a proposal (admin only)
    /// Caller is determined from the call stack
    pub fn close_proposal(&mut self, proposal_id: u32) {
        let caller = sender_account();
        assert!(caller == self.admin, "{}", error::NOT_ADMIN);
        let proposal = self.proposals.iter_mut()
            .find(|p| p.id == proposal_id)
            .expect(error::PROPOSAL_NOT_FOUND);
        proposal.active = false;
    }

    // ==================== Voting Functions ====================

    /// Vote on a proposal
    /// Voter is determined from the call stack
    /// - proposal_id: which proposal to vote on
    /// - vote_yes: true for yes, false for no
    pub fn vote(&mut self, proposal_id: u32, vote_yes: bool) {
        let voter = sender_account();

        // Get the public key for token balance lookup
        let public_key = match voter {
            Account::External(pk) => pk,
            Account::Contract(_) => panic!("{}", error::CONTRACTS_CANNOT_VOTE),
        };

        // Query token balance from the token contract
        let token_balance = get_token_balance(self.token_contract, &public_key);
        assert!(token_balance > 0, "{}", error::NO_VOTING_POWER);

        // Check proposal exists and is active
        let proposal = self.proposals.iter_mut()
            .find(|p| p.id == proposal_id)
            .expect(error::PROPOSAL_NOT_FOUND);
        assert!(proposal.active, "{}", error::PROPOSAL_NOT_ACTIVE);

        // Check if already voted
        let proposal_votes = self.votes.get_mut(&proposal_id)
            .expect(error::PROPOSAL_NOT_FOUND);
        assert!(!proposal_votes.contains_key(&voter), "{}", error::ALREADY_VOTED);

        // Record vote with weight = token balance
        proposal_votes.insert(voter, token_balance);
        if vote_yes {
            proposal.yes_votes = proposal.yes_votes.saturating_add(token_balance);
        } else {
            proposal.no_votes = proposal.no_votes.saturating_add(token_balance);
        }
    }

    // ==================== Query Functions ====================

    /// Get proposal details
    pub fn get_proposal(&self, proposal_id: u32) -> Option<Proposal> {
        self.proposals.iter().find(|p| p.id == proposal_id).cloned()
    }

    /// Get all proposals
    pub fn get_all_proposals(&self) -> Vec<Proposal> {
        self.proposals.clone()
    }

    /// Get proposal count
    pub fn proposal_count(&self) -> u32 {
        self.proposals.len() as u32
    }

    /// Check if caller has voted on a proposal
    pub fn has_voted(&self, proposal_id: u32) -> bool {
        let voter = sender_account();
        self.votes
            .get(&proposal_id)
            .map(|v| v.contains_key(&voter))
            .unwrap_or(false)
    }

    /// Check if a specific account has voted on a proposal
    pub fn has_account_voted(&self, public_key: PublicKey, proposal_id: u32) -> bool {
        let account = Account::External(public_key);
        self.votes
            .get(&proposal_id)
            .map(|v| v.contains_key(&account))
            .unwrap_or(false)
    }

    /// Get vote weight for caller on a proposal (0 if not voted)
    pub fn get_vote_weight(&self, proposal_id: u32) -> u64 {
        let voter = sender_account();
        self.votes
            .get(&proposal_id)
            .and_then(|v| v.get(&voter))
            .copied()
            .unwrap_or(0)
    }

    /// Get vote weight for a specific account on a proposal (0 if not voted)
    pub fn get_account_vote_weight(&self, public_key: PublicKey, proposal_id: u32) -> u64 {
        let account = Account::External(public_key);
        self.votes
            .get(&proposal_id)
            .and_then(|v| v.get(&account))
            .copied()
            .unwrap_or(0)
    }

    /// Get admin account
    pub fn admin(&self) -> Account {
        self.admin
    }

    /// Check if caller is admin
    pub fn is_admin(&self) -> bool {
        sender_account() == self.admin
    }

    /// Get token balance for a public key (queries token contract)
    pub fn get_balance(&self, public_key: PublicKey) -> u64 {
        get_token_balance(self.token_contract, &public_key)
    }

    /// Get the token contract ID used for voting weight
    pub fn token_contract(&self) -> ContractId {
        self.token_contract
    }
}

// ==================== Contract Entry Points ====================
// These are only compiled for WASM targets

#[cfg(target_family = "wasm")]
mod entry_points {
    use super::*;

/// Initialize contract with specified admin and token contract
#[no_mangle]
pub unsafe fn init(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |(admin, token_contract): (Account, ContractId)| {
        STATE.init(admin, token_contract);
    })
}

/// Add proposal (admin only) - caller determined from call stack
#[no_mangle]
pub unsafe fn add_proposal(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |description: String| {
        STATE.add_proposal(description)
    })
}

/// Close proposal (admin only) - caller determined from call stack
#[no_mangle]
pub unsafe fn close_proposal(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |proposal_id: u32| {
        STATE.close_proposal(proposal_id)
    })
}

/// Vote on proposal - voter determined from call stack
#[no_mangle]
pub unsafe fn vote(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |(proposal_id, vote_yes): (u32, bool)| {
        STATE.vote(proposal_id, vote_yes)
    })
}

/// Get proposal by ID
#[no_mangle]
pub unsafe fn get_proposal(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |proposal_id: u32| STATE.get_proposal(proposal_id))
}

/// Get all proposals
#[no_mangle]
pub unsafe fn get_all_proposals(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.get_all_proposals())
}

/// Get proposal count
#[no_mangle]
pub unsafe fn proposal_count(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.proposal_count())
}

/// Check if caller has voted on proposal
#[no_mangle]
pub unsafe fn has_voted(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |proposal_id: u32| {
        STATE.has_voted(proposal_id)
    })
}

/// Check if specific account has voted on proposal
#[no_mangle]
pub unsafe fn has_account_voted(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |(public_key, proposal_id): (PublicKey, u32)| {
        STATE.has_account_voted(public_key, proposal_id)
    })
}

/// Get vote weight for caller on proposal
#[no_mangle]
pub unsafe fn get_vote_weight(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |proposal_id: u32| {
        STATE.get_vote_weight(proposal_id)
    })
}

/// Get vote weight for specific account on proposal
#[no_mangle]
pub unsafe fn get_account_vote_weight(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |(public_key, proposal_id): (PublicKey, u32)| {
        STATE.get_account_vote_weight(public_key, proposal_id)
    })
}

/// Get token balance for a public key
#[no_mangle]
pub unsafe fn get_balance(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |public_key: PublicKey| STATE.get_balance(public_key))
}

/// Get the token contract ID used for voting weight
#[no_mangle]
pub unsafe fn token_contract(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.token_contract())
}

/// Get admin account
#[no_mangle]
pub unsafe fn admin(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.admin())
}

/// Check if caller is admin
#[no_mangle]
pub unsafe fn is_admin(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.is_admin())
}

// ==================== Admin Transfer Entry Points ====================

/// Propose a new admin (admin only) - two-step transfer process
#[no_mangle]
pub unsafe fn propose_admin(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |new_admin: Account| {
        STATE.propose_admin(new_admin)
    })
}

/// Accept admin role (pending admin only) - completes the transfer
#[no_mangle]
pub unsafe fn accept_admin(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.accept_admin())
}

/// Cancel pending admin transfer (admin only)
#[no_mangle]
pub unsafe fn cancel_admin_proposal(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.cancel_admin_proposal())
}

/// Get pending admin (if any)
#[no_mangle]
pub unsafe fn pending_admin(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.pending_admin())
}

} // end of entry_points module

// ==================== Unit Tests ====================
// These tests verify the contract logic without requiring the VM

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn create_test_contract(admin_pk: PublicKey, token_contract: ContractId) -> VoteContract {
        VoteContract {
            admin: Account::External(admin_pk),
            pending_admin: None,
            token_contract,
            proposals: Vec::new(),
            votes: BTreeMap::new(),
            next_proposal_id: 0,
        }
    }

    fn mock_public_key(seed: u8) -> PublicKey {
        // Create a deterministic but valid-looking public key for tests
        let mut bytes = [0u8; 96];
        for i in 0..96 {
            bytes[i] = seed.wrapping_add(i as u8);
        }
        // Note: This won't create a cryptographically valid key,
        // but it's sufficient for testing data structures
        PublicKey::default()
    }

    // ==================== Proposal Tests ====================

    #[test]
    fn test_proposal_structure() {
        let proposal = Proposal {
            id: 0,
            description: "Test proposal".to_string(),
            yes_votes: 100,
            no_votes: 50,
            active: true,
        };

        assert_eq!(proposal.id, 0);
        assert_eq!(proposal.description, "Test proposal");
        assert_eq!(proposal.yes_votes, 100);
        assert_eq!(proposal.no_votes, 50);
        assert!(proposal.active);
    }

    #[test]
    fn test_proposal_default() {
        let proposal = Proposal::default();

        assert_eq!(proposal.id, 0);
        assert_eq!(proposal.description, "");
        assert_eq!(proposal.yes_votes, 0);
        assert_eq!(proposal.no_votes, 0);
        assert!(!proposal.active);
    }

    // ==================== Account Tests ====================

    #[test]
    fn test_account_external() {
        let pk = mock_public_key(1);
        let account = Account::External(pk);

        match account {
            Account::External(_) => (),
            Account::Contract(_) => panic!("Expected External account"),
        }
    }

    #[test]
    fn test_account_contract() {
        let contract_id = ContractId::from_bytes([1u8; 32]);
        let account = Account::Contract(contract_id);

        match account {
            Account::Contract(id) => assert_eq!(id, contract_id),
            Account::External(_) => panic!("Expected Contract account"),
        }
    }

    #[test]
    fn test_account_ordering() {
        let pk1 = mock_public_key(1);
        let pk2 = mock_public_key(2);
        let contract_id = ContractId::from_bytes([1u8; 32]);

        let ext1 = Account::External(pk1);
        let ext2 = Account::External(pk2);
        let contract = Account::Contract(contract_id);

        // External accounts should come before contract accounts
        assert!(ext1 < contract);
        assert!(ext2 < contract);
    }

    // ==================== VoteContract State Tests ====================

    #[test]
    fn test_contract_init() {
        let admin_pk = mock_public_key(1);
        let token_id = ContractId::from_bytes([2u8; 32]);

        let mut contract = VoteContract {
            admin: Account::Contract(ContractId::from_bytes([0u8; 32])),
            pending_admin: None,
            token_contract: ContractId::from_bytes([0u8; 32]),
            proposals: Vec::new(),
            votes: BTreeMap::new(),
            next_proposal_id: 0,
        };

        contract.init(Account::External(admin_pk), token_id);

        assert_eq!(contract.admin, Account::External(admin_pk));
        assert_eq!(contract.token_contract, token_id);
        assert!(contract.pending_admin.is_none());
        assert_eq!(contract.next_proposal_id, 0);
    }

    #[test]
    fn test_get_proposal_returns_none_for_nonexistent() {
        let admin_pk = mock_public_key(1);
        let token_id = ContractId::from_bytes([2u8; 32]);
        let contract = create_test_contract(admin_pk, token_id);

        assert!(contract.get_proposal(0).is_none());
        assert!(contract.get_proposal(999).is_none());
    }

    #[test]
    fn test_get_all_proposals_empty() {
        let admin_pk = mock_public_key(1);
        let token_id = ContractId::from_bytes([2u8; 32]);
        let contract = create_test_contract(admin_pk, token_id);

        let proposals = contract.get_all_proposals();
        assert!(proposals.is_empty());
    }

    #[test]
    fn test_proposal_count_empty() {
        let admin_pk = mock_public_key(1);
        let token_id = ContractId::from_bytes([2u8; 32]);
        let contract = create_test_contract(admin_pk, token_id);

        assert_eq!(contract.proposal_count(), 0);
    }

    #[test]
    fn test_admin_getter() {
        let admin_pk = mock_public_key(1);
        let token_id = ContractId::from_bytes([2u8; 32]);
        let contract = create_test_contract(admin_pk, token_id);

        assert_eq!(contract.admin(), Account::External(admin_pk));
    }

    #[test]
    fn test_token_contract_getter() {
        let admin_pk = mock_public_key(1);
        let token_id = ContractId::from_bytes([2u8; 32]);
        let contract = create_test_contract(admin_pk, token_id);

        assert_eq!(contract.token_contract(), token_id);
    }

    #[test]
    fn test_pending_admin_initially_none() {
        let admin_pk = mock_public_key(1);
        let token_id = ContractId::from_bytes([2u8; 32]);
        let contract = create_test_contract(admin_pk, token_id);

        assert!(contract.pending_admin().is_none());
    }

    // ==================== Has Account Voted Tests ====================

    #[test]
    fn test_has_account_voted_false_no_proposal() {
        let admin_pk = mock_public_key(1);
        let voter_pk = mock_public_key(2);
        let token_id = ContractId::from_bytes([2u8; 32]);
        let contract = create_test_contract(admin_pk, token_id);

        // No proposal exists, should return false
        assert!(!contract.has_account_voted(voter_pk, 0));
    }

    #[test]
    fn test_get_account_vote_weight_zero_no_vote() {
        let admin_pk = mock_public_key(1);
        let voter_pk = mock_public_key(2);
        let token_id = ContractId::from_bytes([2u8; 32]);
        let contract = create_test_contract(admin_pk, token_id);

        // No vote cast, should return 0
        assert_eq!(contract.get_account_vote_weight(voter_pk, 0), 0);
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_max_proposal_description_length() {
        assert_eq!(MAX_PROPOSAL_DESC_LEN, 256);
    }

    #[test]
    fn test_max_proposals() {
        assert_eq!(MAX_PROPOSALS, 100);
    }

    // ==================== Error Message Tests ====================

    #[test]
    fn test_error_messages_defined() {
        assert!(!error::NOT_ADMIN.is_empty());
        assert!(!error::PROPOSAL_NOT_FOUND.is_empty());
        assert!(!error::ALREADY_VOTED.is_empty());
        assert!(!error::NO_VOTING_POWER.is_empty());
        assert!(!error::PROPOSAL_NOT_ACTIVE.is_empty());
        assert!(!error::CONTRACTS_CANNOT_VOTE.is_empty());
    }
}
