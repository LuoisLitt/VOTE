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

/// stDUSK token contract ID
const STDUSK_CONTRACT_ID: [u8; 32] = [
    0xfd, 0xbf, 0x49, 0x10, 0x2e, 0x76, 0xcf, 0x58,
    0x22, 0x40, 0x03, 0x45, 0x1c, 0x6c, 0xb9, 0xe3,
    0x40, 0x3c, 0x54, 0xff, 0x1d, 0x90, 0x42, 0xf8,
    0xbc, 0x46, 0xec, 0x25, 0xc6, 0xa4, 0x33, 0x7c,
];

/// Error messages
mod error {
    pub const SHIELDED_NOT_SUPPORTED: &str = "Shielded transactions not supported";
}

/// Account type - can be either an external account (user) or a contract
#[derive(Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize)]
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
fn sender_account() -> Account {
    if abi::callstack().len() == 1 {
        Account::External(
            abi::public_sender().expect(error::SHIELDED_NOT_SUPPORTED),
        )
    } else {
        Account::Contract(abi::caller().expect("ICC expects a caller"))
    }
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
    proposals: Vec::new(),
    votes: BTreeMap::new(),
    next_proposal_id: 0,
};

/// Query stDUSK balance for an account (external accounts only)
fn get_stdusk_balance(public_key: &PublicKey) -> u64 {
    let stdusk_id = ContractId::from_bytes(STDUSK_CONTRACT_ID);

    // Call stDUSK contract's balance_of function
    match abi::call(stdusk_id, "balance_of", public_key) {
        Ok(balance) => balance,
        Err(_) => 0, // Return 0 if call fails
    }
}

impl VoteContract {
    /// Initialize the contract with specified admin
    pub fn init(&mut self, admin: Account) {
        self.admin = admin;
        self.pending_admin = None;
        self.next_proposal_id = 0;
    }

    // ==================== Admin Transfer Functions (Two-Step Process) ====================

    /// Propose a new admin (admin only)
    /// The new admin must call accept_admin() to complete the transfer
    pub fn propose_admin(&mut self, new_admin: Account) -> bool {
        let caller = sender_account();

        // Only current admin can propose a new admin
        if caller != self.admin {
            return false;
        }

        // Cannot propose self as new admin
        if new_admin == self.admin {
            return false;
        }

        self.pending_admin = Some(new_admin);
        true
    }

    /// Accept admin role (pending admin only)
    /// Completes the two-step admin transfer process
    pub fn accept_admin(&mut self) -> bool {
        let caller = sender_account();

        // Check if there's a pending admin and caller matches
        match &self.pending_admin {
            Some(pending) if *pending == caller => {
                self.admin = caller;
                self.pending_admin = None;
                true
            }
            _ => false,
        }
    }

    /// Cancel pending admin transfer (admin only)
    pub fn cancel_admin_proposal(&mut self) -> bool {
        let caller = sender_account();

        // Only current admin can cancel
        if caller != self.admin {
            return false;
        }

        // Check if there's actually a pending transfer
        if self.pending_admin.is_none() {
            return false;
        }

        self.pending_admin = None;
        true
    }

    /// Get the pending admin (if any)
    pub fn pending_admin(&self) -> Option<Account> {
        self.pending_admin
    }

    // ==================== Proposal Functions (Admin Only) ====================

    /// Add a new proposal (admin only)
    /// Caller is determined from the call stack
    pub fn add_proposal(&mut self, description: String) -> Option<u32> {
        let caller = sender_account();

        if caller != self.admin {
            return None;
        }
        if self.proposals.len() >= MAX_PROPOSALS {
            return None;
        }
        if description.len() > MAX_PROPOSAL_DESC_LEN {
            return None;
        }

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

        Some(id)
    }

    /// Close a proposal (admin only)
    /// Caller is determined from the call stack
    pub fn close_proposal(&mut self, proposal_id: u32) -> bool {
        let caller = sender_account();

        if caller != self.admin {
            return false;
        }
        if let Some(proposal) = self.proposals.iter_mut().find(|p| p.id == proposal_id) {
            proposal.active = false;
            return true;
        }
        false
    }

    // ==================== Voting Functions ====================

    /// Vote on a proposal
    /// Voter is determined from the call stack
    /// - proposal_id: which proposal to vote on
    /// - vote_yes: true for yes, false for no
    pub fn vote(&mut self, proposal_id: u32, vote_yes: bool) -> bool {
        let voter = sender_account();

        // Get the public key for stDUSK balance lookup
        let public_key = match &voter {
            Account::External(pk) => *pk,
            Account::Contract(_) => return false, // Contracts cannot vote
        };

        // Query stDUSK balance from the token contract
        let token_balance = get_stdusk_balance(&public_key);

        // Must have stDUSK tokens to vote
        if token_balance == 0 {
            return false;
        }

        // Check proposal exists and is active
        let proposal = match self.proposals.iter_mut().find(|p| p.id == proposal_id) {
            Some(p) if p.active => p,
            _ => return false,
        };

        // Check if already voted
        let proposal_votes = match self.votes.get_mut(&proposal_id) {
            Some(v) => v,
            None => return false,
        };

        if proposal_votes.contains_key(&voter) {
            return false; // Already voted
        }

        // Record vote with weight = stDUSK balance
        proposal_votes.insert(voter, token_balance);
        if vote_yes {
            proposal.yes_votes = proposal.yes_votes.saturating_add(token_balance);
        } else {
            proposal.no_votes = proposal.no_votes.saturating_add(token_balance);
        }

        true
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

    /// Get stDUSK balance for a public key (queries stDUSK contract)
    pub fn get_balance(&self, public_key: PublicKey) -> u64 {
        get_stdusk_balance(&public_key)
    }
}

// ==================== Contract Entry Points ====================

/// Initialize contract with specified admin
#[no_mangle]
unsafe fn init(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |admin: Account| {
        STATE.init(admin);
    })
}

/// Add proposal (admin only) - caller determined from call stack
#[no_mangle]
unsafe fn add_proposal(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |description: String| {
        STATE.add_proposal(description)
    })
}

/// Close proposal (admin only) - caller determined from call stack
#[no_mangle]
unsafe fn close_proposal(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |proposal_id: u32| {
        STATE.close_proposal(proposal_id)
    })
}

/// Vote on proposal - voter determined from call stack
#[no_mangle]
unsafe fn vote(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |(proposal_id, vote_yes): (u32, bool)| {
        STATE.vote(proposal_id, vote_yes)
    })
}

/// Get proposal by ID
#[no_mangle]
unsafe fn get_proposal(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |proposal_id: u32| STATE.get_proposal(proposal_id))
}

/// Get all proposals
#[no_mangle]
unsafe fn get_all_proposals(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.get_all_proposals())
}

/// Get proposal count
#[no_mangle]
unsafe fn proposal_count(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.proposal_count())
}

/// Check if caller has voted on proposal
#[no_mangle]
unsafe fn has_voted(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |proposal_id: u32| {
        STATE.has_voted(proposal_id)
    })
}

/// Check if specific account has voted on proposal
#[no_mangle]
unsafe fn has_account_voted(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |(public_key, proposal_id): (PublicKey, u32)| {
        STATE.has_account_voted(public_key, proposal_id)
    })
}

/// Get vote weight for caller on proposal
#[no_mangle]
unsafe fn get_vote_weight(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |proposal_id: u32| {
        STATE.get_vote_weight(proposal_id)
    })
}

/// Get vote weight for specific account on proposal
#[no_mangle]
unsafe fn get_account_vote_weight(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |(public_key, proposal_id): (PublicKey, u32)| {
        STATE.get_account_vote_weight(public_key, proposal_id)
    })
}

/// Get stDUSK balance for a public key
#[no_mangle]
unsafe fn get_balance(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |public_key: PublicKey| STATE.get_balance(public_key))
}

/// Get admin account
#[no_mangle]
unsafe fn admin(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.admin())
}

/// Check if caller is admin
#[no_mangle]
unsafe fn is_admin(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.is_admin())
}

// ==================== Admin Transfer Entry Points ====================

/// Propose a new admin (admin only) - two-step transfer process
#[no_mangle]
unsafe fn propose_admin(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |new_admin: Account| {
        STATE.propose_admin(new_admin)
    })
}

/// Accept admin role (pending admin only) - completes the transfer
#[no_mangle]
unsafe fn accept_admin(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.accept_admin())
}

/// Cancel pending admin transfer (admin only)
#[no_mangle]
unsafe fn cancel_admin_proposal(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.cancel_admin_proposal())
}

/// Get pending admin (if any)
#[no_mangle]
unsafe fn pending_admin(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |_: ()| STATE.pending_admin())
}
