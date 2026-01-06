//! Tests for the Vote Contract
//!
//! Note: Tests that require sender authentication (add_proposal, vote, etc.)
//! need a full network session with signed transactions. Direct piecrust calls
//! don't set up the public_sender context correctly.
//!
//! These tests focus on:
//! 1. Contract deployment and initialization
//! 2. Cross-contract calls (vote contract -> token contract)
//! 3. Query functions that don't require authentication

use crate::{TestSession, TOKEN_CONTRACT_ID};

// ==================== Deployment Tests ====================

#[test]
fn test_deploy() {
    // Test that contracts deploy successfully
    let _ = TestSession::new();
}

#[test]
fn test_initial_token_contract() {
    let mut session = TestSession::new();
    let token = session.token_contract();
    assert_eq!(token, TOKEN_CONTRACT_ID);
}

#[test]
fn test_initial_proposal_count() {
    let mut session = TestSession::new();
    assert_eq!(session.proposal_count(), 0);
}

// ==================== Cross-Contract Balance Tests ====================
// These tests verify the vote contract can query the token contract

#[test]
fn test_token_balances_via_vote_contract() {
    let mut session = TestSession::new();

    // Check balances through the vote contract's get_balance
    // This tests the cross-contract call mechanism
    assert_eq!(session.get_balance(&*TestSession::PK_ADMIN), 1000);
    assert_eq!(session.get_balance(&*TestSession::PK_VOTER1), 500);
    assert_eq!(session.get_balance(&*TestSession::PK_VOTER2), 200);
    assert_eq!(session.get_balance(&*TestSession::PK_NO_TOKENS), 0);
}

#[test]
fn test_token_balances_direct() {
    let mut session = TestSession::new();

    // Check balances directly from token contract
    assert_eq!(session.token_balance(&*TestSession::PK_ADMIN), 1000);
    assert_eq!(session.token_balance(&*TestSession::PK_VOTER1), 500);
    assert_eq!(session.token_balance(&*TestSession::PK_VOTER2), 200);
    assert_eq!(session.token_balance(&*TestSession::PK_NO_TOKENS), 0);
}

#[test]
fn test_balance_consistency() {
    let mut session = TestSession::new();

    // Verify the vote contract's balance query matches direct token query
    for pk in [
        &*TestSession::PK_ADMIN,
        &*TestSession::PK_VOTER1,
        &*TestSession::PK_VOTER2,
        &*TestSession::PK_NO_TOKENS,
    ] {
        let direct = session.token_balance(pk);
        let via_vote = session.get_balance(pk);
        assert_eq!(
            direct, via_vote,
            "Balance mismatch for account"
        );
    }
}

// ==================== Query Tests ====================

#[test]
fn test_get_nonexistent_proposal() {
    let mut session = TestSession::new();

    // Should return None for non-existent proposal
    let proposal = session.get_proposal(999);
    assert!(proposal.is_none());
}

#[test]
fn test_get_all_proposals_empty() {
    let mut session = TestSession::new();

    let proposals = session.get_all_proposals();
    assert!(proposals.is_empty());
}

// ==================== Note on Authentication Tests ====================
//
// The following functions require sender authentication via sender_account():
// - add_proposal (admin only)
// - close_proposal (admin only)
// - vote (requires public_sender for token balance lookup)
// - propose_admin (admin only)
// - accept_admin (pending admin only)
// - cancel_admin_proposal (admin only)
// - is_admin (uses sender_account)
// - has_voted (uses sender_account)
// - get_vote_weight (uses sender_account)
//
// These cannot be properly tested with direct piecrust calls because
// abi::public_sender() and abi::callstack() require transaction context.
//
// To fully test these functions, use the EMT-style test framework with:
// 1. NetworkSession from dusk-vm
// 2. Genesis contracts (transfer_contract.wasm, stake_contract.wasm)
// 3. Signed moonlight transactions (icc_transaction)
//
// See: https://github.com/dusk-network/electronic-money-token/tree/main/tests
