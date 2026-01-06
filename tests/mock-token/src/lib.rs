//! Mock Token Contract for Testing
//!
//! A simple token contract that stores balances and provides balance_of query.
//! Used to test the vote contract's token balance integration.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use dusk_core::abi;
use dusk_core::signatures::bls::PublicKey;

use rkyv::{Archive, Deserialize, Serialize};
use bytecheck::CheckBytes;

/// Mock token state
struct MockToken {
    balances: BTreeMap<[u8; 96], u64>,
}

static mut STATE: MockToken = MockToken {
    balances: BTreeMap::new(),
};

impl MockToken {
    /// Initialize with a list of (public_key, balance) pairs
    fn init(&mut self, initial_balances: Vec<(PublicKey, u64)>) {
        for (pk, balance) in initial_balances {
            self.balances.insert(pk.to_raw_bytes(), balance);
        }
    }

    /// Get balance for a public key
    fn balance_of(&self, public_key: &PublicKey) -> u64 {
        self.balances
            .get(&public_key.to_raw_bytes())
            .copied()
            .unwrap_or(0)
    }

    /// Set balance for a public key (for testing)
    fn set_balance(&mut self, public_key: PublicKey, balance: u64) {
        self.balances.insert(public_key.to_raw_bytes(), balance);
    }
}

/// Initialize the mock token with balances
#[no_mangle]
unsafe fn init(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |initial_balances: Vec<(PublicKey, u64)>| {
        STATE.init(initial_balances)
    })
}

/// Get balance for a public key
#[no_mangle]
unsafe fn balance_of(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |public_key: PublicKey| {
        STATE.balance_of(&public_key)
    })
}

/// Set balance for a public key (test helper)
#[no_mangle]
unsafe fn set_balance(arg_len: u32) -> u32 {
    abi::wrap_call(arg_len, |(public_key, balance): (PublicKey, u64)| {
        STATE.set_balance(public_key, balance)
    })
}
