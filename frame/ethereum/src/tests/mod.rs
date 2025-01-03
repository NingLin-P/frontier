// This file is part of Frontier.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use frame_support::{
	assert_err, assert_ok, dispatch::GetDispatchInfo, unsigned::TransactionValidityError,
};
use sp_runtime::{
	traits::Applyable,
	transaction_validity::{InvalidTransaction, ValidTransactionBuilder},
};
use std::str::FromStr;

use crate::{
	mock::*, CallOrCreateInfo, Event, RawOrigin, Transaction, TransactionAction, H160, H256, U256,
};
use fp_self_contained::CheckedExtrinsic;
use frame_support::traits::Hooks;
use pallet_evm::AddressMapping;
use sp_core::keccak_256;
use std::time::Instant;

mod eip1559;
mod eip2930;
mod legacy;

// This ERC-20 contract mints the maximum amount of tokens to the contract creator.
// pragma solidity ^0.5.0;`
// import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v2.5.1/contracts/token/ERC20/ERC20.sol";
// contract MyToken is ERC20 {
//	 constructor() public { _mint(msg.sender, 2**256 - 1); }
// }
pub const ERC20_CONTRACT_BYTECODE: &str = include_str!("./res/erc20_contract_bytecode.txt");

// pragma solidity ^0.6.6;
// contract Test {
//      function foo() external pure returns (bool) {
// 	 		return true;
//     }
//
//     function bar() external pure {
// 	 		require(false, "very_long_error_msg_that_we_expect_to_be_trimmed_away");
// 	   }
// }
pub const TEST_CONTRACT_CODE: &str = "608060405234801561001057600080fd5b50610129806100206000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c8063c2985578146037578063febb0f7e146055575b600080fd5b603d605d565b60405180821515815260200191505060405180910390f35b605b6066565b005b60006001905090565b600060bc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260358152602001806100bf6035913960400191505060405180910390fd5b56fe766572795f6c6f6e675f6572726f725f6d73675f746861745f77655f6578706563745f746f5f62655f7472696d6d65645f61776179a26469706673582212207af96dd688d3a3adc999c619e6073d5b6056c72c79ace04a90ea4835a77d179364736f6c634300060c0033";

pub fn address_build(seed_number: u64) -> AccountInfo {
	let mut seed = [0u8; 32];
	seed[0..8].copy_from_slice(&seed_number.to_be_bytes());
	let private_key = H256::from_slice(&seed);
	let secret_key = libsecp256k1::SecretKey::parse_slice(&private_key[..]).unwrap();
	let public_key = &libsecp256k1::PublicKey::from_secret_key(&secret_key).serialize()[1..65];
	let address = H160::from(H256::from(keccak_256(public_key)));

	AccountInfo {
		private_key,
		account_id: <Test as pallet_evm::Config>::AddressMapping::into_account_id(address),
		address,
	}
}

#[test]
fn evm_transact_1000() {
	n_evm_transact(1000);
}

#[test]
fn evm_transact_4000() {
	n_evm_transact(4000);
}

#[test]
fn evm_transact_8000() {
	n_evm_transact(8000);
}

fn n_evm_transact(n: u64) {
	let (acc, mut ext) = new_test_ext_with_initial_balance(1, u64::MAX / 2);
	ext.execute_with(|| {
		let sender = &acc[0];
		let txs: Vec<_> = (1..n)
			.map(|i| {
				let receiver = address_build(i);
				LegacyUnsignedTransaction {
					nonce: U256::from(i - 1),
					gas_price: U256::from(10000),
					gas_limit: U256::from(21000),
					action: ethereum::TransactionAction::Call(receiver.address),
					value: U256::from(1234567890),
					input: vec![],
				}
				.sign(&sender.private_key)
			})
			.collect();

		let start = Instant::now();
		for tx in txs {
			Ethereum::transact(RawOrigin::EthereumTransaction(sender.address).into(), tx).unwrap();
		}
		Ethereum::on_finalize(1);

		println!("{} tx took {}ms", n, start.elapsed().as_millis());
	});
}
