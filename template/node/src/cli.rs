use crate::service::EthConfiguration;
use ethereum::{TransactionAction, TransactionSignature, TransactionV2 as Transaction};
use fp_account::AccountId20;
use frontier_template_runtime::opaque::Block;
use pallet_evm::{config_preludes::ChainId, AddressMapping, IdentityAddressMapping};
use rlp::RlpStream;
use sc_block_builder::BlockBuilderBuilder;
use sc_cli::{PruningParams, SharedParams};
use sp_api::{ApiExt, CallApiAt, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::HeaderBackend;
use sp_core::{hashing::keccak_256, H160, H256, U256};
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

/// Available Sealing methods.
#[derive(Copy, Clone, Debug, Default, clap::ValueEnum)]
pub enum Sealing {
	/// Seal using rpc method.
	#[default]
	Manual,
	/// Seal when transaction is executed.
	Instant,
}

#[derive(Debug, clap::Parser)]
pub struct Cli {
	#[command(subcommand)]
	pub subcommand: Option<Subcommand>,

	#[allow(missing_docs)]
	#[command(flatten)]
	pub run: sc_cli::RunCmd,

	/// Choose sealing method.
	#[arg(long, value_enum, ignore_case = true)]
	pub sealing: Option<Sealing>,

	#[command(flatten)]
	pub eth: EthConfiguration,
}

#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
	/// Key management cli utilities
	#[command(subcommand)]
	Key(sc_cli::KeySubcommand),

	/// Build a chain specification.
	BuildSpec(sc_cli::BuildSpecCmd),

	/// Validate blocks.
	CheckBlock(sc_cli::CheckBlockCmd),

	/// Export blocks.
	ExportBlocks(sc_cli::ExportBlocksCmd),

	/// Export the state of a given block into a chain spec.
	ExportState(sc_cli::ExportStateCmd),

	/// Import blocks.
	ImportBlocks(sc_cli::ImportBlocksCmd),

	/// Remove the whole chain.
	PurgeChain(sc_cli::PurgeChainCmd),

	/// Revert the chain to a previous state.
	Revert(sc_cli::RevertCmd),

	/// Sub-commands concerned with benchmarking.
	#[cfg(feature = "runtime-benchmarks")]
	#[command(subcommand)]
	Benchmark(frame_benchmarking_cli::BenchmarkCmd),

	/// Sub-commands concerned with benchmarking.
	#[cfg(not(feature = "runtime-benchmarks"))]
	Benchmark,

	/// Db meta columns information.
	FrontierDb(fc_cli::FrontierDbCmd),

	BenchmarkBlockExecution(BlockExecutionCmd),
}

pub struct LegacyUnsignedTransaction {
	pub nonce: U256,
	pub gas_price: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Vec<u8>,
}

impl LegacyUnsignedTransaction {
	fn signing_rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(9);
		s.append(&self.nonce);
		s.append(&self.gas_price);
		s.append(&self.gas_limit);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.input);
		s.append(&ChainId::get());
		s.append(&0u8);
		s.append(&0u8);
	}

	fn signing_hash(&self) -> H256 {
		let mut stream = RlpStream::new();
		self.signing_rlp_append(&mut stream);
		H256::from(keccak_256(&stream.out()))
	}

	pub fn sign(&self, key: &H256) -> Transaction {
		self.sign_with_chain_id(key, ChainId::get())
	}

	pub fn sign_with_chain_id(&self, key: &H256, chain_id: u64) -> Transaction {
		let hash = self.signing_hash();
		let msg = libsecp256k1::Message::parse(hash.as_fixed_bytes());
		let s = libsecp256k1::sign(
			&msg,
			&libsecp256k1::SecretKey::parse_slice(&key[..]).unwrap(),
		);
		let sig = s.0.serialize();

		let sig = TransactionSignature::new(
			s.1.serialize() as u64 % 2 + chain_id * 2 + 35,
			H256::from_slice(&sig[0..32]),
			H256::from_slice(&sig[32..64]),
		)
		.unwrap();

		Transaction::Legacy(ethereum::LegacyTransaction {
			nonce: self.nonce,
			gas_price: self.gas_price,
			gas_limit: self.gas_limit,
			action: self.action,
			value: self.value,
			input: self.input.clone(),
			signature: sig,
		})
	}
}

pub struct AccountInfo {
	pub address: H160,
	pub account_id: AccountId20,
	pub private_key: H256,
}

pub fn address_build(seed_number: u64) -> AccountInfo {
	let mut seed = [0u8; 32];
	seed[0..8].copy_from_slice(&seed_number.to_be_bytes());
	let private_key = H256::from_slice(&seed);
	let secret_key = libsecp256k1::SecretKey::parse_slice(&private_key[..]).unwrap();
	let public_key = &libsecp256k1::PublicKey::from_secret_key(&secret_key).serialize()[1..65];
	let address = H160::from(H256::from(keccak_256(public_key)));

	AccountInfo {
		private_key,
		account_id: IdentityAddressMapping::into_account_id(address),
		address,
	}
}

#[derive(Debug, Clone, clap::Parser)]
pub struct BlockExecutionCmd {
	/// Shared parameters
	#[command(flatten)]
	pub shared_params: SharedParams,

	#[allow(missing_docs)]
	#[command(flatten)]
	pub pruning_params: PruningParams,

	// The total number of tx in the block
	#[clap(long)]
	pub number: usize,
}

impl BlockExecutionCmd {
	pub fn run<C>(&self, client: Arc<C>)
	where
		C: HeaderBackend<Block>
			+ ProvideRuntimeApi<Block>
			+ CallApiAt<Block>
			+ Send
			+ Sync
			+ 'static,
		C::Api: ApiExt<Block> + BlockBuilderApi<Block> + 'static,
	{
		let sender = address_build(1u64);
		let txs: Vec<_> = (2..(self.number + 2))
			.map(|i| {
				let receiver = address_build(i as u64);
				let transaction = LegacyUnsignedTransaction {
					nonce: U256::from(i - 2),
					gas_price: U256::from(1000000000),
					gas_limit: U256::from(21000),
					action: ethereum::TransactionAction::Call(receiver.address),
					value: U256::from(1234567890),
					input: vec![],
				}
				.sign(&sender.private_key);
				frontier_template_runtime::UncheckedExtrinsic::new_unsigned(
					pallet_ethereum::Call::transact { transaction }.into(),
				)
				.into()
			})
			.collect();

		let mut block_builder = BlockBuilderBuilder::new(client.as_ref())
			.on_parent_block(client.info().genesis_hash)
			.with_parent_block_number(0u32.into())
			.build()
			.unwrap();

		let start = std::time::Instant::now();
		for tx in txs {
			block_builder.push(tx).unwrap();
		}
		println!("{} tx took {}ms", self.number, start.elapsed().as_millis());
	}
}

impl sc_cli::CliConfiguration for BlockExecutionCmd {
	fn shared_params(&self) -> &SharedParams {
		&self.shared_params
	}

	fn pruning_params(&self) -> Option<&PruningParams> {
		Some(&self.pruning_params)
	}
}
