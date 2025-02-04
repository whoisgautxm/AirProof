mod structs;
mod server;
use actix_web::{Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, utils, HashableKey, ProverClient, SP1Stdin};
use ethers_core::types::{H160, Signature, H256};
use ethers_core::abi::Token;
use ethers_core::types::transaction::eip712::EIP712Domain;
use ethers_core::utils::keccak256;
use std::fs;
use structs::{Attest, InputData};

// Reuse existing constants and structs

/// ELF file for the Succinct RISC-V zkVM.
pub const ADDRESS_ELF: &[u8] = include_elf!("fibonacci-program");
const YEAR_IN_SECONDS: u64 = 365 * 24 * 60 * 60;
const THRESHOLD_AGE: u64 = 18 * YEAR_IN_SECONDS;

#[derive(Serialize, Deserialize)]
struct ProofData {
    proof: String,         // hex string
    public_inputs: String, // hex string
    vkey_hash: String,     // vk.bytes32()
    mode: String,
}

#[derive(Parser)]
#[command(name = "zkVM Proof Generator")]
struct Cli {
    #[arg(long, default_value_t = false, help = "Generate or use pregenerated proof")]
    prove: bool,
    #[arg(long, default_value = "plonk", help = "Proof mode (e.g., groth16, plonk)")]
    mode: String,
}

fn parse_input_data(file_path: &str) -> Result<InputData, Box<dyn std::error::Error>> {
    let json_str = fs::read_to_string(file_path)?;
    let input_data = serde_json::from_str(&json_str)?;
    Ok(input_data)
}

pub fn domain_separator(domain: &EIP712Domain, type_hash: H256) -> H256 {
    let encoded = ethers_core::abi::encode(&[
        Token::FixedBytes(type_hash.as_bytes().to_vec()),
        Token::FixedBytes(keccak256(domain.name.as_ref().unwrap().as_bytes()).to_vec()),
        Token::FixedBytes(keccak256(domain.version.as_ref().unwrap().as_bytes()).to_vec()),
        Token::Uint(domain.chain_id.unwrap()),
        Token::Address(domain.verifying_contract.unwrap()),
    ]);
    keccak256(&encoded).into()
}

fn create_domain_separator(input_data: &InputData) -> H256 {
    let domain = ethers_core::types::transaction::eip712::EIP712Domain {
        name: Some(input_data.sig.domain.name.clone()),
        version: Some(input_data.sig.domain.version.clone()),
        chain_id: Some(ethers_core::types::U256::from_dec_str(&input_data.sig.domain.chain_id).unwrap()),
        verifying_contract: Some(input_data.sig.domain.verifying_contract.parse().unwrap()),
        salt: None,
    };
    domain_separator(
        &domain,
        ethers_core::utils::keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)").into(),
    )
}

fn build_message(input_data: &InputData) -> Attest {
    Attest {
        version: input_data.sig.message.version.clone(),
        schema: input_data.sig.message.schema.parse().unwrap(),
        recipient: input_data.sig.message.recipient.parse().unwrap(),
        time: input_data.sig.message.time.parse().unwrap(),
        expiration_time: input_data.sig.message.expiration_time.parse().unwrap(),
        revocable: input_data.sig.message.revocable,
        ref_uid: input_data.sig.message.ref_uid.parse().unwrap(),
        data: ethers_core::utils::hex::decode(&input_data.sig.message.data[2..]).unwrap(),
        salt: input_data.sig.message.salt.parse().unwrap(),
    }
}

fn parse_signature(input_data: &InputData) -> Signature {
    Signature {
        r: input_data.sig.signature.r.parse().unwrap(),
        s: input_data.sig.signature.s.parse().unwrap(),
        v: input_data.sig.signature.v.into(),
    }
}

pub async fn generate_proof(input_path: &str) -> Result<ProofData, Box<dyn std::error::Error>> {
    utils::setup_logger();
    
    let input_data = parse_input_data(input_path)?;
    let signer_address: H160 = input_data.signer.parse()?;
    let message = build_message(&input_data);
    let domain_separator = create_domain_separator(&input_data);
    let signature = parse_signature(&input_data);

    let mut stdin = SP1Stdin::new();
    stdin.write(&signer_address);
    stdin.write(&signature);
    stdin.write(&(THRESHOLD_AGE));
    stdin.write(&(chrono::Utc::now().timestamp() as u64));
    stdin.write(&message);
    stdin.write(&domain_separator);

    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(ADDRESS_ELF);
    
    // Generate PLONK proof by default
    let proof = client.prove(&pk, &stdin)
        .plonk()
        .run()?;

    Ok(ProofData {
        proof: hex::encode(proof.bytes()),
        public_inputs: hex::encode(proof.public_values),
        vkey_hash: vk.bytes32(),
        mode: "plonk".to_string(),
    })
}