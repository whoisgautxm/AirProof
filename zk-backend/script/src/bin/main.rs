mod structs;
use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer, Result};
use clap::Parser;
use ethers_core::abi::Token;
use ethers_core::types::transaction::eip712::EIP712Domain;
use ethers_core::types::{Signature, H160, H256};
use ethers_core::utils::keccak256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sp1_sdk::{
    include_elf, utils, ProverClient, SP1Stdin,SP1ProofWithPublicValues,HashableKey
};
use sp1_sdk::Prover;
use std::fs;
use std::path::Path;
use structs::{Attest, InputData};
use dotenv::dotenv;

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
    #[arg(
        long,
        default_value_t = false,
        help = "Generate or use pregenerated proof"
    )]
    prove: bool,
    #[arg(
        long,
        default_value = "plonk",
        help = "Proof mode (e.g., groth16, plonk)"
    )]
    mode: String,
}

async fn save_input(json: web::Json<Value>) -> Result<HttpResponse> {
    // Create directory if it doesn't exist
    let dir_path = Path::new("src/bin");
    if !dir_path.exists() {
        fs::create_dir_all(dir_path).map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to create directory: {}", e))
        })?;
    }

    // Save the JSON to input.json
    let file_path = dir_path.join("input.json");
    fs::write(&file_path, serde_json::to_string_pretty(&json.0).unwrap()).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Failed to write file: {}", e))
    })?;

    Ok(HttpResponse::Ok().json(json.0))
}

fn parse_input_data(file_path: &str) -> InputData {
    let json_str = fs::read_to_string(file_path).expect("Failed to read input file");
    serde_json::from_str(&json_str).expect("Failed to parse JSON input")
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
        chain_id: Some(
            ethers_core::types::U256::from_dec_str(&input_data.sig.domain.chain_id).unwrap(),
        ),
        verifying_contract: Some(input_data.sig.domain.verifying_contract.parse().unwrap()),
        salt: None,
    };
    domain_separator(
        &domain,
        ethers_core::utils::keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        )
        .into(),
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

async fn generate_proof(mode: String) -> Result<HttpResponse> {


    utils::setup_logger();
    let input_data = parse_input_data("/Users/shivanshgupta/Desktop/AirProof/AirProof/zk-backend/script/src/bin/input.json");

    let signer_address: H160 = input_data.signer.parse().unwrap();
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

    let client = ProverClient::builder()
        .network()
        .private_key("0xfe513d8088442654ae6db6a23998f698100e34d43c9d6c105743590de0ae1e88")
        .rpc_url("https://rpc.production.succinct.xyz")
        .build();
    let (pk, vk) = client.setup(ADDRESS_ELF);


    // Request a proof with reserved prover network capacity and wait for it to be fulfilled

    let proof_path = format!("../binaries/DOB-Attestaion_{}_proof.bin", mode);
    let json_path = format!("../json/DOB-Attestaion_{}_proof.json", mode);
    let mode = "groth16";

    let proof =  client
            .prove(&pk, &stdin)
            .groth16()
            .skip_simulation(false)
            .run_async()
            .await
            .expect("Groth16 proof generation failed");
    
    client.verify(&proof, &vk).expect("verification failed");
    println!("Successfully verified proof!");
    proof.save(&proof_path).expect("Failed to save proof");

    let proof = SP1ProofWithPublicValues::load(&proof_path).expect("Failed to load proof");
    let fixture = ProofData {
        proof: hex::encode(proof.bytes()),
        public_inputs: hex::encode(proof.public_values),
        vkey_hash: vk.bytes32(),
        mode: mode.to_string(),
    };

    fs::write(
        &json_path,
        serde_json::to_string(&fixture).expect("Failed to serialize proof"),
    )
    .expect("Failed to write JSON proof");

    Ok(HttpResponse::Ok().json(fixture))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();  // Load .env file
    println!("Server starting at http://localhost:8080");

    HttpServer::new(|| {
        let cors = Cors::permissive();

        App::new()
            .wrap(cors)
            .route("/save-input", web::post().to(save_input))
            .route("/generate-proof", web::post().to(generate_proof))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
