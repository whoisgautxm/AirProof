//! A program to verify an attestation's signature, age threshold, and output relevant data.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use ethers_core::abi::Token;
use ethers_core::types::{Address, RecoveryMessage, Signature, H160, H256};
use ethers_core::utils::keccak256;
use fibonacci_lib::PublicValuesStruct;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Attest {
    version: u16,
    schema: H256,
    recipient: Address,
    time: u64,
    expiration_time: u64,
    revocable: bool,
    ref_uid: H256,
    data: Vec<u8>,
    salt: H256,
}

fn hash_message(domain_separator: &H256, message: &Attest) -> H256 {
    let message_typehash = keccak256(
        b"Attest(uint16 version,bytes32 schema,address recipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,bytes32 salt)"
    );

    let encoded_message = ethers_core::abi::encode(&[
        Token::FixedBytes(message_typehash.to_vec()),
        Token::Uint(message.version.into()),
        Token::FixedBytes(message.schema.as_bytes().to_vec()),
        Token::Address(message.recipient),
        Token::Uint(message.time.into()),
        Token::Uint(message.expiration_time.into()),
        Token::Bool(message.revocable),
        Token::FixedBytes(message.ref_uid.as_bytes().to_vec()),
        Token::FixedBytes(keccak256(&message.data).to_vec()),
        Token::FixedBytes(message.salt.as_bytes().to_vec()),
    ]);

    keccak256(
        &[0x19, 0x01]
            .iter()
            .chain(domain_separator.as_bytes())
            .chain(&keccak256(&encoded_message))
            .cloned()
            .collect::<Vec<u8>>(),
    )
    .into()
}

pub fn main() {
    // Read inputs from the zkVM environment.
    let signer_address: H160 = sp1_zkvm::io::read();
    let signature: Signature = sp1_zkvm::io::read();
    let message: Attest = sp1_zkvm::io::read();
    let first_name: String = sp1_zkvm::io::read();
    let last_name: String = sp1_zkvm::io::read();
    let date_of_birth: u64 = sp1_zkvm::io::read();
    let adhaar_number: u64 = sp1_zkvm::io::read();
    let domain_separator: H256 = sp1_zkvm::io::read();


    let calculated_digest = hash_message(&domain_separator, &message);
    let recovered_address = signature
        .recover(RecoveryMessage::Hash(calculated_digest))
        .expect("Signature recovery failed");

    let signer_address_bytes: [u8; 20] = signer_address.into();
    let recipient_address_bytes: [u8; 20] = message.recipient.into();
   

    if signer_address != recovered_address {
        panic!("Invalid signature");
    } else {
        let public_values = PublicValuesStruct {
            signer_address: signer_address_bytes.into(),
            receipent_address: recipient_address_bytes.into(),
            first_name,
            last_name,
            date_of_birth,
            adhaar_number,
        };
        sp1_zkvm::io::commit_slice(&PublicValuesStruct::abi_encode(&public_values));
    }
}
