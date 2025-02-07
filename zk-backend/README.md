## Github Links 
- ZK-Backend - https://github.com/whoisgautxm/AirProof
- Contracts - https://github.com/Shivannsh/airproof-fhe
- Walkthrough Video - https://youtu.be/pxyek5mhxMA

# SP1 Project Template

This is a template for creating an end-to-end [SP1](https://github.com/succinctlabs/sp1) project
that can generate a proof of any RISC-V program.

## Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://docs.succinct.xyz/getting-started/install.html)

## Running the Project

There are four main ways to run this project: build a program, execute a program, generate a core proof, and
generate an EVM-compatible proof.

### Build the Program

To build the program, run the following command:

```sh
cd program
cargo prove build
```

### Execute the Program

To run the server in the script directory without generating a proof:

```sh
cd script
cargo run --bin server
```

### Retrieve the Verification Key

To retrieve your `programVKey` for your on-chain contract, run the following command in `script`:

```sh
cargo run --release --bin vkey
```

## Using the Prover Network

We highly recommend using the Succinct prover network for any non-trivial programs or benchmarking purposes. For more information, see the [setup guide](https://docs.succinct.xyz/docs/generating-proofs/prover-network).

To get started, copy the example environment file:

```sh
cp .env.example .env
```

Set the `NETWORK_PRIVATE_KEY` environment variable to your whitelisted private key.

For example, to generate an EVM-compatible proof using the prover network, run the following
command:

```sh
SP1_PROVER=network NETWORK_PRIVATE_KEY=... cargo run --release --bin evm
```

## API Endpoints

The backend provides two main REST API endpoints for handling zk-proof generation:

### 1. Save Input Data

- **Endpoint**: `POST /save-input`
- **Purpose**: Store JSON input data for proof generation
- **Request**:
  ```bash
  curl -X POST http://localhost:8080/save-input \
    -H "Content-Type: application/json" \
    -d @src/bin/input.json
  ```
- **Response**: Returns the saved JSON data
- **File Handling**: Saves to `src/bin/input.json`

### 2. Generate Proof

- **Endpoint**: `POST /generate-proof`
- **Purpose**: Generate zk-proof using previously saved input
- **Request**:
  ```bash
  curl -X POST http://localhost:8080/generate-proof
  ```
- **Response**:
  ```json
  {
    "proof": "<hex_string>",
    "public_inputs": "<hex_string>",
    "vkey_hash": "<verification_key_hash>",
    "mode": "groth16",
    "signer_address": "...",
    "recipient_address": "...",
    "first_name": "...",
    "last_name": "...",
    "date_of_birth": 1738842536,
    "adhaar_number": 1234567890
  }
  ```
- **Outputs**:
  - Binary proof in `../binaries/`
  - JSON proof in `../json/`
