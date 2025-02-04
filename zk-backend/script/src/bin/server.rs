use actix_web::{web, App, HttpResponse, HttpServer, Result};
use actix_multipart::Multipart;
use futures::{StreamExt, TryStreamExt};
use std::fs;
use std::path::Path;
use uuid::Uuid;
use std::process::Command;


pub async fn handle_proof_generation(mut payload: Multipart) -> Result<HttpResponse> {
    // Create temporary directory for input files if it doesn't exist
    let temp_dir = Path::new("temp_inputs");
    if !temp_dir.exists() {
        fs::create_dir_all(temp_dir).map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to create temp directory: {}", e))
        })?;
    }

    // Generate unique filename
    let input_filename = format!("temp_inputs/input_{}.json", Uuid::new_v4());

    // Process uploaded file
    while let Ok(Some(mut field)) = payload.try_next().await {
        let mut file_content = Vec::new();
        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!("Failed to read chunk: {}", e))
            })?;
            file_content.extend_from_slice(&data);
        }

        // Write the file
        fs::write(&input_filename, &file_content).map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to write file: {}", e))
        })?;

        // Generate proof using the zkVM logic
        if let Err(e) = generate_proof(&input_filename).await {
            eprintln!("Initial proof generation failed: {}", e);
        }

        // Run the proof generation command
        let output = Command::new("sh")
            .arg("-c")
            .arg("SP1_PROVER=network \
                  NETWORK_PRIVATE_KEY=0xfe513d8088442654ae6db6a23998f698100e34d43c9d6c105743590de0ae1e88 \
                  NETWORK_RPC_URL=https://rpc.production.succinct.xyz \
                  RUST_LOG=info \
                  cargo run --release --bin main -- --prove")
            .current_dir("/home/gautam/Desktop/AirProof/zk-backend/script")
            .output()
            .expect("Failed to execute command");

        if output.status.success() {
            println!("Proof generation successful!");
            println!("{}", String::from_utf8_lossy(&output.stdout));
            
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "message": "Proof generated successfully"
            })));
        } else {
            eprintln!("Proof generation failed:");
            eprintln!("{}", String::from_utf8_lossy(&output.stderr));
            
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Proof generation failed: {}", 
                    String::from_utf8_lossy(&output.stderr))
            })));
        }
    }

    Ok(HttpResponse::BadRequest().json(serde_json::json!({
        "status": "error",
        "message": "No file uploaded"
    })))
}

pub async fn start_server() -> std::io::Result<()> {
    println!("Starting server at http://127.0.0.1:8080");
    
    HttpServer::new(|| {
        App::new()
            .route("/generate-proof", web::post().to(handle_proof_generation))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    start_server().await
} 