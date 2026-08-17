use methods::{PREPROCESS_GUEST_ELF, PREPROCESS_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs};

#[derive(Serialize, Deserialize)]
struct PreprocessInput {
    ciphertext: Vec<u8>,
    sector: Vec<u8>,
    expected_client_hash: [u8; 32],
    expected_porep_input_hash: [u8; 32],
    file_id: String,
    job_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PreprocessJournal {
    client_ciphertext_hash: [u8; 32],
    porep_input_hash: [u8; 32],
    ciphertext_size: u32,
    sector_size: u32,
    padding_size: u32,
    binding_verified: bool,
    file_id: String,
    job_id: String,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::filter::EnvFilter::from_default_env(),
        )
        .init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 5 {
        eprintln!(
            "Usage: {} <ciphertext-path> <sector-path> <file-id> <job-id>",
            args[0]
        );
        std::process::exit(1);
    }

    let ciphertext_path = &args[1];
    let sector_path = &args[2];
    let file_id = &args[3];
    let job_id = &args[4];

    let ciphertext =
        fs::read(ciphertext_path).expect("failed to read stored ciphertext");

    let sector =
        fs::read(sector_path).expect("failed to read sector file");

    let expected_client_hash = sha256(&ciphertext);
    let expected_porep_input_hash = sha256(&sector);

    println!("Ciphertext path: {ciphertext_path}");
    println!("Sector path:     {sector_path}");
    println!("Ciphertext size: {}", ciphertext.len());
    println!("Sector size:     {}", sector.len());
    println!(
        "Client commitment: {}",
        to_hex(&expected_client_hash)
    );
    println!(
        "PoRep input hash:  {}",
        to_hex(&expected_porep_input_hash)
    );

    let input = PreprocessInput {
        ciphertext,
        sector,
        expected_client_hash,
        expected_porep_input_hash,
        file_id: file_id.clone(),
        job_id: job_id.clone(),
    };

    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    println!("Executing preprocessing proof program...");

    let prove_info = default_prover()
        .prove(env, PREPROCESS_GUEST_ELF)
        .expect("zkVM preprocessing proof failed");

    let receipt = prove_info.receipt;

    let journal: PreprocessJournal =
        receipt.journal.decode().expect("failed to decode journal");

    receipt
        .verify(PREPROCESS_GUEST_ID)
        .expect("receipt verification failed");

    assert_eq!(
        journal.client_ciphertext_hash,
        expected_client_hash,
        "journal client commitment mismatch"
    );

    assert_eq!(
        journal.porep_input_hash,
        expected_porep_input_hash,
        "journal PoRep input hash mismatch"
    );

    assert!(
        journal.binding_verified,
        "guest did not verify input binding"
    );

    assert!(
        journal.file_id == *file_id,
        "journal file ID mismatch"
    );

    assert!(
        journal.job_id == *job_id,
        "journal job ID mismatch"
    );

    println!();
    println!("===== zkVM Preprocessing Result =====");
    println!("Receipt verified:       true");
    println!("Input binding verified: {}", journal.binding_verified);
    println!("Ciphertext size:        {}", journal.ciphertext_size);
    println!("Sector size:            {}", journal.sector_size);
    println!("Padding size:           {}", journal.padding_size);
    println!(
        "Client commitment:      {}",
        to_hex(&journal.client_ciphertext_hash)
    );
    println!(
        "PoRep input hash:       {}",
        to_hex(&journal.porep_input_hash)
    );

    let dev_mode =
        env::var("RISC0_DEV_MODE").unwrap_or_default() == "1";

    if dev_mode {
        println!();
        println!("Dev Mode: receipt was NOT saved because it is not cryptographically valid.");
    } else {
        let receipt_path =
            format!("preprocessing-{}.receipt", job_id);

        let receipt_bytes =
            bincode::serialize(&receipt)
                .expect("failed to serialize receipt");

        fs::write(&receipt_path, &receipt_bytes)
            .expect("failed to save receipt");

        println!();
        println!("Valid receipt saved: {}", receipt_path);
        println!("Receipt size:         {} bytes", receipt_bytes.len());
    }
    println!("File ID:                {}", journal.file_id);
    println!("PoRep Job ID:           {}", journal.job_id);

}