use methods::PREPROCESS_GUEST_ID;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};
use std::{env, fs};

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

fn parse_hash(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value)
        .expect("hash must be hexadecimal");

    bytes.try_into()
        .expect("hash must contain exactly 32 bytes")
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 6 {
        eprintln!(
            "Usage: {} <receipt> <client-hash> <porep-input-hash> <file-id> <job-id>",
            args[0]
        );
        std::process::exit(1);
    }

    let receipt_bytes =
        fs::read(&args[1]).expect("failed to read receipt");

    let receipt: Receipt =
        bincode::deserialize(&receipt_bytes)
            .expect("failed to deserialize receipt");

    // Verify the cryptographic proof and expected guest program.
    receipt
        .verify(PREPROCESS_GUEST_ID)
        .expect("cryptographic receipt verification failed");

    let journal: PreprocessJournal =
        receipt.journal.decode()
            .expect("failed to decode receipt journal");

    let expected_client_hash = parse_hash(&args[2]);
    let expected_porep_hash = parse_hash(&args[3]);
    let expected_file_id = &args[4];
    let expected_job_id = &args[5];

        println!("===== Independent VC Verification =====");
        println!("Cryptographic proof:    PASS");
        println!("Expected guest program: PASS");

        if journal.client_ciphertext_hash != expected_client_hash {
            println!("Client commitment:      FAIL");
            println!("Reason: receipt belongs to a different client commitment");
            std::process::exit(2);
        }

        println!("Client commitment:      PASS");

        if journal.porep_input_hash != expected_porep_hash {
            println!("PoRep input commitment: FAIL");
            println!("Reason: receipt belongs to a different PoRep input");
            std::process::exit(3);
        }

        println!("PoRep input commitment: PASS");
            if journal.file_id.as_str() != expected_file_id.as_str() {
                println!("File ID binding:        FAIL");
                println!("Reason: receipt belongs to a different file ID");
                std::process::exit(4);
            }

            println!("File ID binding:        PASS");

            if journal.job_id.as_str() != expected_job_id.as_str() {
                println!("PoRep Job ID binding:   FAIL");
                println!("Reason: receipt belongs to a different PoRep job");
                std::process::exit(5);
            }

            println!("PoRep Job ID binding:   PASS");

        if !journal.binding_verified {
            println!("Input binding:          FAIL");
            std::process::exit(6);
        }

        println!("Input binding:          PASS");
        println!("Ciphertext was read:    false");
        println!("Sector was read:        false");
}