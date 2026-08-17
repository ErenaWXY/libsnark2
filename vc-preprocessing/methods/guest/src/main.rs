use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SECTOR_SIZE: usize = 2048;

#[derive(Serialize, Deserialize)]
struct PreprocessInput {
    ciphertext: Vec<u8>,
    sector: Vec<u8>,
    expected_client_hash: [u8; 32],
    expected_porep_input_hash: [u8; 32],
    file_id: String,
    job_id: String,
}

#[derive(Serialize, Deserialize)]
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

fn main() {
    let input: PreprocessInput = env::read();

    assert!(
        !input.file_id.is_empty() && input.file_id.len() <= 128,
        "invalid file ID"
    );

    assert!(
        !input.job_id.is_empty() && input.job_id.len() <= 128,
        "invalid PoRep job ID"
    );

    assert!(
        input.ciphertext.len() <= SECTOR_SIZE,
        "ciphertext is larger than one sector"
    );

    assert_eq!(
        input.sector.len(),
        SECTOR_SIZE,
        "sector must be exactly 2048 bytes"
    );

    let client_hash = sha256(&input.ciphertext);
    let sector_hash = sha256(&input.sector);

    assert_eq!(
        client_hash,
        input.expected_client_hash,
        "ciphertext does not match client commitment"
    );

    assert_eq!(
        sector_hash,
        input.expected_porep_input_hash,
        "sector does not match PoRep input commitment"
    );

    let data_length = input.ciphertext.len();

    assert!(
        &input.sector[..data_length] == input.ciphertext.as_slice(),
        "sector content does not match ciphertext"
    );

    assert!(
        input.sector[data_length..]
            .iter()
            .all(|byte| *byte == 0),
        "sector padding is not zero"
    );

    let journal = PreprocessJournal {
        client_ciphertext_hash: client_hash,
        porep_input_hash: sector_hash,
        ciphertext_size: data_length as u32,
        sector_size: SECTOR_SIZE as u32,
        padding_size: (SECTOR_SIZE - data_length) as u32,
        binding_verified: true,
        file_id: input.file_id,
        job_id: input.job_id,
    };

    env::commit(&journal);
}