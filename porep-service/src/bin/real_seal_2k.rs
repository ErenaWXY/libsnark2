	
use serde::Serialize;
use std::{env, fs, path::PathBuf};

#[derive(Serialize)]
struct SealResult {
    ok: bool,
    file_id: String,
    input_path: String,
    cache_dir: String,
    sector_size: u64,
    message: String,
}

fn main() {
    let mut file_id = String::new();
    let mut input_path = String::new();
    let mut cache_dir = String::new();

    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--file-id" => file_id = args.next().unwrap_or_default(),
            "--input-path" => input_path = args.next().unwrap_or_default(),
            "--cache-dir" => cache_dir = args.next().unwrap_or_default(),
            _ => {}
        }
    }

    if file_id.is_empty() || input_path.is_empty() || cache_dir.is_empty() {
        eprintln!("missing required args");
        std::process::exit(2);
    }

    let input = PathBuf::from(&input_path);

    let input_bytes =
        fs::read(&input).expect("failed to read input file");

    fs::create_dir_all(&cache_dir)
        .expect("failed to create cache dir");

    let sector_size: usize = 2048;

    let mut staged = vec![0u8; sector_size];

    let copy_len = input_bytes.len().min(sector_size);

    staged[..copy_len]
        .copy_from_slice(&input_bytes[..copy_len]);

    let staged_path =
        PathBuf::from(&cache_dir).join("staged-file");

    fs::write(&staged_path, &staged)
        .expect("failed to write staged-file");

    let result = SealResult {
        ok: true,
        file_id,
        input_path,
        cache_dir,
        sector_size: 2048,
        message: format!(
            "staged payload ready: copied {} bytes into 2KiB sector",
            copy_len
        ),
    };

    println!(
        "{}",
        serde_json::to_string(&result).unwrap()
    );
}
