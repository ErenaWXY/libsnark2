use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    fs,
    path::PathBuf,
};
use tokio::process::Command;
use std::time::Instant;
use uuid::Uuid;

#[derive(Clone, Default)]
struct AppState {
    jobs: Arc<Mutex<HashMap<String, JobRecord>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SectorRecord {
    sector_index: usize,
    input_path: String,
    input_hash: String,
    comm_d: Option<String>,
    comm_r: Option<String>,
    sector_id: Option<String>,
    prover_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JobRecord {
    job_id: String,
    state: String, // pending | sealing | staged | proved | failed
    file_id: Option<String>,
    input_path: Option<String>,
    cache_dir: String,
    sector_size: Option<usize>,
    sector_count: Option<usize>,
    input_hash: Option<String>,
    sectorization_verified: Option<bool>,
    sector_records: Vec<SectorRecord>,
    comm_d: Option<String>,
    comm_r: Option<String>,
    sector_id: Option<String>,
    prover_id: Option<String>,
    stdout: Option<String>,
    stderr: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct SealTestResponse {
    job_id: String,
    state: String,
    cache_dir: String,
}

#[derive(Debug, Deserialize)]
struct SealFileRequest {
    file_id: String,
    path: String,
}

#[derive(Debug, Serialize)]
struct SealFileResponse {
    job_id: String,
    state: String,
    file_id: String,
    input_path: String,
    cache_dir: String,
}

#[derive(Debug, Serialize)]
struct JobResponse {
    job_id: String,
    state: String,
    file_id: Option<String>,
    input_path: Option<String>,
    cache_dir: String,
    sector_size: Option<usize>,
    sector_count: Option<usize>,
    input_hash: Option<String>,
    sectorization_verified: Option<bool>,
    sector_records: Vec<SectorRecord>,
    comm_d: Option<String>,
    comm_r: Option<String>,
    sector_id: Option<String>,
    prover_id: Option<String>,
    stdout: Option<String>,
    stderr: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct WindowPostResponse {
    job_id: String,
    post_type: String,
    sector_count: usize,
    verified: bool,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize)]
struct VcVerifyResponse {
    job_id: String,
    verification_type: String,
    receipt_path: String,
    verified: bool,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize)]
struct VcProveResponse {
    job_id: String,
    proof_type: String,
    receipt_path: String,
    generated: bool,
    generation_seconds: f64,
    receipt_size: Option<u64>,
    stdout: String,
    stderr: String,
}

fn parse_named_value(text: &str, names: &[&str]) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        for name in names {
            let target = name.to_ascii_lowercase();
            if let Some(pos) = lower.find(&target) {
                let rest = &line[pos + name.len()..];
                let value = rest
                    .trim_start_matches(|c: char| c == ' ' || c == ':' || c == '=' || c == '\"')
                    .trim_end_matches(|c: char| c == ' ' || c == ',' || c == '\"' || c == '}')
                    .trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

async fn sha256_path(path: &str) -> Option<String> {
    let output = Command::new("sha256sum").arg(path).output().await.ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(|s| s.to_string())
}

async fn health() -> &'static str {
    "ok"
}

async fn seal_test(
    State(state): State<AppState>,
) -> Result<Json<SealTestResponse>, (StatusCode, String)> {
    let job_id = Uuid::new_v4().to_string();
    let cache_dir = format!("/home/xinyue/libsnark2/porep-cache/{}", job_id);

    {
        let mut jobs = state.jobs.lock().unwrap();
        jobs.insert(
            job_id.clone(),
            JobRecord {
                job_id: job_id.clone(),
                state: "sealing".to_string(),
                file_id: None,
                input_path: None,
                cache_dir: cache_dir.clone(),
                sector_size: None,
                sector_count: None,
                input_hash: None,
                sectorization_verified: None,
                sector_records: Vec::new(),
                comm_d: None,
                comm_r: None,
                sector_id: None,
                prover_id: None,
                stdout: None,
                stderr: None,
                error: None,
            },
        );
    }

    let state_clone = state.clone();
    let job_id_clone = job_id.clone();
    let cache_dir_clone = cache_dir.clone();

    tokio::spawn(async move {
        let benchy_path = "/home/xinyue/libsnark2/third_party/rust-fil-proofs/target/release/benchy";

        let mut cmd = Command::new(benchy_path);

        cmd.arg("porep")
            .arg("--size")
            .arg("2KiB")
            .arg("--cache")
            .arg(&cache_dir_clone)
            .env(
                "FIL_PROOFS_PARAMETER_CACHE",
                "/home/xinyue/libsnark2/proof-params",
            )
            .env("RUST_LOG", "info");
            
        let output = cmd.output().await;

        let mut jobs = state_clone.jobs.lock().unwrap();
        let Some(job) = jobs.get_mut(&job_id_clone) else {
            return;
        };

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();

                job.stdout = Some(stdout);
                job.stderr = Some(stderr);

                if out.status.success() {
                    job.state = "proved".to_string();
                } else {
                    job.state = "failed".to_string();
                    job.error = Some("benchy returned non-zero exit code".to_string());
                }
            }
            Err(e) => {
                job.state = "failed".to_string();
                job.error = Some(format!("failed to execute benchy: {}", e));
            }
        }
    });

    Ok(Json(SealTestResponse {
        job_id,
        state: "sealing".to_string(),
        cache_dir,
    }))
}

async fn seal_file(
    State(state): State<AppState>,
    Json(req): Json<SealFileRequest>,
) -> Result<Json<SealFileResponse>, (StatusCode, String)> {
    let job_id = Uuid::new_v4().to_string();
    let cache_dir = format!("/home/xinyue/libsnark2/porep-cache/{}", job_id);

    {
        let mut jobs = state.jobs.lock().unwrap();
        jobs.insert(
            job_id.clone(),
            JobRecord {
                job_id: job_id.clone(),
                state: "sealing".to_string(),
                file_id: Some(req.file_id.clone()),
                input_path: Some(req.path.clone()),
                cache_dir: cache_dir.clone(),
                sector_size: None,
                sector_count: None,
                input_hash: None,
                sectorization_verified: None,
                sector_records: Vec::new(),
                comm_d: None,
                comm_r: None,
                sector_id: None,
                prover_id: None,
                stdout: None,
                stderr: None,
                error: None,
            },
        );
    }

    let state_clone = state.clone();
    let job_id_clone = job_id.clone();
    let file_id_clone = req.file_id.clone();
    let input_path_clone = req.path.clone();
    let cache_dir_clone = cache_dir.clone();

    tokio::spawn(async move {
        let helper_path = "/home/xinyue/libsnark2/porep-service/target/debug/real_seal_2k";
        let sector_size: usize = 2048; // 2KiB sector
        // let helper_path = "/home/xinyue/libsnark2/porep-service/target/debug/real_seal_8m";
        // let sector_size: usize = 8 * 1024 * 1024;

        println!(">>> START seal-whole-file job_id = {}", job_id_clone);
        println!(">>> input_path = {}", input_path_clone);
        println!(">>> sector_size = {} bytes", sector_size);

        let total_start = Instant::now();

        let input_data = match fs::read(&input_path_clone) {
            Ok(data) => data,
            Err(e) => {
                let mut jobs = state_clone.jobs.lock().unwrap();
                if let Some(job) = jobs.get_mut(&job_id_clone) {
                    job.state = "failed".to_string();
                    job.error = Some(format!("failed to read input file: {}", e));
                }
                return;
            }
        };

        let file_size = input_data.len();
        let total_sectors = (file_size + sector_size - 1) / sector_size;
        let input_hash = sha256_path(&input_path_clone).await;

        {
            let mut jobs = state_clone.jobs.lock().unwrap();
            if let Some(job) = jobs.get_mut(&job_id_clone) {
                job.sector_size = Some(sector_size);
                job.sector_count = Some(total_sectors);
                job.input_hash = input_hash.clone();
                job.sectorization_verified = Some(false);
            }
        }

        println!(">>> file_size = {} bytes", file_size);
        println!(">>> total_sectors = {}", total_sectors);

        let mut all_stdout = String::new();
        let mut all_stderr = String::new();
        let mut sectorization_verified = true;

        for sector_index in 0..total_sectors {
            let start = sector_index * sector_size;
            let end = std::cmp::min(start + sector_size, file_size);

            let mut chunk = input_data[start..end].to_vec();

            // pad last sector to 2KiB
            if chunk.len() < sector_size {
                chunk.resize(sector_size, 0);
            }

            let chunk_path = PathBuf::from(format!(
                "{}/sector_{}.bin",
                cache_dir_clone,
                sector_index
            ));
            let chunk_path_string = chunk_path.to_string_lossy().to_string();

            if let Some(parent) = chunk_path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            if let Err(e) = fs::write(&chunk_path, &chunk) {
                let mut jobs = state_clone.jobs.lock().unwrap();
                if let Some(job) = jobs.get_mut(&job_id_clone) {
                    job.state = "failed".to_string();
                    job.error = Some(format!("failed to write sector chunk: {}", e));
                }
                return;
            }

            match fs::read(&chunk_path) {
                Ok(saved_chunk) => {
                    let data_len = end - start;
                    let data_matches = saved_chunk.get(..data_len) == Some(&input_data[start..end]);
                    let padding_is_zero = saved_chunk
                        .get(data_len..)
                        .map(|padding| padding.iter().all(|b| *b == 0))
                        .unwrap_or(false);
                    if saved_chunk.len() != sector_size || !data_matches || !padding_is_zero {
                        sectorization_verified = false;
                    }
                }
                Err(_) => sectorization_verified = false,
            }

            println!(
                ">>> sealing sector {}/{}: {}",
                sector_index + 1,
                total_sectors,
                chunk_path.display()
            );

            // Bind the exact bytes passed to real_seal_2k to this job. The
            // hash is checked again after the helper exits to detect a sector
            // file being replaced while sealing is in progress.
            let sector_input_hash = match sha256_path(&chunk_path_string).await {
                Some(hash) => hash,
                None => {
                    let mut jobs = state_clone.jobs.lock().unwrap();
                    if let Some(job) = jobs.get_mut(&job_id_clone) {
                        job.state = "failed".to_string();
                        job.error = Some(format!(
                            "failed to hash PoRep input for sector {}",
                            sector_index
                        ));
                    }
                    return;
                }
            };

            let sector_start = Instant::now();

            let output = Command::new(helper_path)
                .arg("--file-id")
                .arg(format!("{}_sector_{}", file_id_clone, sector_index))
                .arg("--input-path")
                .arg(&chunk_path_string)
                .arg("--cache-dir")
                .arg(format!("{}/sector_{}", cache_dir_clone, sector_index))
                .output()
                .await;

            let sector_duration = sector_start.elapsed();

            println!(
                ">>> sector {}/{} sealing time: {:.3} s",
                sector_index + 1,
                total_sectors,
                sector_duration.as_secs_f64()
            );

            match output {
                Ok(out) => {
                    all_stdout.push_str(&format!(
                        "\n===== sector {} stdout =====\n{}",
                        sector_index,
                        String::from_utf8_lossy(&out.stdout)
                    ));
                    all_stderr.push_str(&format!(
                        "\n===== sector {} stderr =====\n{}",
                        sector_index,
                        String::from_utf8_lossy(&out.stderr)
                    ));

                    let combined_output = format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&out.stdout),
                        String::from_utf8_lossy(&out.stderr)
                    );
                    let parsed_comm_d = parse_named_value(&combined_output, &["comm_d", "commD"]);
                    let parsed_comm_r = parse_named_value(&combined_output, &["comm_r", "commR"]);
                    let parsed_sector_id = parse_named_value(&combined_output, &["sector_id", "sectorId"]);
                    let parsed_prover_id = parse_named_value(&combined_output, &["prover_id", "proverId"]);

                    let post_seal_hash = sha256_path(&chunk_path_string).await;
                    if post_seal_hash.as_deref() != Some(sector_input_hash.as_str()) {
                        let mut jobs = state_clone.jobs.lock().unwrap();
                        if let Some(job) = jobs.get_mut(&job_id_clone) {
                            job.state = "failed".to_string();
                            job.stdout = Some(all_stdout);
                            job.stderr = Some(all_stderr);
                            job.error = Some(format!(
                                "PoRep input changed while sealing sector {}",
                                sector_index
                            ));
                        }
                        return;
                    }

                    {
                        let mut jobs = state_clone.jobs.lock().unwrap();
                        if let Some(job) = jobs.get_mut(&job_id_clone) {
                            if parsed_comm_d.is_some() { job.comm_d = parsed_comm_d.clone(); }
                            if parsed_comm_r.is_some() { job.comm_r = parsed_comm_r.clone(); }
                            if parsed_sector_id.is_some() { job.sector_id = parsed_sector_id.clone(); }
                            if parsed_prover_id.is_some() { job.prover_id = parsed_prover_id.clone(); }

                            job.sector_records.push(SectorRecord {
                                sector_index,
                                input_path: chunk_path_string.clone(),
                                input_hash: sector_input_hash.clone(),
                                comm_d: parsed_comm_d,
                                comm_r: parsed_comm_r,
                                sector_id: parsed_sector_id,
                                prover_id: parsed_prover_id,
                            });
                        }
                    }

                    if !out.status.success() {
                        let mut jobs = state_clone.jobs.lock().unwrap();
                        if let Some(job) = jobs.get_mut(&job_id_clone) {
                            job.state = "failed".to_string();
                            job.stdout = Some(all_stdout);
                            job.stderr = Some(all_stderr);
                            job.error = Some(format!(
                                "real_seal_2k failed at sector {}",
                                sector_index
                            ));
                        }
                        return;
                    }
                }
                Err(e) => {
                    let mut jobs = state_clone.jobs.lock().unwrap();
                    if let Some(job) = jobs.get_mut(&job_id_clone) {
                        job.state = "failed".to_string();
                        job.stdout = Some(all_stdout);
                        job.stderr = Some(all_stderr);
                        job.error = Some(format!("failed to execute real_seal_2k: {}", e));
                    }
                    return;
                }
            }
        }

        let total_duration = total_start.elapsed();

        println!(">>> FINISH seal-whole-file job_id = {}", job_id_clone);
        println!(">>> Whole-file sealing time: {:.3} s", total_duration.as_secs_f64());

        let mut jobs = state_clone.jobs.lock().unwrap();
        if let Some(job) = jobs.get_mut(&job_id_clone) {
            job.state = "proved".to_string();
            job.sectorization_verified = Some(sectorization_verified);
            job.stdout = Some(all_stdout);
            job.stderr = Some(all_stderr);
        }
    });

    Ok(Json(SealFileResponse {
        job_id,
        state: "sealing".to_string(),
        file_id: req.file_id,
        input_path: req.path,
        cache_dir,
    }))
}

async fn job_status(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<JobResponse>, (StatusCode, String)> {
    let jobs = state.jobs.lock().unwrap();
    let Some(job) = jobs.get(&job_id) else {
        return Err((StatusCode::NOT_FOUND, "job not found".to_string()));
    };

    Ok(Json(JobResponse {
        job_id: job.job_id.clone(),
        state: job.state.clone(),
        file_id: job.file_id.clone(),
        input_path: job.input_path.clone(),
        cache_dir: job.cache_dir.clone(),
        sector_size: job.sector_size,
        sector_count: job.sector_count,
        input_hash: job.input_hash.clone(),
        sectorization_verified: job.sectorization_verified,
        sector_records: job.sector_records.clone(),
        comm_d: job.comm_d.clone(),
        comm_r: job.comm_r.clone(),
        sector_id: job.sector_id.clone(),
        prover_id: job.prover_id.clone(),
        stdout: job.stdout.clone(),
        stderr: job.stderr.clone(),
        error: job.error.clone(),
    }))
}


async fn window_post_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<WindowPostResponse>, (StatusCode, String)> {
    let job = {
        let jobs = state.jobs.lock().unwrap();
        let Some(job) = jobs.get(&job_id) else {
            return Err((StatusCode::NOT_FOUND, "job not found".to_string()));
        };
        job.clone()
    };

    if job.state != "proved" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("job is not proved yet, current state = {}", job.state),
        ));
    }

    let mut sector_dirs: Vec<PathBuf> = fs::read_dir(&job.cache_dir)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read cache dir {}: {}", job.cache_dir, e),
            )
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|s| s.to_str())
                    .map(|name| name.starts_with("sector_"))
                    .unwrap_or(false)
        })
        .collect();

    sector_dirs.sort();

    if sector_dirs.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("no sector cache directories found under {}", job.cache_dir),
        ));
    }

    let benchy_path =
        "/home/xinyue/libsnark2/third_party/rust-fil-proofs/target/release/benchy";

    let mut all_stdout = String::new();
    let mut all_stderr = String::new();

    for sector_dir in &sector_dirs {
        let sector_name = sector_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("sector_unknown")
            .to_string();

        let tmp_dir = format!("/tmp/window-post-job-{}-{}", job_id, sector_name);

        // Always run WindowPoSt on a temporary copy, so the preserved PoRep cache is never damaged.
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to create tmp dir {}: {}", tmp_dir, e),
            )
        })?;

        // Use cp -a to preserve all cache artifacts exactly.
        let copy_status = Command::new("cp")
            .arg("-a")
            .arg(format!("{}/.", sector_dir.to_string_lossy()))
            .arg(&tmp_dir)
            .status()
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to copy sector cache: {}", e),
                )
            })?;

        if !copy_status.success() {
            let _ = fs::remove_dir_all(&tmp_dir);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to copy sector cache from {:?}", sector_dir),
            ));
        }

        let output = Command::new(benchy_path)
            .arg("window-post")
            .arg("--size")
            .arg("2KiB")
            .arg("--cache")
            .arg(&tmp_dir)
            .arg("--skip-precommit-phase1")
            .arg("--skip-precommit-phase2")
            .arg("--skip-commit-phase1")
            .arg("--skip-commit-phase2")
            .env(
                "FIL_PROOFS_PARAMETER_CACHE",
                "/home/xinyue/libsnark2/proof-params",
            )
            .env("RUST_LOG", "info")
            .output()
            .await
            .map_err(|e| {
                let _ = fs::remove_dir_all(&tmp_dir);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to run window-post: {}", e),
                )
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        all_stdout.push_str(&format!(
            "\n===== WindowPoSt {} stdout =====\n{}",
            sector_name, stdout
        ));
        all_stderr.push_str(&format!(
            "\n===== WindowPoSt {} stderr =====\n{}",
            sector_name, stderr
        ));

        let _ = fs::remove_dir_all(&tmp_dir);

        if !output.status.success() {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("WindowPoSt failed for {}\n{}", sector_name, stderr),
            ));
        }
    }

    Ok(Json(WindowPostResponse {
        job_id,
        post_type: "WindowPoSt".to_string(),
        sector_count: sector_dirs.len(),
        verified: true,
        stdout: all_stdout,
        stderr: all_stderr,
    }))
}

async fn vc_prove_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<VcProveResponse>, (StatusCode, String)> {
    let job = {
        let jobs = state.jobs.lock().unwrap();

        let Some(job) = jobs.get(&job_id) else {
            return Err((
                StatusCode::NOT_FOUND,
                "PoRep job not found".to_string(),
            ));
        };

        job.clone()
    };

    if job.state != "proved" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "PoRep job is not proved, current state = {}",
                job.state
            ),
        ));
    }

    if job.sector_records.len() != 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Current VC prototype supports exactly one sector; job contains {} sectors",
                job.sector_records.len()
            ),
        ));
    }

    let file_id = job.file_id.clone().ok_or((
        StatusCode::BAD_REQUEST,
        "PoRep job has no file ID".to_string(),
    ))?;

    let input_path = job.input_path.clone().ok_or((
        StatusCode::BAD_REQUEST,
        "PoRep job has no input path".to_string(),
    ))?;

    let sector = job
        .sector_records
        .iter()
        .find(|record| record.sector_index == 0)
        .ok_or((
            StatusCode::BAD_REQUEST,
            "PoRep job has no sector 0 record".to_string(),
        ))?;

    let receipt_path = format!(
        "{}/preprocessing-{}.receipt",
        job.cache_dir,
        job_id
    );

    // Remove only an older VC receipt for this exact job.
    if std::path::Path::new(&receipt_path).exists() {
        fs::remove_file(&receipt_path).map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to replace old VC receipt: {}", error),
            )
        })?;
    }

    let prover_path =
        "/home/xinyue/libsnark2/vc-preprocessing/target/release/host";

    let started = Instant::now();

    let output = Command::new(prover_path)
        .arg(&input_path)
        .arg(&sector.input_path)
        .arg(&file_id)
        .arg(&job_id)
        .current_dir(&job.cache_dir)
        .env("RISC0_DEV_MODE", "0")
        .env("RUST_LOG", "warn")
        .output()
        .await
        .map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to execute RISC Zero prover: {}", error),
            )
        })?;

    let generation_seconds = started.elapsed().as_secs_f64();

    let stdout =
        String::from_utf8_lossy(&output.stdout).to_string();

    let stderr =
        String::from_utf8_lossy(&output.stderr).to_string();

    let receipt_size = fs::metadata(&receipt_path)
        .ok()
        .map(|metadata| metadata.len());

    let generated =
        output.status.success() &&
        receipt_size.is_some();

    Ok(Json(VcProveResponse {
        job_id,
        proof_type:
            "RISC0_CRYPTOGRAPHIC_PREPROCESSING".to_string(),
        receipt_path,
        generated,
        generation_seconds,
        receipt_size,
        stdout,
        stderr,
    }))
}

async fn vc_verify_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<VcVerifyResponse>, (StatusCode, String)> {
    let job = {
        let jobs = state.jobs.lock().unwrap();

        let Some(job) = jobs.get(&job_id) else {
            return Err((
                StatusCode::NOT_FOUND,
                "PoRep job not found".to_string(),
            ));
        };

        job.clone()
    };

    if job.state != "proved" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "PoRep job is not proved, current state = {}",
                job.state
            ),
        ));
    }

    let file_id = job.file_id.clone().ok_or((
        StatusCode::BAD_REQUEST,
        "PoRep job has no file ID".to_string(),
    ))?;

    let client_hash = job.input_hash.clone().ok_or((
        StatusCode::BAD_REQUEST,
        "PoRep job has no input hash".to_string(),
    ))?;

    let sector = job
        .sector_records
        .iter()
        .find(|record| record.sector_index == 0)
        .ok_or((
            StatusCode::BAD_REQUEST,
            "PoRep job has no sector 0 record".to_string(),
        ))?;

    let receipt_path = format!(
        "{}/preprocessing-{}.receipt",
        job.cache_dir,
        job_id
    );

    if !std::path::Path::new(&receipt_path).exists() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("VC receipt not found: {}", receipt_path),
        ));
    }

    let verifier_path =
        "/home/xinyue/libsnark2/vc-preprocessing/target/release/verify";

    let output = Command::new(verifier_path)
        .arg(&receipt_path)
        .arg(&client_hash)
        .arg(&sector.input_hash)
        .arg(&file_id)
        .arg(&job_id)
        .output()
        .await
        .map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to execute VC verifier: {}", error),
            )
        })?;

    let stdout =
        String::from_utf8_lossy(&output.stdout).to_string();

    let stderr =
        String::from_utf8_lossy(&output.stderr).to_string();

    Ok(Json(VcVerifyResponse {
        job_id,
        verification_type:
            "RISC0_CRYPTOGRAPHIC_PREPROCESSING".to_string(),
        receipt_path,
        verified: output.status.success(),
        stdout,
        stderr,
    }))
}

#[tokio::main]
async fn main() {
    let state = AppState::default();

    let app = Router::new()
        .route("/health", get(health))
        .route("/seal-test", post(seal_test))
        .route("/seal-file", post(seal_file))
        .route("/jobs/:job_id", get(job_status))
        .route("/jobs/:job_id/window-post", post(window_post_job))
        .route("/jobs/:job_id/vc/prove", post(vc_prove_job))
        .route("/jobs/:job_id/vc/verify", post(vc_verify_job))
        .with_state(state);

    let addr: SocketAddr = "127.0.0.1:8787".parse().unwrap();
    println!("PoRep service running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
