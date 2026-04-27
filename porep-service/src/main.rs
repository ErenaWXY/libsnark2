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
};
use tokio::process::Command;
use uuid::Uuid;

#[derive(Clone, Default)]
struct AppState {
    jobs: Arc<Mutex<HashMap<String, JobRecord>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JobRecord {
    job_id: String,
    state: String, // pending | sealing | staged | proved | failed
    file_id: Option<String>,
    input_path: Option<String>,
    cache_dir: String,
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
    stdout: Option<String>,
    stderr: Option<String>,
    error: Option<String>,
}

async fn health() -> &'static str {
    "ok"
}

async fn seal_test(
    State(state): State<AppState>,
) -> Result<Json<SealTestResponse>, (StatusCode, String)> {
    let job_id = Uuid::new_v4().to_string();
    let cache_dir = format!("/home/erena/libsnark2/porep-cache/{}", job_id);

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
        let benchy_path = "/home/erena/libsnark2/third_party/rust-fil-proofs/target/release/benchy";

        let mut cmd = Command::new(benchy_path);

        cmd.arg("porep")
            .arg("--size")
            .arg("2KiB")
            .arg("--cache")
            .arg(&cache_dir_clone)
            .env(
                "FIL_PROOFS_PARAMETER_CACHE",
                "/home/erena/libsnark2/proof-params",
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
    let cache_dir = format!("/home/erena/libsnark2/porep-cache/{}", job_id);

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
        let helper_path = "/home/erena/libsnark2/porep-service/target/debug/real_seal_2k";

        let mut cmd = Command::new(helper_path);

        cmd.arg("--file-id")
            .arg(&file_id_clone)
            .arg("--input-path")
            .arg(&input_path_clone)
            .arg("--cache-dir")
            .arg(&cache_dir_clone);

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
                    job.state = "staged".to_string();
                } else {
                    job.state = "failed".to_string();
                    job.error = Some("real_seal_2k returned non-zero exit code".to_string());
                }
            }
            Err(e) => {
                job.state = "failed".to_string();
                job.error = Some(format!("failed to execute real_seal_2k: {}", e));
            }
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
        stdout: job.stdout.clone(),
        stderr: job.stderr.clone(),
        error: job.error.clone(),
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
        .with_state(state);

    let addr: SocketAddr = "127.0.0.1:8787".parse().unwrap();
    println!("PoRep service running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}