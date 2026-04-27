use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Clone, Default)]
struct AppState {
    jobs: Arc<Mutex<HashMap<String, JobRecord>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JobRecord {
    job_id: String,
    file_id: String,
    file_path: String,
    state: String,
    comm_d: Option<String>,
    comm_r: Option<String>,
    proof: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SealRequest {
    file_id: String,
    path: String,
}

#[derive(Debug, Serialize)]
struct SealResponse {
    job_id: String,
    state: String,
    comm_d: Option<String>,
    comm_r: Option<String>,
    proof: Option<String>,
}

#[derive(Debug, Serialize)]
struct JobResponse {
    job_id: String,
    file_id: String,
    state: String,
    comm_d: Option<String>,
    comm_r: Option<String>,
    proof: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    job_id: String,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    ok: bool,
    message: String,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

async fn health() -> &'static str {
    "ok"
}

async fn seal(
    State(state): State<AppState>,
    Json(req): Json<SealRequest>,
) -> Result<Json<SealResponse>, (StatusCode, String)> {
    let job_id = Uuid::new_v4().to_string();

    let mut record = JobRecord {
        job_id: job_id.clone(),
        file_id: req.file_id.clone(),
        file_path: req.path.clone(),
        state: "sealing".to_string(),
        comm_d: None,
        comm_r: None,
        proof: None,
        error: None,
    };

    let file_bytes = match fs::read(&req.path) {
        Ok(b) => b,
        Err(e) => {
            record.state = "failed".to_string();
            record.error = Some(format!("read file failed: {}", e));
            state.jobs.lock().unwrap().insert(job_id.clone(), record);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "read file failed".to_string()));
        }
    };

    // comm_d = hash(original file)
    let comm_d = sha256_hex(&file_bytes);

    // replica_bytes = SHA256("replica:"+file_bytes)
    let mut replica_input = b"replica:".to_vec();
    replica_input.extend_from_slice(&file_bytes);
    let comm_r = sha256_hex(&replica_input);

    // proof = SHA256(file_id || comm_d || comm_r)
    let mut proof_input = req.file_id.as_bytes().to_vec();
    proof_input.extend_from_slice(comm_d.as_bytes());
    proof_input.extend_from_slice(comm_r.as_bytes());
    let proof = sha256_hex(&proof_input);

    record.state = "proved".to_string();
    record.comm_d = Some(comm_d.clone());
    record.comm_r = Some(comm_r.clone());
    record.proof = Some(proof.clone());

    state.jobs.lock().unwrap().insert(job_id.clone(), record);

    Ok(Json(SealResponse {
        job_id,
        state: "proved".to_string(),
        comm_d: Some(comm_d),
        comm_r: Some(comm_r),
        proof: Some(proof),
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
        file_id: job.file_id.clone(),
        state: job.state.clone(),
        comm_d: job.comm_d.clone(),
        comm_r: job.comm_r.clone(),
        proof: job.proof.clone(),
        error: job.error.clone(),
    }))
}

async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    let jobs = state.jobs.lock().unwrap();
    let Some(job) = jobs.get(&req.job_id) else {
        return Err((StatusCode::NOT_FOUND, "job not found".to_string()));
    };

    if job.state != "proved" {
        return Ok(Json(VerifyResponse {
            ok: false,
            message: "job is not in proved state".to_string(),
        }));
    }

    let file_bytes = match fs::read(&job.file_path) {
        Ok(b) => b,
        Err(e) => {
            return Ok(Json(VerifyResponse {
                ok: false,
                message: format!("cannot read stored file: {}", e),
            }))
        }
    };

    let comm_d_now = sha256_hex(&file_bytes);

    let mut replica_input = b"replica:".to_vec();
    replica_input.extend_from_slice(&file_bytes);
    let comm_r_now = sha256_hex(&replica_input);

    let mut proof_input = job.file_id.as_bytes().to_vec();
    proof_input.extend_from_slice(comm_d_now.as_bytes());
    proof_input.extend_from_slice(comm_r_now.as_bytes());
    let proof_now = sha256_hex(&proof_input);

    let ok = job.comm_d.as_deref() == Some(comm_d_now.as_str())
        && job.comm_r.as_deref() == Some(comm_r_now.as_str())
        && job.proof.as_deref() == Some(proof_now.as_str());

    Ok(Json(VerifyResponse {
        ok,
        message: if ok {
            "verification passed: stored file matches recorded proof".to_string()
        } else {
            "verification failed: stored file does not match recorded proof".to_string()
        },
    }))
}

#[tokio::main]
async fn main() {
    let state = AppState::default();

    let app = Router::new()
        .route("/health", get(health))
        .route("/seal", post(seal))
        .route("/jobs/:job_id", get(job_status))
        .route("/verify", post(verify))
        .with_state(state);

    let addr: SocketAddr = "127.0.0.1:8787".parse().unwrap();
    println!("PoRep service running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}