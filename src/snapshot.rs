//! Snapshots through QMP async jobs. QEMU needs a qcow2 node to hold the VM state; we lazily
//! attach a private sparse carrier image so even diskless guests can be snapshotted.
//! Job results are polled and the job's error string is checked (a "successful" call can still fail).

use crate::qmp::{Qmp, CALL_TIMEOUT};
use crate::Res;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};

const CARRIER: &str = "qmcp-snap";
const JOB_TIMEOUT: Duration = Duration::from_secs(60);

pub fn valid_tag(tag: &str) -> Res<()> {
    let ok = !tag.is_empty() && tag.len() <= 64 && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
    match ok {
        true => Ok(()),
        false => Err(format!("invalid snapshot name '{tag}' (letters, digits and _.- only)")),
    }
}

async fn ensure_carrier(qmp: &Qmp, dir: &Path) -> Res<()> {
    let nodes = qmp.exec("query-named-block-nodes", json!({}), CALL_TIMEOUT).await?;
    if nodes.as_array().is_some_and(|a| a.iter().any(|n| n["node-name"] == CARRIER)) {
        return Ok(());
    }
    let image = dir.join("snap-carrier.qcow2");
    let made = tokio::process::Command::new("qemu-img").args(["create", "-q", "-f", "qcow2"]).arg(&image).arg("64M").output().await.map_err(|e| format!("qemu-img: {e}"))?;
    if !made.status.success() {
        return Err(format!("qemu-img create failed: {}", String::from_utf8_lossy(&made.stderr).trim()));
    }
    let args = json!({"driver": "qcow2", "node-name": CARRIER, "file": {"driver": "file", "filename": image}});
    qmp.exec("blockdev-add", args, CALL_TIMEOUT).await.map(|_| ())
}

fn job_args(tag: &str) -> Value {
    json!({"tag": tag, "vmstate": CARRIER, "devices": [CARRIER]})
}

/// Start an async job command and wait for it to conclude; returns the job's error, if any, as Err.
async fn run_job(qmp: &Qmp, cmd: &str, mut args: Value) -> Res<()> {
    let job = format!("{cmd}-{}", std::process::id());
    args["job-id"] = json!(job);
    qmp.exec(cmd, args, CALL_TIMEOUT).await?;
    let deadline = Instant::now() + JOB_TIMEOUT;
    let outcome = loop {
        let jobs = qmp.exec("query-jobs", json!({}), CALL_TIMEOUT).await?;
        let entry = jobs.as_array().and_then(|a| a.iter().find(|j| j["id"] == job.as_str())).cloned();
        match entry {
            Some(j) if j["status"] == "concluded" => break j["error"].as_str().map_or(Ok(()), |e| Err(format!("{cmd}: {e}"))),
            None => break Ok(()),
            Some(_) if Instant::now() >= deadline => break Err(format!("{cmd}: job still running after {JOB_TIMEOUT:?}")),
            Some(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };
    let _ = qmp.exec("job-dismiss", json!({"id": job}), CALL_TIMEOUT).await;
    outcome
}

pub async fn save(qmp: &Qmp, dir: &Path, tag: &str) -> Res<()> {
    valid_tag(tag)?;
    ensure_carrier(qmp, dir).await?;
    run_job(qmp, "snapshot-save", job_args(tag)).await
}

pub async fn load(qmp: &Qmp, dir: &Path, tag: &str) -> Res<()> {
    valid_tag(tag)?;
    ensure_carrier(qmp, dir).await?;
    run_job(qmp, "snapshot-load", job_args(tag)).await
}

pub async fn delete(qmp: &Qmp, dir: &Path, tag: &str) -> Res<()> {
    valid_tag(tag)?;
    ensure_carrier(qmp, dir).await?;
    run_job(qmp, "snapshot-delete", json!({"tag": tag, "devices": [CARRIER]})).await
}

pub async fn list(qmp: &Qmp) -> Res<String> {
    qmp.hmp("info snapshots").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_validation() {
        assert!(valid_tag("t1_ok-2.x").is_ok());
        for bad in ["", "a b", "a;b", "../x", &"x".repeat(65)] {
            assert!(valid_tag(bad).is_err(), "{bad}");
        }
    }
}
