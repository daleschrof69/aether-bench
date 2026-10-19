//! Qualcomm EDL (Sahara / Firehose) wrapper — real operations via `edlclient`.
//!
//! `edlclient` (https://github.com/bkerler/edl — MIT) is the open-source
//! Qualcomm Sahara/Firehose client from the author of mtkclient. After
//! `pip install edlclient` it exposes the `edl` console command. Like
//! mtkclient / heimdall we shell out to it as a subprocess and stream its
//! output back over the JSON-RPC bridge.
//!
//! KNOWN LIMITATIONS (not bugs — Qualcomm Secure Boot constraints):
//! - Firehose operations need the correct signed loader (programmer) for the
//!   target SoC. `edlclient` bundles a large loader database, but newer/locked
//!   OEM devices (Secure Boot fused) require an OEM-signed loader we cannot
//!   ship. On those, edl reports a Sahara/auth error — surfaced to the user.
//! - Read operations (printgpt, partition read) work on most 9008 targets.

use anyhow::{anyhow, Context, Result};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc::UnboundedSender;

use crate::mtkclient::StreamLine;

/// Locate the `edl` console script installed by `pip install edlclient`.
fn find_edl() -> Result<String> {
    for candidate in ["edl", "edl.exe"] {
        if let Ok(out) = std::process::Command::new(candidate).arg("--help").output() {
            if out.status.success() {
                return Ok(candidate.to_string());
            }
        }
    }
    Err(anyhow!(
        "edl not found on PATH — install the Qualcomm client with:\n  \
         pip install --user edlclient\n\
         (same author as mtkclient; provides the `edl` command). On Windows, \
         bind the 9008 port to the Qualcomm QDLoader / libusb driver with Zadig."
    ))
}

/// Verify edlclient is available; returns a short identifying string.
pub fn check_edl() -> Result<String> {
    let bin = find_edl()?;
    // edlclient has no stable --version flag; presence on PATH is the signal.
    Ok(format!("edlclient ({bin})"))
}

/// One-shot (non-streaming) edlclient install for the CLI `setup` command.
pub async fn install_edl_once() -> Result<String> {
    let python = crate::mtkclient::python_bin()?;
    let out = Command::new(&python)
        .args(["-m", "pip", "install", "--user", "--upgrade", "edlclient"])
        .output()
        .await
        .context("failed to spawn pip")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        return Err(anyhow!("pip install edlclient failed:\n{}", text));
    }
    Ok(text)
}

/// Stream `pip install --user --upgrade edlclient` so the Setup Wizard can
/// show live progress. Returns the pip exit code.
pub async fn install_edl_streaming(tx: UnboundedSender<StreamLine>) -> Result<i32> {
    let python = crate::mtkclient::python_bin()?;
    let mut cmd = Command::new(&python);
    cmd.args(["-m", "pip", "install", "--user", "--upgrade", "edlclient"]);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let mut child: Child = cmd.spawn().context("failed to spawn pip")?;
    stream_child(&mut child, &tx).await;
    let status = child.wait().await.context("pip exited abnormally")?;
    drop(tx);
    Ok(status.code().unwrap_or(-1))
}

/// Spawn `edl ARGS...` and stream stdout/stderr through the channel.
pub async fn run_edl_streaming(args: &[&str], tx: UnboundedSender<StreamLine>) -> Result<i32> {
    let bin = find_edl()?;
    let mut cmd = Command::new(&bin);
    for a in args {
        cmd.arg(a);
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let mut child: Child = cmd.spawn().context("failed to spawn edl")?;
    stream_child(&mut child, &tx).await;
    let status = child.wait().await.context("edl exited abnormally")?;
    drop(tx);
    Ok(status.code().unwrap_or(-1))
}

/// Pipe a child's stdout+stderr into the StreamLine channel.
async fn stream_child(child: &mut Child, tx: &UnboundedSender<StreamLine>) {
    if let Some(stdout) = child.stdout.take() {
        let tx2 = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx2.send(StreamLine { stream: "stdout", line });
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let tx2 = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx2.send(StreamLine { stream: "stderr", line });
            }
        });
    }
}
