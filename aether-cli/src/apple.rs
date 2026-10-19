//! Apple DFU / Recovery wrapper — real checkm8 pwn + device info.
//!
//! Two open-source tools drive genuine Apple operations:
//!   * `irecovery` (libimobiledevice — LGPL) talks to devices in Recovery/DFU
//!     and reads ECID / serial / model (`irecovery -q`).
//!   * `gaster` (https://github.com/0x7ff/gaster — BSD) runs the checkm8 BootROM
//!     exploit (`gaster pwn`) on A5–A11 devices to enter pwned-DFU.
//!
//! KNOWN LIMITATIONS (honest scope):
//!   * checkm8 only covers A5–A11 SoCs (iPhone 5s … iPhone X). A12+ are NOT
//!     exploitable — gaster will report the device is unsupported.
//!   * Pwned-DFU is the entry point. A full activation-lock / Hello-screen
//!     removal needs a ramdisk workflow (palera1n-style) that is device- and
//!     iOS-specific and NOT bundled here. We wire the real pwn + info steps;
//!     anything beyond that must be run from the dedicated tooling.

use anyhow::{anyhow, Context, Result};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc::UnboundedSender;

use crate::mtkclient::StreamLine;

fn find_tool(names: &[&str], install_hint: &str) -> Result<String> {
    for candidate in names {
        if let Ok(out) = std::process::Command::new(candidate).arg("--help").output() {
            // Many of these print help to stderr and exit non-zero; treat a
            // successful spawn as "present".
            let _ = out;
            return Ok(candidate.to_string());
        }
    }
    Err(anyhow!("{} not found on PATH — {}", names[0], install_hint))
}

fn find_irecovery() -> Result<String> {
    find_tool(
        &["irecovery", "irecovery.exe"],
        "install libimobiledevice: macOS `brew install libimobiledevice`, \
         Linux `apt install libirecovery-utils`, Windows via the imobiledevice-net release.",
    )
}

fn find_gaster() -> Result<String> {
    find_tool(
        &["gaster", "gaster.exe"],
        "build it from https://github.com/0x7ff/gaster (`make`) and place the \
         binary on PATH. checkm8 supports A5–A11 devices only.",
    )
}

/// Report which Apple tools are available.
pub fn check_apple() -> Result<String> {
    let mut parts = Vec::new();
    if let Ok(b) = find_irecovery() {
        parts.push(format!("irecovery ({b})"));
    }
    if let Ok(b) = find_gaster() {
        parts.push(format!("gaster ({b})"));
    }
    if parts.is_empty() {
        return Err(anyhow!(
            "no Apple tools found — install irecovery (libimobiledevice) and gaster (checkm8)."
        ));
    }
    Ok(parts.join(", "))
}

async fn run_streaming(bin: &str, args: &[&str], tx: UnboundedSender<StreamLine>) -> Result<i32> {
    let mut cmd = Command::new(bin);
    for a in args {
        cmd.arg(a);
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let mut child: Child = cmd.spawn().with_context(|| format!("failed to spawn {bin}"))?;
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
    let status = child.wait().await.context("apple tool exited abnormally")?;
    drop(tx);
    Ok(status.code().unwrap_or(-1))
}

/// Read device info from Recovery/DFU (`irecovery -q`).
pub async fn read_info_streaming(tx: UnboundedSender<StreamLine>) -> Result<i32> {
    let bin = find_irecovery()?;
    run_streaming(&bin, &["-q"], tx).await
}

/// Run the checkm8 BootROM exploit to enter pwned-DFU (`gaster pwn`).
pub async fn pwn_dfu_streaming(tx: UnboundedSender<StreamLine>) -> Result<i32> {
    let bin = find_gaster()?;
    run_streaming(&bin, &["pwn"], tx).await
}
