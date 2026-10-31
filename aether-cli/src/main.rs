//! Aether CLI — entry point.
//!
//! Subcommand layout:
//!     aether-cli devices            list USB targets currently attached
//!     aether-cli scan               watch for new device hot-plug events
//!     aether-cli info <port>        read serial, model, and firmware/build
//!     aether-cli diag status|identity|firmware|battery|storage
//!     aether-cli bypass-frp <port>  (NOT IMPLEMENTED) MTK BROM / Qualcomm EDL FRP bypass
//!     aether-cli repair-imei <port> --imei1 <i> [--imei2 <i>]  (NOT IMPLEMENTED)
//!     aether-cli unlock-bootloader <port>  (NOT IMPLEMENTED)
//!     aether-cli samsung-factory-reset
//!     aether-cli edl-detect          detect Qualcomm EDL / 9008 devices
//!     aether-cli serve              run local WebSocket bridge for the Aether web dashboard

mod apple;
mod bridge;
mod diag;
mod edl;
mod exploits;
mod heimdall;
mod mtkclient;
mod qualcomm;
mod usb;

use clap::{Parser, Subcommand};
use colored::Colorize;

const BANNER: &str = r#"
   ▄▄▄       ▓█████ ▄▄▄█████▓ ██░ ██ ▓█████  ██▀███
  ▒████▄     ▓█   ▀ ▓  ██▒ ▓▒▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒
  ▒██  ▀█▄   ▒███   ▒ ▓██░ ▒░▒██▀▀██░▒███   ▓██ ░▄█ ▒
  ░██▄▄▄▄██  ▒▓█  ▄ ░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄
   ▓█   ▓██▒ ░▒████▒  ▒██▒ ░ ░▓█▒░██▓░▒████▒░██▓ ▒██▒
"#;

#[derive(Parser, Debug)]
#[command(
    name = "aether-cli",
    version,
    about = "Aether Repair Tool — unified CLI for MTK / Qualcomm / Apple / Samsung device repair",
    long_about = None,
)]
struct Cli {
    /// Verbose output (also enable with RUST_LOG=debug)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Skip the banner.
    #[arg(long, global = true)]
    no_banner: bool,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List all USB devices currently visible.
    Devices,
    /// Continuously watch for device hot-plug events.
    Scan,
    /// Read serial, model, firmware/build, and other identity fields.
    ///
    /// The reader follows the connection: Samsung Download mode, Apple
    /// DFU/Recovery or a trusted iPhone, MediaTek BROM, Qualcomm EDL, or an
    /// authorized ADB / fastboot session. Exits with an error when no device
    /// is attached.
    Info {
        /// Print a single JSON object.
        #[arg(long)]
        json: bool,
        /// Print a synthetic report without opening USB or external tools.
        #[arg(long)]
        dry_run: bool,
        /// Selector: auto, vid:pid, bus:addr, or serial.
        #[arg(default_value = "auto")]
        port: String,
    },
    /// Read-only connection and identity queries.
    Diag {
        /// Print a single JSON object.
        #[arg(long, global = true)]
        json: bool,
        /// Print a synthetic report without opening USB or external tools.
        #[arg(long, global = true)]
        dry_run: bool,
        /// Selector: auto, vid:pid, bus:addr, or serial.
        #[arg(long, global = true, default_value = "auto")]
        port: String,
        #[command(subcommand)]
        section: DiagSection,
    },
    /// Bypass Factory Reset Protection via mtkclient (erases the FRP partition).
    BypassFrp {
        #[arg(default_value = "auto")]
        port: String,
    },
    /// Restore / write IMEI to the modem NV partition via mtkclient.
    /// LEGAL: only for restoring an OEM-printed IMEI after a flash — see NOTICE.md.
    RepairImei {
        #[arg(default_value = "auto")]
        port: String,
        #[arg(long)]
        imei1: String,
        #[arg(long)]
        imei2: Option<String>,
    },
    /// Unlock OEM bootloader via mtkclient seccfg patch. Destructive — wipes userdata.
    UnlockBootloader {
        #[arg(default_value = "auto")]
        port: String,
    },
    /// Detect a Samsung device in Download Mode via Heimdall.
    SamsungDetect,
    /// Read the Samsung device's Partition Information Table (PIT).
    SamsungReadPit,
    /// Real factory reset on a Samsung device — erases USERDATA + CACHE + METADATA via Heimdall.
    /// Phone must be in Download Mode (Vol-Down + Bixby + Power, then Vol-Up).
    /// Works on Galaxy S9 / Note 9 / older A-series. Newer Knox 3.x models may reject writes.
    SamsungFactoryReset,
    /// Detect Qualcomm EDL / 9008 devices currently attached.
    EdlDetect,
    /// Detect Android MTP (file transfer) devices currently attached.
    MtpDetect,
    /// Run a local WebSocket bridge so the Aether web dashboard can talk to attached devices.
    Serve {
        /// Bind address.
        #[arg(long, default_value = "127.0.0.1:8765")]
        addr: String,
    },
    /// First-launch setup — installs Python dependencies (mtkclient) via pip.
    /// Safe to re-run; pip-upgrades if a newer mtkclient is published.
    Setup,
    /// Print the version of the bundled / detected mtkclient (Python tool).
    Doctor,
}

#[derive(Subcommand, Debug)]
enum DiagSection {
    /// List supported connections. Does not query firmware.
    Status,
    /// Serial, model, firmware/build, chipset, and related identity fields.
    Identity,
    /// Firmware kind or build string exposed by the current mode.
    Firmware,
    /// Battery level and health when this mode exposes them.
    Battery,
    /// Storage capacity when this mode exposes it.
    Storage,
}

fn print_banner() {
    println!("{}", BANNER.bright_green());
    println!(
        "  {} {}  ·  {}",
        "Aether Repair Tool CLI".bright_white().bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).bright_green(),
        "MTK · Qualcomm · Apple · Samsung".dimmed(),
    );
    println!(
        "  {}\n",
        "For licensed technicians only. https://aether.dev/legal".dimmed()
    );
}

fn init_tracing(verbose: bool) {
    let filter = if verbose {
        tracing_subscriber::EnvFilter::new("debug")
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    if !cli.no_banner && !command_wants_json(&cli.cmd) {
        print_banner();
    }
    match cli.cmd {
        Command::Devices => usb::list_devices()?,
        Command::Scan => usb::watch_hotplug().await?,
        Command::Info {
            port,
            json,
            dry_run,
        } => diag::run_cli(&port, "identity", json, dry_run).await?,
        Command::Diag {
            port,
            json,
            dry_run,
            section,
        } => {
            let name = match section {
                DiagSection::Status => "status",
                DiagSection::Identity => "identity",
                DiagSection::Firmware => "firmware",
                DiagSection::Battery => "battery",
                DiagSection::Storage => "storage",
            };
            diag::run_cli(&port, name, json, dry_run).await?
        }
        Command::BypassFrp { port } => exploits::frp::bypass_frp(&port).await?,
        Command::RepairImei { port, imei1, imei2 } => {
            exploits::imei::repair_imei(&port, &imei1, imei2.as_deref()).await?
        }
        Command::UnlockBootloader { port } => exploits::bootloader::unlock(&port).await?,
        Command::SamsungDetect => exploits::samsung::detect().await?,
        Command::SamsungReadPit => exploits::samsung::read_pit().await?,
        Command::SamsungFactoryReset => exploits::samsung::factory_reset().await?,
        Command::EdlDetect => usb::report_edl_detection()?,
        Command::MtpDetect => usb::report_mtp_detection()?,
        Command::Serve { addr } => bridge::serve(&addr).await?,
        Command::Setup => {
            println!(
                "  {} installing mtkclient via pip (requires Python 3.8+) ...",
                "→".bright_green()
            );
            let out = mtkclient::install_mtkclient().await?;
            println!("{}", out.dimmed());
            let ver = mtkclient::check_mtkclient()?;
            println!(
                "  {} mtkclient {} ready",
                "✓".bright_green(),
                ver.bright_white()
            );
            println!(
                "  {} installing edlclient (Qualcomm Firehose) via pip ...",
                "→".bright_green()
            );
            match qualcomm::install_edl_once().await {
                Ok(_) => println!("  {} edlclient ready", "✓".bright_green()),
                Err(e) => println!("  {} edlclient: {}", "✗".bright_red(), e),
            }
        }
        Command::Doctor => {
            match mtkclient::check_mtkclient() {
                Ok(v) => println!("  {} mtkclient {}", "✓".bright_green(), v.bright_white()),
                Err(e) => println!("  {} mtkclient: {}", "✗".bright_red(), e),
            }
            match heimdall::check_heimdall() {
                Ok(v) => println!("  {} {}", "✓".bright_green(), v.bright_white()),
                Err(e) => println!("  {} heimdall: {}", "✗".bright_red(), e),
            }
            match qualcomm::check_edl() {
                Ok(v) => println!("  {} {}", "✓".bright_green(), v.bright_white()),
                Err(e) => println!("  {} edl: {}", "✗".bright_red(), e),
            }
            match apple::check_apple() {
                Ok(v) => println!("  {} apple: {}", "✓".bright_green(), v.bright_white()),
                Err(e) => println!("  {} apple: {}", "✗".bright_red(), e),
            }
            for (ok, line) in diag::tool_status_lines() {
                if ok {
                    println!("  {} {}", "✓".bright_green(), line.bright_white());
                } else {
                    println!("  {} {}", "✗".bright_red(), line);
                }
            }
        }
    }
    Ok(())
}

fn command_wants_json(cmd: &Command) -> bool {
    match cmd {
        Command::Info { json, .. } | Command::Diag { json, .. } => *json,
        _ => false,
    }
}
