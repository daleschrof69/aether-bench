//! USB enumeration + hot-plug watching via `rusb`.
//!
//! Real and functional — talks to libusb on the host. On machines without a
//! USB subsystem (Docker containers, headless CI) `libusb_init` fails; instead
//! of panicking or bubbling an error, we degrade gracefully to an empty device
//! list so `aether-cli devices` / the bridge stay usable everywhere.

use anyhow::Result;
use colored::Colorize;
use rusb::{Context, Device, DeviceDescriptor, UsbContext};
use serde_json::{json, Value};
use std::time::Duration;

/// Create a libusb context, returning `None` when no USB subsystem is available
/// (Docker/headless CI). Never panics.
fn usb_context() -> Option<Context> {
    match Context::new() {
        Ok(ctx) => Some(ctx),
        Err(e) => {
            tracing::debug!("libusb unavailable ({e}) — USB features disabled on this host");
            None
        }
    }
}

/// Enumerate attached USB devices as (device, descriptor) pairs. Returns an
/// empty vec on hosts without USB — never panics, never errors.
fn enumerate() -> Vec<(Device<Context>, DeviceDescriptor)> {
    let Some(ctx) = usb_context() else {
        return Vec::new();
    };
    let list = match ctx.devices() {
        Ok(l) => l,
        Err(e) => {
            tracing::debug!("libusb device enumeration failed: {e}");
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for d in list.iter() {
        if let Ok(desc) = d.device_descriptor() {
            out.push((d, desc));
        }
    }
    out
}

/// How a supported phone presents on USB. Used to choose a read-only identity
/// query. Modes that only expose the USB descriptor stay descriptor-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbKind {
    Mtk,
    QualcommEdl,
    QualcommDiag,
    SamsungDownload,
    AppleDfu,
    AppleRecovery,
    AppleNormal,
    Fastboot,
    Adb,
    Mtp,
    DescriptorOnly,
    Unknown,
}

/// VID/PID classification aligned with `frontend/src/lib/usbSignatures.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbSignature {
    pub platform: &'static str,
    pub brand: &'static str,
    pub mode: &'static str,
    pub kind: UsbKind,
}

/// Exact VID:PID match. Vendor-only fallbacks are handled separately so a
/// random accessory with a known vendor id is not treated as a phone mode.
/// iPhone / iPad / iPod USB IDs. Keyboards and trackpads share vendor 0x05ac
/// and must stay out of this list.
fn apple_signature(vid: u16, pid: u16) -> Option<UsbSignature> {
    if vid != 0x05ac {
        return None;
    }
    let (mode, kind) = match pid {
        // DFU / WTF. 0x4141 is the PID a device already in pwned-DFU enumerates as.
        0x1222 => ("WTF mode", UsbKind::AppleDfu),
        0x1227 => ("DFU mode", UsbKind::AppleDfu),
        0x1338 => ("Restore (DFU)", UsbKind::AppleDfu),
        0x4141 => ("Pwned DFU", UsbKind::AppleDfu),
        // libirecovery recovery PIDs are 0x1280–0x1283, not only 0x1281.
        0x1280..=0x1283 => ("Recovery mode", UsbKind::AppleRecovery),
        // Normal-mode multiplex. Modern iPhones use 0x12a8; older models use the
        // other IDs in 0x1290–0x12ab.
        0x12a8 | 0x1290 | 0x1292 | 0x1294 | 0x1297 | 0x12a0 => {
            ("Normal (iPhone)", UsbKind::AppleNormal)
        }
        0x1291 | 0x1293 | 0x129e | 0x12a4 => ("Normal (iPod)", UsbKind::AppleNormal),
        0x12aa => ("Normal (iPod/iPad)", UsbKind::AppleNormal),
        0x129a | 0x129f | 0x12a2 | 0x12a3 | 0x12a5 | 0x12a6 | 0x12a9 | 0x12ab => {
            ("Normal (iPad)", UsbKind::AppleNormal)
        }
        0x1295 | 0x1296 | 0x1298 | 0x129b | 0x129c | 0x129d | 0x12a1 | 0x12a7 => {
            ("Normal (iPhone/iPad)", UsbKind::AppleNormal)
        }
        _ => return None,
    };
    Some(UsbSignature {
        platform: "Apple",
        brand: "Apple",
        mode,
        kind,
    })
}

pub fn exact_signature(vid: u16, pid: u16) -> Option<UsbSignature> {
    if let Some(sig) = apple_signature(vid, pid) {
        return Some(sig);
    }
    let (platform, brand, mode, kind) = match (vid, pid) {
        (0x0e8d, 0x0003) => ("MediaTek", "MediaTek", "Preloader", UsbKind::Mtk),
        (0x0e8d, 0x2000) => ("MediaTek", "MediaTek", "BROM (Boot ROM)", UsbKind::Mtk),
        (0x0e8d, 0x2001) => ("MediaTek", "MediaTek", "Preloader (DA)", UsbKind::Mtk),
        (0x0e8d, 0x201c) => ("MediaTek", "MediaTek", "BROM (secure)", UsbKind::Mtk),

        (0x05c6, 0x9008) => (
            "Qualcomm",
            "Qualcomm",
            "EDL 9008 (Sahara)",
            UsbKind::QualcommEdl,
        ),
        (0x05c6, 0x9006) => (
            "Qualcomm",
            "Qualcomm",
            "QDLoader (mass storage)",
            UsbKind::QualcommEdl,
        ),
        (0x05c6, 0x676c) => (
            "Qualcomm",
            "Qualcomm",
            "QDLoader HS-USB",
            UsbKind::QualcommEdl,
        ),
        (0x05c6, 0x9091) => (
            "Qualcomm",
            "Qualcomm",
            "EDL (Firehose)",
            UsbKind::QualcommEdl,
        ),
        (0x05c6, 0x90b8) => (
            "Qualcomm",
            "Qualcomm",
            "EDL (OEM 90b8)",
            UsbKind::QualcommEdl,
        ),
        (0x05c6, 0x900e) => (
            "Qualcomm",
            "Qualcomm",
            "Diagnostic (DIAG)",
            UsbKind::QualcommDiag,
        ),

        (0x04e8, 0x685d) => (
            "Samsung",
            "Samsung",
            "Download mode (Odin)",
            UsbKind::SamsungDownload,
        ),
        (0x04e8, 0x6601) => ("Samsung", "Samsung", "Upload mode", UsbKind::DescriptorOnly),
        (0x04e8, 0x685e) => ("Samsung", "Samsung", "Kies", UsbKind::DescriptorOnly),
        (0x04e8, 0x6860) | (0x04e8, 0x6865) | (0x04e8, 0x6866) => {
            ("Samsung", "Samsung", "Normal (MTP)", UsbKind::Mtp)
        }

        (0x18d1, 0x4ee0) | (0x18d1, 0xd00d) => {
            ("Android", "Google / Android", "Fastboot", UsbKind::Fastboot)
        }
        (0x18d1, 0x4ee7) => ("Android", "Google / Android", "ADB", UsbKind::Adb),
        (0x18d1, 0x4ee1) => ("Android", "Google / Android", "Normal (MTP)", UsbKind::Mtp),
        (0x18d1, 0x4ee2)
        | (0x18d1, 0x4ee3)
        | (0x18d1, 0x4ee4)
        | (0x18d1, 0x4ee5)
        | (0x18d1, 0x4ee6) => ("Android", "Google / Android", "ADB / MTP", UsbKind::Adb),

        (0x2717, 0xff40) | (0x2717, 0xff48) => ("Android", "Xiaomi", "Normal (MTP)", UsbKind::Mtp),
        (0x2a45, 0x4ee0) => ("Android", "Meizu", "Normal (MTP)", UsbKind::Mtp),
        (0x22b8, 0x2e76) | (0x22b8, 0x2e80) => {
            ("Android", "Motorola", "Fastboot", UsbKind::Fastboot)
        }
        _ => return None,
    };
    Some(UsbSignature {
        platform,
        brand,
        mode,
        kind,
    })
}

fn vendor_fallback(vid: u16) -> Option<UsbSignature> {
    let (platform, brand) = match vid {
        0x0e8d => ("MediaTek", "MediaTek"),
        0x05c6 => ("Qualcomm", "Qualcomm"),
        // Apple keyboards and trackpads share 05ac. Only the exact phone
        // PIDs above are treated as iPhone/iPad connections.
        0x04e8 => ("Samsung", "Samsung"),
        0x18d1 => ("Android", "Google / Android"),
        0x2717 | 0x2b4c => ("Android", "Xiaomi"),
        0x22b8 => ("Android", "Motorola"),
        0x1004 => ("Android", "LG"),
        0x12d1 => ("Android", "Huawei"),
        0x0bb4 => ("Android", "HTC / OnePlus"),
        0x2a70 => ("Android", "OnePlus"),
        0x22d9 => ("Android", "OPPO / Realme"),
        0x2d95 => ("Android", "Vivo"),
        0x1782 => ("Unisoc", "Spreadtrum / Unisoc"),
        0x0fce | 0x0489 => ("Android", "Sony"),
        0x19d2 => ("Android", "ZTE"),
        0x0b05 => ("Android", "ASUS"),
        _ => return None,
    };
    Some(UsbSignature {
        platform,
        brand,
        mode: "USB",
        kind: UsbKind::DescriptorOnly,
    })
}

pub fn signature(vid: u16, pid: u16) -> Option<UsbSignature> {
    exact_signature(vid, pid).or_else(|| vendor_fallback(vid))
}

/// Match a USB device against known repair-mode signatures.
///
/// Returns the mode label only for an exact VID:PID. Vendor-only devices stay
/// untagged so hubs and accessories are not highlighted as phone modes.
fn classify(desc: &DeviceDescriptor) -> Option<&'static str> {
    exact_signature(desc.vendor_id(), desc.product_id()).map(|s| s.mode)
}

/// One attached USB device, including descriptor strings when the host can read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbIdentity {
    pub bus: u8,
    pub addr: u8,
    pub vid: String,
    pub pid: String,
    pub manufacturer: String,
    pub product: String,
    pub serial: String,
    pub bcd_device: String,
    pub platform: Option<&'static str>,
    pub brand: Option<&'static str>,
    pub mode: Option<&'static str>,
    pub kind: UsbKind,
}

fn dash_if_empty(value: String) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "—".to_string()
    } else {
        trimmed.to_string()
    }
}

fn identity_from(d: &Device<Context>, desc: &DeviceDescriptor) -> UsbIdentity {
    let sig = signature(desc.vendor_id(), desc.product_id());
    let exact = exact_signature(desc.vendor_id(), desc.product_id());
    let (manufacturer, product, serial) = match d.open() {
        Ok(handle) => {
            let manufacturer = handle
                .read_manufacturer_string_ascii(desc)
                .unwrap_or_else(|_| "—".into());
            let product = handle
                .read_product_string_ascii(desc)
                .unwrap_or_else(|_| "—".into());
            let serial = handle
                .read_serial_number_string_ascii(desc)
                .unwrap_or_else(|_| "—".into());
            (manufacturer, product, serial)
        }
        Err(_) => ("—".into(), "—".into(), "—".into()),
    };
    let mut ident = UsbIdentity {
        bus: d.bus_number(),
        addr: d.address(),
        vid: format!("{:04x}", desc.vendor_id()),
        pid: format!("{:04x}", desc.product_id()),
        manufacturer: dash_if_empty(manufacturer),
        product: dash_if_empty(product),
        serial: dash_if_empty(serial),
        bcd_device: desc.device_version().to_string(),
        platform: sig.map(|s| s.platform),
        brand: sig.map(|s| s.brand),
        mode: exact.map(|s| s.mode),
        kind: sig.map(|s| s.kind).unwrap_or(UsbKind::Unknown),
    };
    promote_apple_strings(&mut ident);
    ident
}

/// Catch an iPhone whose PID is not in the table yet. Apple keyboards share
/// vendor 0x05ac, so this only fires on iPhone/iPad/iPod product strings or a
/// DFU serial (`CPID:`).
fn promote_apple_strings(ident: &mut UsbIdentity) {
    if ident.vid != "05ac" {
        return;
    }
    if matches!(
        ident.kind,
        UsbKind::AppleDfu | UsbKind::AppleRecovery | UsbKind::AppleNormal
    ) {
        return;
    }
    let product = ident.product.to_ascii_lowercase();
    let serial = ident.serial.to_ascii_lowercase();
    let (mode, kind) = if serial.contains("cpid:") || product.contains("dfu") {
        ("DFU mode", UsbKind::AppleDfu)
    } else if product.contains("recovery") {
        ("Recovery mode", UsbKind::AppleRecovery)
    } else if product.contains("iphone") || product.contains("apple mobile device") {
        ("Normal (iPhone)", UsbKind::AppleNormal)
    } else if product.contains("ipad") {
        ("Normal (iPad)", UsbKind::AppleNormal)
    } else if product.contains("ipod") {
        ("Normal (iPod)", UsbKind::AppleNormal)
    } else {
        return;
    };
    ident.platform = Some("Apple");
    ident.brand = Some("Apple");
    ident.mode = Some(mode);
    ident.kind = kind;
}

/// Enumerate USB devices with descriptor identity. Empty when libusb is unavailable.
pub fn identities() -> Vec<UsbIdentity> {
    enumerate()
        .iter()
        .map(|(d, desc)| identity_from(d, desc))
        .collect()
}

/// True when the device presents an Android MTP (Media Transfer Protocol) signature.
pub fn is_mtp_device(desc: &DeviceDescriptor) -> bool {
    matches!(
        (desc.vendor_id(), desc.product_id()),
        (0x18d1, 0x4ee1..=0x4ee7)
            | (0x04e8, 0x6860)
            | (0x04e8, 0x6865)
            | (0x04e8, 0x6866)
            | (0x2717, 0xff40)
            | (0x2717, 0xff48)
            | (0x2a45, 0x4ee0)
    ) || classify(desc).map(|s| s.contains("MTP")).unwrap_or(false)
}

/// Structured description of a detected MTP device.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MtpDevice {
    pub bus: u8,
    pub addr: u8,
    pub vid: String,
    pub pid: String,
    pub product: String,
    pub manufacturer: String,
    pub mode: &'static str,
}

/// Scan currently attached USB devices and return every MTP target.
pub fn detect_mtp_devices() -> Vec<MtpDevice> {
    let mut out = Vec::new();
    for (d, desc) in enumerate() {
        if !is_mtp_device(&desc) {
            continue;
        }
        let mode = classify(&desc).unwrap_or("MTP");
        let manufacturer = d
            .open()
            .ok()
            .and_then(|h| h.read_manufacturer_string_ascii(&desc).ok())
            .unwrap_or_else(|| "—".into());
        let product = d
            .open()
            .ok()
            .and_then(|h| h.read_product_string_ascii(&desc).ok())
            .unwrap_or_else(|| "—".into());
        out.push(MtpDevice {
            bus: d.bus_number(),
            addr: d.address(),
            vid: format!("{:04x}", desc.vendor_id()),
            pid: format!("{:04x}", desc.product_id()),
            product,
            manufacturer,
            mode,
        });
    }
    out
}

/// Pretty-print MTP detection results to the terminal.
pub fn report_mtp_detection() -> Result<()> {
    let found = detect_mtp_devices();
    if found.is_empty() {
        println!(
            "  {} No MTP (file transfer) device detected.",
            "✗".bright_red()
        );
        println!(
            "  {}",
            "Enable File Transfer / MTP on the phone and retry.".dimmed()
        );
        return Ok(());
    }
    println!(
        "  {} {} MTP device(s) detected:",
        "✓".bright_green(),
        found.len()
    );
    for dev in &found {
        println!(
            "    bus {:>3} · addr {:>3} | {}:{} | {} | {} {}",
            dev.bus,
            dev.addr,
            dev.vid,
            dev.pid,
            dev.mode.bright_green().bold(),
            dev.manufacturer.dimmed(),
            dev.product
        );
    }
    Ok(())
}

/// True when the device presents a Qualcomm EDL / 9008 (Sahara or Firehose) signature.
pub fn is_edl_device(desc: &DeviceDescriptor) -> bool {
    is_edl_device_ids(desc.vendor_id(), desc.product_id())
}

/// Structured description of a detected EDL device.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EdlDevice {
    pub bus: u8,
    pub addr: u8,
    pub vid: String,
    pub pid: String,
    pub product: String,
    pub manufacturer: String,
    pub mode: &'static str,
}

/// Scan currently attached USB devices and return every Qualcomm EDL / 9008 target.
/// Returns an empty vec when no USB subsystem is available or no EDL device is present.
pub fn detect_edl_devices() -> Vec<EdlDevice> {
    let mut out = Vec::new();
    for (d, desc) in enumerate() {
        if !is_edl_device(&desc) {
            continue;
        }
        let mode = classify(&desc).unwrap_or("Qualcomm EDL");
        let manufacturer = d
            .open()
            .ok()
            .and_then(|h| h.read_manufacturer_string_ascii(&desc).ok())
            .unwrap_or_else(|| "—".into());
        let product = d
            .open()
            .ok()
            .and_then(|h| h.read_product_string_ascii(&desc).ok())
            .unwrap_or_else(|| "—".into());
        out.push(EdlDevice {
            bus: d.bus_number(),
            addr: d.address(),
            vid: format!("{:04x}", desc.vendor_id()),
            pid: format!("{:04x}", desc.product_id()),
            product,
            manufacturer,
            mode,
        });
    }
    out
}

/// Pretty-print EDL detection results to the terminal.
pub fn report_edl_detection() -> Result<()> {
    let found = detect_edl_devices();
    if found.is_empty() {
        println!(
            "  {} No Qualcomm EDL / 9008 device detected.",
            "✗".bright_red()
        );
        println!(
            "  {}",
            "Put the device into EDL mode (test-point, adb reboot edl, or fastboot reboot-edl) and retry.".dimmed()
        );
        return Ok(());
    }
    println!(
        "  {} {} Qualcomm EDL device(s) detected:",
        "✓".bright_green(),
        found.len()
    );
    for dev in &found {
        println!(
            "    bus {:>3} · addr {:>3} | {}:{} | {} | {} {}",
            dev.bus,
            dev.addr,
            dev.vid,
            dev.pid,
            dev.mode.bright_green().bold(),
            dev.manufacturer.dimmed(),
            dev.product
        );
    }
    Ok(())
}

/// JSON representation of the current USB device list — used by the bridge.
///
/// `platform` is the family name the desktop pages match (`MediaTek`,
/// `Qualcomm`, `Samsung`, `Apple`, `Android`). `mode` / `repair_mode` describe
/// how the device is connected. Serial, product, and manufacturer come from
/// the USB string descriptor when the host allows that read.
pub fn devices_as_json() -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for dev in identities() {
        out.push(json!({
            "bus": dev.bus,
            "addr": dev.addr,
            "vid": dev.vid,
            "pid": dev.pid,
            "manufacturer": dev.manufacturer,
            "product": dev.product,
            "serial": dev.serial,
            "bcd_device": dev.bcd_device,
            "platform": dev.platform,
            "brand": dev.brand,
            "mode": dev.mode,
            "repair_mode": dev.mode,
        }));
    }
    Ok(out)
}

pub fn list_devices() -> Result<()> {
    let devices = identities();
    let mut shown = 0;
    let mut repair_targets = 0;
    for dev in &devices {
        shown += 1;
        let platform = dev.platform.unwrap_or("USB");
        let line = format!(
            "  bus {:>3} · addr {:>3} | {} {} | {:<10} | {} {} | sn {}",
            dev.bus,
            dev.addr,
            dev.vid,
            dev.pid,
            platform,
            dev.manufacturer.dimmed(),
            dev.product,
            dev.serial,
        );
        if let Some(tag) = dev.mode {
            repair_targets += 1;
            println!("{}", format!("{}  ← {}", line, tag).bright_green().bold());
        } else {
            println!("{}", line);
        }
    }
    println!();
    println!(
        "  {} {} USB devices · {} repair-mode targets detected.",
        "→".bright_green(),
        shown,
        repair_targets,
    );
    if shown == 0 {
        println!(
            "  {}",
            "No USB subsystem detected (or no devices attached). On a real \
             technician machine, plug in a device in BROM / EDL / DFU / Download mode."
                .dimmed()
        );
    } else if repair_targets == 0 {
        println!(
            "  {}",
            "Plug in a device in BROM / EDL / DFU / Download mode and retry.".dimmed()
        );
    }
    Ok(())
}

pub async fn watch_hotplug() -> Result<()> {
    println!(
        "  {} watching for hot-plug events ... (Ctrl-C to stop)",
        "○".bright_green()
    );
    let mut last = collect_keys();
    loop {
        tokio::time::sleep(Duration::from_millis(750)).await;
        let now = collect_keys();
        for k in now.difference(&last) {
            println!("  {} attached  {}", "+".bright_green().bold(), k);
        }
        for k in last.difference(&now) {
            println!("  {} detached  {}", "-".red().bold(), k);
        }
        last = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_modes_map_to_read_kinds() {
        let mtk = exact_signature(0x0e8d, 0x2000).unwrap();
        assert_eq!(mtk.platform, "MediaTek");
        assert_eq!(mtk.kind, UsbKind::Mtk);

        let edl = exact_signature(0x05c6, 0x9008).unwrap();
        assert_eq!(edl.platform, "Qualcomm");
        assert_eq!(edl.kind, UsbKind::QualcommEdl);

        let download = exact_signature(0x04e8, 0x685d).unwrap();
        assert_eq!(download.platform, "Samsung");
        assert_eq!(download.kind, UsbKind::SamsungDownload);

        let dfu = exact_signature(0x05ac, 0x1227).unwrap();
        assert_eq!(dfu.platform, "Apple");
        assert_eq!(dfu.kind, UsbKind::AppleDfu);

        let phone = exact_signature(0x05ac, 0x12a8).unwrap();
        assert_eq!(phone.kind, UsbKind::AppleNormal);
    }

    #[test]
    fn apple_accessories_are_not_phones() {
        assert!(exact_signature(0x05ac, 0x024f).is_none());
        assert!(signature(0x05ac, 0x024f).is_none());
    }

    #[test]
    fn iphone_recovery_and_normal_pids_are_detected() {
        for pid in [0x1280u16, 0x1281, 0x1282, 0x1283] {
            let sig = exact_signature(0x05ac, pid).unwrap();
            assert_eq!(sig.kind, UsbKind::AppleRecovery, "{pid:04x}");
            assert_eq!(sig.platform, "Apple");
        }
        assert_eq!(exact_signature(0x05ac, 0x1222).unwrap().kind, UsbKind::AppleDfu);
        assert_eq!(exact_signature(0x05ac, 0x1290).unwrap().mode, "Normal (iPhone)");
        assert_eq!(exact_signature(0x05ac, 0x12a8).unwrap().mode, "Normal (iPhone)");
        assert_eq!(exact_signature(0x05ac, 0x12aa).unwrap().mode, "Normal (iPod/iPad)");
    }

    #[test]
    fn iphone_product_string_promotes_unknown_pid() {
        let mut ident = UsbIdentity {
            bus: 1,
            addr: 2,
            vid: "05ac".into(),
            pid: "ffff".into(),
            manufacturer: "Apple Inc.".into(),
            product: "iPhone".into(),
            serial: "—".into(),
            bcd_device: "0".into(),
            platform: None,
            brand: None,
            mode: None,
            kind: UsbKind::Unknown,
        };
        promote_apple_strings(&mut ident);
        assert_eq!(ident.kind, UsbKind::AppleNormal);
        assert_eq!(ident.platform, Some("Apple"));
        assert_eq!(ident.mode, Some("Normal (iPhone)"));

        let mut keyboard = ident.clone();
        keyboard.product = "Apple Internal Keyboard / Trackpad".into();
        keyboard.kind = UsbKind::Unknown;
        keyboard.platform = None;
        keyboard.mode = None;
        promote_apple_strings(&mut keyboard);
        assert_eq!(keyboard.kind, UsbKind::Unknown);
    }

    #[test]
    fn diagnostic_pid_is_not_edl() {
        assert!(!is_edl_device_ids(0x05c6, 0x900e));
        assert!(is_edl_device_ids(0x05c6, 0x9008));
        assert!(is_edl_device_ids(0x05c6, 0x676c));
    }
}

fn is_edl_device_ids(vid: u16, pid: u16) -> bool {
    exact_signature(vid, pid)
        .map(|s| s.kind == UsbKind::QualcommEdl)
        .unwrap_or(false)
}

fn collect_keys() -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    for (d, desc) in enumerate() {
        out.insert(format!(
            "{:04x}:{:04x} bus{}.addr{}",
            desc.vendor_id(),
            desc.product_id(),
            d.bus_number(),
            d.address()
        ));
    }
    out
}
