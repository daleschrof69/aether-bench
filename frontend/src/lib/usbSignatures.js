// USB device intelligence for Aether Repair Tool.
//
// Two layers:
//   1. USB_SIGNATURES — exact VID:PID → { platform, mode, repair } matches for
//      the modes that matter to a repair tech (BROM, EDL, DFU, Download, …).
//   2. USB_VENDORS — VID → { brand, platform } fallback so an unrecognized PID
//      still resolves to a sensible brand/platform instead of "unknown".
//
// Kept in sync with the Rust CLI `usb.rs::classify()` for the repair-mode PIDs.

// vid:pid → repair-mode signature.
export const USB_SIGNATURES = [
  // ── MediaTek ────────────────────────────────────────────────────────────
  { vid: 0x0e8d, pid: 0x0003, platform: "MediaTek", mode: "Preloader", repair: true },
  { vid: 0x0e8d, pid: 0x2000, platform: "MediaTek", mode: "BROM (Boot ROM)", repair: true },
  { vid: 0x0e8d, pid: 0x2001, platform: "MediaTek", mode: "Preloader (DA)", repair: true },
  { vid: 0x0e8d, pid: 0x201c, platform: "MediaTek", mode: "BROM (secure)", repair: true },
  // ── Qualcomm ────────────────────────────────────────────────────────────
  { vid: 0x05c6, pid: 0x9008, platform: "Qualcomm", mode: "EDL 9008 (Sahara)", repair: true },
  { vid: 0x05c6, pid: 0x900e, platform: "Qualcomm", mode: "Diagnostic (DIAG)", repair: true },
  { vid: 0x05c6, pid: 0x9006, platform: "Qualcomm", mode: "QDLoader (mass storage)", repair: true },
  { vid: 0x05c6, pid: 0x676c, platform: "Qualcomm", mode: "QDLoader HS-USB", repair: true },
  { vid: 0x05c6, pid: 0x9091, platform: "Qualcomm", mode: "EDL (Firehose)", repair: true },
  // ── Apple ───────────────────────────────────────────────────────────────
  // DFU / WTF, every recovery PID (0x1280–0x1283), and the normal-mode
  // multiplex range. Modern iPhones enumerate as 0x12a8. Keyboards share
  // vendor 0x05ac and are intentionally not listed.
  { vid: 0x05ac, pid: 0x1222, platform: "Apple", mode: "WTF mode", repair: true },
  { vid: 0x05ac, pid: 0x1227, platform: "Apple", mode: "DFU mode", repair: true },
  { vid: 0x05ac, pid: 0x1280, platform: "Apple", mode: "Recovery mode", repair: true },
  { vid: 0x05ac, pid: 0x1281, platform: "Apple", mode: "Recovery mode", repair: true },
  { vid: 0x05ac, pid: 0x1282, platform: "Apple", mode: "Recovery mode", repair: true },
  { vid: 0x05ac, pid: 0x1283, platform: "Apple", mode: "Recovery mode", repair: true },
  { vid: 0x05ac, pid: 0x1338, platform: "Apple", mode: "Restore (DFU)", repair: true },
  { vid: 0x05ac, pid: 0x4141, platform: "Apple", mode: "Pwned DFU", repair: true },
  { vid: 0x05ac, pid: 0x12a8, platform: "Apple", mode: "Normal (iPhone)", repair: false },
  { vid: 0x05ac, pid: 0x1290, platform: "Apple", mode: "Normal (iPhone)", repair: false },
  { vid: 0x05ac, pid: 0x1292, platform: "Apple", mode: "Normal (iPhone)", repair: false },
  { vid: 0x05ac, pid: 0x1294, platform: "Apple", mode: "Normal (iPhone)", repair: false },
  { vid: 0x05ac, pid: 0x1297, platform: "Apple", mode: "Normal (iPhone)", repair: false },
  { vid: 0x05ac, pid: 0x12a0, platform: "Apple", mode: "Normal (iPhone)", repair: false },
  { vid: 0x05ac, pid: 0x12aa, platform: "Apple", mode: "Normal (iPod/iPad)", repair: false },
  // ── Samsung ─────────────────────────────────────────────────────────────
  { vid: 0x04e8, pid: 0x685d, platform: "Samsung", mode: "Download mode (Odin)", repair: true },
  { vid: 0x04e8, pid: 0x6601, platform: "Samsung", mode: "Upload / RAM dump", repair: true },
  { vid: 0x04e8, pid: 0x685e, platform: "Samsung", mode: "Kies", repair: false },
  { vid: 0x04e8, pid: 0x6860, platform: "Samsung", mode: "Normal (MTP)", repair: false },
  // ── Spreadtrum / Unisoc ───────────────────────────────────────────────────
  { vid: 0x1782, pid: 0x4d00, platform: "Unisoc", mode: "SPRD Download", repair: true },
  { vid: 0x1782, pid: 0x4d01, platform: "Unisoc", mode: "SPRD Diag", repair: true },
  // ── LG ────────────────────────────────────────────────────────────────────
  { vid: 0x1004, pid: 0x633e, platform: "Android", mode: "LG Download (LGUP)", repair: true },
  { vid: 0x1004, pid: 0x627f, platform: "Android", mode: "Normal (LG)", repair: false },
  // ── Huawei / HiSilicon ─────────────────────────────────────────────────────
  { vid: 0x12d1, pid: 0x3609, platform: "Android", mode: "COM 1.0 (testpoint DL)", repair: true },
  { vid: 0x12d1, pid: 0x1010, platform: "Android", mode: "Bootloader (fastboot)", repair: true },
  // ── Generic Android: fastboot / ADB ────────────────────────────────────────
  { vid: 0x18d1, pid: 0x4ee0, platform: "Android", mode: "Fastboot", repair: true },
  { vid: 0x18d1, pid: 0xd00d, platform: "Android", mode: "Fastboot (Nexus)", repair: true },
  { vid: 0x18d1, pid: 0x4ee7, platform: "Android", mode: "ADB", repair: false },
  { vid: 0x18d1, pid: 0x4ee1, platform: "Android", mode: "Normal (MTP)", repair: false },
  // ── Motorola ───────────────────────────────────────────────────────────────
  { vid: 0x22b8, pid: 0x2e76, platform: "Qualcomm", mode: "Fastboot (Moto)", repair: true },
  { vid: 0x22b8, pid: 0x2e80, platform: "Qualcomm", mode: "AP Fastboot", repair: true },
];

// VID → brand/platform fallback for devices whose exact PID we don't recognise.
export const USB_VENDORS = {
  0x0e8d: { brand: "MediaTek", platform: "MediaTek" },
  0x05c6: { brand: "Qualcomm", platform: "Qualcomm" },
  0x05ac: { brand: "Apple", platform: "Apple" },
  0x04e8: { brand: "Samsung", platform: "Samsung" },
  0x18d1: { brand: "Google / Android", platform: "Android" },
  0x2717: { brand: "Xiaomi", platform: "Android" },
  0x2b4c: { brand: "Xiaomi", platform: "Android" },
  0x22b8: { brand: "Motorola", platform: "Android" },
  0x1004: { brand: "LG", platform: "Android" },
  0x12d1: { brand: "Huawei", platform: "Android" },
  0x0bb4: { brand: "HTC / OnePlus", platform: "Android" },
  0x2a70: { brand: "OnePlus", platform: "Android" },
  0x22d9: { brand: "OPPO / Realme", platform: "Android" },
  0x2d95: { brand: "Vivo", platform: "Android" },
  0x1782: { brand: "Spreadtrum / Unisoc", platform: "Unisoc" },
  0x2e04: { brand: "HMD / Nokia", platform: "Android" },
  0x0fce: { brand: "Sony", platform: "Android" },
  0x0489: { brand: "Foxconn / Sony", platform: "Android" },
  0x19d2: { brand: "ZTE", platform: "Android" },
  0x1bbb: { brand: "TCL / Alcatel", platform: "Android" },
  0x0b05: { brand: "ASUS", platform: "Android" },
  0x0955: { brand: "NVIDIA", platform: "Android" },
  0x2916: { brand: "Yota / Android", platform: "Android" },
};

/**
 * Resolve a USB device to { platform, mode, repair, brand, known }.
 * Falls back to a vendor-level match, then null if the vendor is unknown too.
 */
export const classifyUsb = (vid, pid, hints = {}) => {
  const product = String(hints.product || "").toLowerCase();
  const serial = String(hints.serial || "").toLowerCase();
  if (vid === 0x05ac && !USB_SIGNATURES.some((s) => s.vid === vid && s.pid === pid)) {
    if (serial.includes("cpid:") || product.includes("dfu")) {
      return { vid, pid, platform: "Apple", mode: "DFU mode", repair: true, brand: "Apple", known: true };
    }
    if (product.includes("recovery")) {
      return { vid, pid, platform: "Apple", mode: "Recovery mode", repair: true, brand: "Apple", known: true };
    }
    if (product.includes("iphone") || product.includes("apple mobile device")) {
      return { vid, pid, platform: "Apple", mode: "Normal (iPhone)", repair: false, brand: "Apple", known: true };
    }
    if (product.includes("ipad")) {
      return { vid, pid, platform: "Apple", mode: "Normal (iPad)", repair: false, brand: "Apple", known: true };
    }
    if (product.includes("ipod")) {
      return { vid, pid, platform: "Apple", mode: "Normal (iPod)", repair: false, brand: "Apple", known: true };
    }
  }
  const sig = USB_SIGNATURES.find((s) => s.vid === vid && s.pid === pid);
  if (sig) {
    return { ...sig, brand: USB_VENDORS[vid]?.brand, known: true };
  }
  const vendor = USB_VENDORS[vid];
  if (vendor) {
    return {
      vid,
      pid,
      platform: vendor.platform,
      mode: "Standard mode (ADB / MTP / Fastboot)",
      repair: false,
      brand: vendor.brand,
      known: false,
    };
  }
  return null;
};

// Vendor filters for navigator.usb.requestDevice() — derived from USB_VENDORS
// so the browser chooser surfaces all supported phone makers.
export const USB_REQUEST_FILTERS = Object.keys(USB_VENDORS).map((v) => ({
  vendorId: Number(v),
}));
