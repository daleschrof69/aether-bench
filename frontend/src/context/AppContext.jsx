import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from "react";
import { toast } from "sonner";
import { useCliBridge } from "../hooks/useCliBridge";
import { useWebUsb } from "../hooks/useWebUsb";

const AppContext = createContext(null);
export const useApp = () => useContext(AppContext);

// Mapping from a UI action key to the JSON-RPC method on the local CLI bridge.
// Every entry here maps to a REAL operation that the native aether-cli executes
// via mtkclient / heimdall / edlclient / checkm8 on the connected device. There
// is no simulation / demo fallback — operations only run when the local CLI
// bridge is live. Keys NOT listed here are not yet backed by a real tool and
// are reported honestly as unavailable (never faked).
const BRIDGE_METHODS = {
  // MediaTek (mtkclient)
  bypass_frp:             { method: "mtk.frp_bypass" },
  repair_imei:            { method: "mtk.repair_imei" },
  unlock_bootloader:      { method: "mtk.unlock_bootloader" },
  erase_userdata:         { method: "mtk.erase_userdata" },
  read_info:              { method: "mtk.read_info" },
  universal_unlock:       { method: "unlock.auto" },
  remove_screen_lock:     { method: "android.remove_screen_lock" },
  disable_auth:           { method: "mtk.disable_auth" },
  read_frp_token:         { method: "mtk.read_frp" },
  mdm_bypass:             { method: "android.remove_screen_lock" },
  // Qualcomm (edlclient — Sahara/Firehose)
  enter_edl:              { method: "qualcomm.enter_edl" },
  edl_auth_unlock:        { method: "qualcomm.edl_auth_unlock" },
  cert_repair:            { method: "qualcomm.cert_repair" },
  safe_format:            { method: "qualcomm.safe_format" },
  // Samsung (heimdall — Odin/Loke)
  samsung_detect:         { method: "samsung.detect" },
  samsung_read_pit:       { method: "samsung.read_pit" },
  samsung_factory_reset:  { method: "samsung.factory_reset" },
  // Apple (checkm8 / libimobiledevice)
  apple_info:             { method: "diag.read", params: { section: "identity" } },
  icloud_check:           { method: "apple.read_info" },
  hello_screen_bypass:    { method: "apple.pwn_dfu" },
  // MTP
  mtp_detect:             { method: "mtp.detect" },
  mtp_list:               { method: "mtp.list" },
  mtp_pull:               { method: "mtp.pull" },
  mtp_info:               { method: "mtp.info" },
};

const PLATFORM_HINTS = {
  MTK: "MediaTek",
  QC: "Qualcomm",
  SAMSUNG: "Samsung",
  Samsung: "Samsung",
  Apple: "Apple",
  iPhone: "Apple",
};

const GENERIC_USB_NAME = /qhusb|qhsusb|gadget|composite|preloader|apple mobile device|usb modem|samsung mobile|adb interface|^mtp$|^android$|^fastboot$/i;

const usableUsbName = (value) => {
  if (!value || value === "—") return "";
  const text = String(value).trim();
  if (!text || GENERIC_USB_NAME.test(text)) return "";
  return text;
};

const platformFromMode = (mode) => {
  if (!mode) return "";
  if (mode.startsWith("MediaTek") || mode.includes("BROM") || mode.includes("Preloader")) return "MediaTek";
  if (mode.startsWith("Qualcomm") || mode.includes("EDL") || mode.includes("Sahara")) return "Qualcomm";
  if (mode.startsWith("Samsung") || mode.includes("Download") || mode.includes("Odin")) return "Samsung";
  if (mode.startsWith("Apple") || mode.includes("DFU") || mode.includes("Recovery")) return "Apple";
  if (mode.includes("Android") || mode.includes("ADB") || mode.includes("MTP") || mode.includes("Fastboot")) return "Android";
  return "";
};

const maskImei = (imei) => {
  const digits = String(imei || "").replace(/\D/g, "");
  if (digits.length < 8) return "";
  return `${digits.slice(0, 2)}•••••••${digits.slice(-4)}`;
};

const deviceFromUsb = (target) => {
  const platform = target.platform || platformFromMode(target.mode || target.repair_mode) || "USB";
  const mode = target.mode || target.repair_mode || "";
  const model = usableUsbName(target.product) || mode || `${platform} ${target.vid}:${target.pid}`;
  const brand = usableUsbName(target.manufacturer) || target.brand || platform;
  const serial = usableUsbName(target.serial) || "—";
  return {
    model,
    brand,
    platform,
    imei: "—",
    imei_masked: "—",
    imei2: "—",
    imei2_masked: "—",
    serial,
    firmware: "—",
    battery: "—",
    bootloader: mode || "—",
    cpuId: "—",
    storage: "—",
    ram: "—",
    region: "—",
    vid: target.vid,
    pid: target.pid,
    android: "—",
    patch: "—",
    source: "bridge",
    detectedAt: new Date(),
  };
};

const applyIdentityReport = (prev, report) => {
  if (!prev || !report || report.report !== "identity") return prev;
  const next = { ...prev };
  if (report.platform && report.platform !== "—") next.platform = report.platform;
  if (report.brand) next.brand = report.brand;
  if (report.model) next.model = report.model;
  if (report.serial) next.serial = report.serial;
  if (report.firmware) next.firmware = report.firmware;
  if (report.chipset) next.cpuId = report.chipset;
  if (report.battery) next.battery = report.battery;
  if (report.storage) next.storage = report.storage;
  if (report.connection) next.bootloader = report.connection;
  const fields = report.fields || {};
  if (fields.android_version) next.android = fields.android_version;
  if (fields.security_patch) next.patch = fields.security_patch;
  const masked = maskImei(fields.imei);
  if (masked) {
    next.imei = masked;
    next.imei_masked = masked;
  }
  const masked2 = maskImei(fields.imei2);
  if (masked2) {
    next.imei2 = masked2;
    next.imei2_masked = masked2;
  }
  return next;
};

const formatTime = (d = new Date()) =>
  `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;

let logIdCounter = 0;

export const AppProvider = ({ children }) => {
  const [status, setStatus] = useState("idle"); // idle | searching | connected | working
  const [device, setDevice] = useState(null);
  const [comPort, setComPort] = useState(null);
  const [logs, setLogs] = useState([]);
  const [activeAction, setActiveAction] = useState(null);
  const [progress, setProgress] = useState(0);
  const [autoConnect, setAutoConnect] = useState(true);
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [credits, setCredits] = useState(100);
  const [setupOpen, setSetupOpen] = useState(false);
  const [imeiModalOpen, setImeiModalOpen] = useState(false);
  const timersRef = useRef([]);
  const scanGen = useRef(0);
  const cliBridge = useCliBridge();
  const webusb = useWebUsb();

  const pushLog = useCallback((level, text) => {
    setLogs((prev) => {
      const next = [
        ...prev,
        { id: ++logIdCounter, ts: formatTime(), level, text },
      ];
      return next.length > 500 ? next.slice(-500) : next;
    });
  }, []);

  const clearLogs = useCallback(() => {
    setLogs([]);
    pushLog("INFO", "Console cleared by user.");
  }, [pushLog]);

  const clearTimers = useCallback(() => {
    timersRef.current.forEach((t) => clearTimeout(t));
    timersRef.current = [];
  }, []);

  // Real device scan via the local Aether CLI bridge (libusb enumeration on the
  // host). No simulation: if the bridge is offline we tell the user how to
  // bring it online instead of inventing a fake device.
  const startSearch = useCallback(async (hint) => {
    clearTimers();
    const generation = ++scanGen.current;
    setStatus("searching");
    setDevice(null);
    setComPort(null);
    setActiveAction(null);
    const wanted = typeof hint === "string" ? PLATFORM_HINTS[hint] : null;
    pushLog("INFO", wanted ? `Scanning USB bus for ${wanted} ...` : "Scanning USB bus via local Aether bridge ...");

    if (cliBridge.status !== "connected" || typeof cliBridge.call !== "function") {
      pushLog("ERROR", "Local Aether CLI bridge is offline — no real USB access.");
      pushLog("INFO", "Start aether-cli on this machine (or launch the Aether desktop app), then retry.");
      pushLog("INFO", "Or click 'Connect via WebUSB' to pair a device directly in Chrome / Edge / Opera over HTTPS.");
      setStatus("idle");
      toast.error("CLI bridge offline", { description: "Start the Aether CLI to detect real devices." });
      return;
    }

    try {
      const res = await cliBridge.call("devices", {});
      if (scanGen.current !== generation) return;
      const list = Array.isArray(res?.devices) ? res.devices : [];
      const known = list.filter((d) => d.platform || d.mode || d.repair_mode);
      const pool = wanted ? known.filter((d) => (d.platform || platformFromMode(d.mode || d.repair_mode)) === wanted) : known;
      if (wanted && pool.length === 0) {
        pushLog("WARN", `No ${wanted} device found. Plug it in and retry.`);
        setStatus("idle");
        toast.warning(`No ${wanted} device`);
        return;
      }
      const target = pool.find((d) => d.mode || d.repair_mode) || pool[0] || list.find((d) => d.repair_mode) || (!wanted ? list[0] : null);
      if (!target) {
        pushLog("WARN", "No USB devices found. Plug a phone in BROM / EDL / DFU / Download mode and retry.");
        setStatus("idle");
        toast.warning("No device detected");
        return;
      }
      const dev = deviceFromUsb(target);
      setDevice(dev);
      setComPort(`bus ${target.bus} · addr ${target.addr}`);
      setStatus("connected");
      pushLog("SUCCESS", `Device detected: ${dev.model} (${target.vid}:${target.pid})`);
      if (dev.serial !== "—") pushLog("INFO", `Serial ${dev.serial}`);
      if (!target.mode && !target.repair_mode) {
        pushLog("WARN", "Device is not in a known repair mode. Enter BROM / EDL / DFU / Download mode, or authorize ADB, for a firmware read.");
      }
      toast.success(`Connected · ${dev.model}`, { description: `${target.vid}:${target.pid}` });

      if (typeof cliBridge.runJob === "function" && dev.platform && dev.platform !== "USB") {
        setActiveAction("Read identity");
        setStatus("working");
        pushLog("INFO", "Reading serial, model, and firmware ...");
        cliBridge
          .runJob("diag.read", { port: `${target.vid}:${target.pid}`, section: "identity" }, (ev) => {
            if (scanGen.current !== generation) return;
            const line = ev?.line || "";
            if (line.startsWith("AETHER_DIAG ")) {
              try {
                const report = JSON.parse(line.slice("AETHER_DIAG ".length));
                setDevice((prev) => applyIdentityReport(prev, report));
                if (report.ok) {
                  pushLog(
                    "SUCCESS",
                    `Identity · ${report.model || dev.model} · serial ${report.serial || "n/a"} · firmware ${report.firmware || "n/a"}`
                  );
                }
              } catch (err) {
                pushLog("WARN", `Identity report could not be parsed: ${err?.message || err}`);
              }
              return;
            }
            if (ev.stream === "stdout" && line) pushLog("INFO", line);
            else if (ev.stream === "stderr" && line) pushLog("WARN", line);
            else if (ev.stream === "done") {
              if (ev.exit_code && ev.exit_code !== 0) {
                pushLog("ERROR", `Identity read failed (exit ${ev.exit_code}).`);
              }
              setActiveAction(null);
              setStatus("connected");
            }
          })
          .catch((err) => {
            if (scanGen.current !== generation) return;
            pushLog("ERROR", `Identity read failed: ${err?.message || err}`);
            setActiveAction(null);
            setStatus("connected");
          });
      }
    } catch (e) {
      if (scanGen.current !== generation) return;
      pushLog("ERROR", `Bridge device scan failed: ${e?.message || e}`);
      setStatus("idle");
    }
  }, [cliBridge, pushLog, clearTimers]);

  const disconnect = useCallback(() => {
    clearTimers();
    scanGen.current += 1;
    pushLog("WARN", "Device disconnected by user.");
    setStatus("idle");
    setDevice(null);
    setComPort(null);
    setActiveAction(null);
    setProgress(0);
  }, [pushLog, clearTimers]);

  // Real in-browser device detection via WebUSB (Chromium + HTTPS). Enumerates
  // and classifies the connected device by VID/PID. Note: running full exploit
  // protocols still requires the native aether-cli bridge.
  const connectWebUsb = useCallback(async () => {
    scanGen.current += 1;
    if (!webusb.supported) {
      pushLog("ERROR", "WebUSB unavailable — use Chrome, Edge or Opera on desktop.");
      return;
    }
    pushLog("INFO", "Requesting USB device access (WebUSB) ...");
    try {
      const d = await webusb.request();
      const sig = d.signature;
      const dev = {
        model: usableUsbName(d.product) || (sig ? `${sig.platform} ${sig.mode}` : `USB Device ${d.vidHex}:${d.pidHex}`),
        brand: usableUsbName(d.manufacturer) || sig?.brand || "Unknown vendor",
        platform: sig?.platform || "USB",
        imei: "—",
        imei_masked: "—",
        imei2: "—",
        imei2_masked: "—",
        serial: usableUsbName(d.serial) || "—",
        firmware: "—",
        battery: "—",
        bootloader: sig?.mode || "Interface mode",
        cpuId: "—",
        storage: "—",
        ram: "—",
        region: "—",
        vid: d.vidHex,
        pid: d.pidHex,
        android: "—",
        patch: "—",
        source: "webusb",
        detectedAt: new Date(),
      };
      clearTimers();
      setDevice(dev);
      setComPort("WebUSB");
      setStatus("connected");
      pushLog("SUCCESS", `WebUSB authorized: ${dev.brand} ${dev.model}`);
      pushLog("INFO", `USB ${d.vidHex}:${d.pidHex}${d.serial ? ` · SN ${d.serial}` : ""}`);
      if (sig?.repair) {
        pushLog("SUCCESS", `Repair-mode target recognized: ${sig.platform} — ${sig.mode}`);
      } else if (sig) {
        pushLog(
          "WARN",
          `${sig.brand || sig.platform} detected in ${sig.mode}. Switch to BROM / EDL / DFU / Download mode for repair operations.`
        );
      } else {
        pushLog("WARN", `Unrecognized USB vendor ${d.vidHex}:${d.pidHex}. Put the device in a known repair mode and retry.`);
      }
      pushLog("INFO", "USB descriptors do not include the firmware build. Scan with the CLI bridge for a protocol identity read.");
    } catch (e) {
      if (e?.name === "NotFoundError") {
        pushLog("WARN", "WebUSB: no device selected.");
      } else if (e?.name === "SecurityError") {
        pushLog("ERROR", "WebUSB blocked by permissions policy — open the app in its own Chromium tab.");
      } else {
        pushLog("ERROR", `WebUSB error: ${e?.message || e}`);
      }
    }
  }, [webusb, pushLog, clearTimers]);

  const runAction = useCallback(
    (actionKey, label, params = {}) => {
      if (status !== "connected" || activeAction) return;

      const bridgeMap = BRIDGE_METHODS[actionKey];
      const bridgeLive =
        cliBridge.status === "connected" && typeof cliBridge.runJob === "function";

      // No bridge → no operation. We never fake success.
      if (!bridgeLive) {
        pushLog("ERROR", `Cannot run "${label}" — local Aether CLI bridge is offline.`);
        pushLog("INFO", "Start aether-cli on this machine (or launch the Aether desktop app) to run operations on real hardware.");
        toast.error("Bridge offline", { description: `Start the Aether CLI to run ${label}.` });
        return;
      }

      // Bridge live but this operation needs tooling the CLI doesn't expose yet.
      if (!bridgeMap) {
        pushLog("WARN", `"${label}" is not yet wired to a local CLI operation — skipping.`);
        pushLog("INFO", "This operation requires an additional loader/module in aether-cli.");
        toast.warning(`${label} · unavailable`, { description: "Not yet supported by the local CLI." });
        return;
      }

      // LIVE execution — stream real mtkclient / heimdall output into the console.
      setActiveAction(label);
      setStatus("working");
      setProgress(0);
      pushLog("INFO", `>>> EXECUTING (LIVE): ${label}`);
      pushLog("INFO", `aether-cli → ${bridgeMap.method}`);

      cliBridge
        .runJob(bridgeMap.method, { ...(bridgeMap.params || {}), ...params }, (ev) => {
          const line = ev?.line || "";
          if (line.startsWith("AETHER_DIAG ")) {
            try {
              const report = JSON.parse(line.slice("AETHER_DIAG ".length));
              setDevice((prev) => applyIdentityReport(prev, report));
            } catch (err) {
              pushLog("WARN", `Identity report could not be parsed: ${err?.message || err}`);
            }
            return;
          }
          if (ev.stream === "stdout" && line) {
            pushLog("INFO", line);
          } else if (ev.stream === "stderr" && line) {
            pushLog("WARN", ev.line);
          } else if (ev.stream === "done") {
            if (ev.exit_code === 0) {
              pushLog("SUCCESS", `${label} completed (exit 0).`);
              toast.success(`${label} · done`, { description: "Operation completed successfully." });
            } else {
              pushLog("ERROR", `${label} failed (exit ${ev.exit_code}).`);
              toast.error(`${label} · failed`, { description: `Exit code ${ev.exit_code}` });
            }
            const finishT = setTimeout(() => {
              setActiveAction(null);
              setStatus("connected");
              setProgress(0);
            }, 600);
            timersRef.current.push(finishT);
          }
        })
        .catch((e) => {
          pushLog("ERROR", `bridge error: ${e?.message || e}`);
          toast.error("Bridge error", { description: e?.message || String(e) });
          setActiveAction(null);
          setStatus("connected");
          setProgress(0);
        });
    },
    [status, activeAction, pushLog, cliBridge]
  );

  // Boot sequence — honest init banner (no fake engine loading).
  const bootedRef = useRef(false);
  useEffect(() => {
    if (bootedRef.current) return;
    bootedRef.current = true;
    pushLog("INFO", "[Aether] Phone Repair Tools initializing ...");
    pushLog("INFO", "[Aether] Looking for local CLI bridge on ws://127.0.0.1:8765 ...");
    pushLog("INFO", "[Aether] Plug a device into BROM / EDL / DFU / Download mode, or pair via WebUSB.");
    return () => clearTimers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // React to the local CLI bridge coming online/offline. When it connects and
  // auto-connect is on, immediately scan for a real device.
  const prevBridgeStatus = useRef("offline");
  useEffect(() => {
    if (cliBridge.status === "connected" && prevBridgeStatus.current !== "connected") {
      pushLog(
        "SUCCESS",
        `Local Aether CLI bridge connected${cliBridge.info?.version ? ` (v${cliBridge.info.version})` : ""}.`
      );
      if (cliBridge.info?.mtkclient) pushLog("INFO", `mtkclient ${cliBridge.info.mtkclient} ready.`);
      if (cliBridge.info?.heimdall) pushLog("INFO", `heimdall ${cliBridge.info.heimdall} ready.`);
      if (autoConnect && status === "idle") startSearch();
    }
    if (cliBridge.status === "offline" && prevBridgeStatus.current === "connected") {
      pushLog("WARN", "Local Aether CLI bridge disconnected.");
    }
    prevBridgeStatus.current = cliBridge.status;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cliBridge.status]);

  const value = {
    status,
    device,
    comPort,
    logs,
    activeAction,
    progress,
    autoConnect,
    soundEnabled,
    credits,
    setCredits,
    setAutoConnect,
    setSoundEnabled,
    startSearch,
    disconnect,
    connectWebUsb,
    webusb,
    runAction,
    pushLog,
    clearLogs,
    cliBridge,
    setupOpen,
    setSetupOpen,
    imeiModalOpen,
    setImeiModalOpen,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};
