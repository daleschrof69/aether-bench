import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from "react";
import { toast } from "sonner";
import { generateDevice, COM_PORTS, ACTION_LOG_TEMPLATES, fillTemplate } from "../lib/mockData";
import { useCliBridge } from "../hooks/useCliBridge";
import { useWebUsb } from "../hooks/useWebUsb";

const AppContext = createContext(null);
export const useApp = () => useContext(AppContext);

// Mapping from a UI action key to the JSON-RPC method on the local CLI bridge.
// When the bridge is connected we call the real method (which streams
// mtkclient output back as log lines). When the bridge is offline we fall
// back to the deterministic demo simulation in mockData.js.
const BRIDGE_METHODS = {
  bypass_frp:             { method: "mtk.frp_bypass" },
  repair_imei:            { method: "mtk.repair_imei" },
  unlock_bootloader:      { method: "mtk.unlock_bootloader" },
  erase_userdata:         { method: "mtk.erase_userdata" },
  read_info:              { method: "mtk.read_info" },
  enter_edl:              { method: "qualcomm.enter_edl" },
  samsung_detect:         { method: "samsung.detect" },
  samsung_read_pit:       { method: "samsung.read_pit" },
  samsung_factory_reset:  { method: "samsung.factory_reset" },
  universal_unlock:       { method: "unlock.auto" },
  remove_screen_lock:     { method: "android.remove_screen_lock" },
  disable_auth:           { method: "mtk.disable_auth" },
  mdm_bypass:             { method: "android.mdm_bypass" },
  edl_auth_unlock:        { method: "qualcomm.edl_auth_unlock" },
  cert_repair:            { method: "qualcomm.cert_repair" },
  samsung_mdm_remove:     { method: "samsung.mdm_remove" },
  sim_unlock:             { method: "unlock.sim_unlock" },
  hello_screen_bypass:    { method: "apple.hello_bypass" },
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

  const startSearch = useCallback((forceChipset = "auto") => {
    // Coerce accidental event-object args (onClick={startSearch}) back to auto.
    const chipset = typeof forceChipset === "string" ? forceChipset : "auto";
    clearTimers();
    setStatus("searching");
    setDevice(null);
    setComPort(null);
    pushLog("INFO", "Aether driver loaded. Scanning USB bus ...");
    pushLog("INFO", "Listening on COM ports: " + COM_PORTS.join(", "));

    const t1 = setTimeout(() => pushLog("INFO", "Probing for MTK preloader signature ..."), 350);
    const t2 = setTimeout(() => pushLog("INFO", "Probing for Qualcomm EDL 9008 ..."), 700);
    const t2b = setTimeout(() => pushLog("INFO", "Probing for Samsung Download Mode (Odin/Loke) ..."), 1000);
    const t3 = setTimeout(() => {
      const dev = generateDevice(chipset);
      const port = COM_PORTS[Math.floor(Math.random() * COM_PORTS.length)];
      setDevice(dev);
      setComPort(port);
      setStatus("connected");
      pushLog("SUCCESS", `Handshake OK on ${port}`);
      pushLog("SUCCESS", `Device detected: ${dev.model}`);
      pushLog("INFO", `Brand: ${dev.brand} | Android ${dev.android} | Patch ${dev.patch}`);
      toast.success(`Connected · ${dev.model}`, { description: `${dev.brand} · ${dev.platform} · ${port}` });
    }, 1400);
    timersRef.current = [t1, t2, t2b, t3];
  }, [pushLog, clearTimers]);

  const disconnect = useCallback(() => {
    clearTimers();
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
    if (!webusb.supported) {
      pushLog("ERROR", "WebUSB unavailable — use Chrome, Edge or Opera on desktop.");
      return;
    }
    pushLog("INFO", "Requesting USB device access (WebUSB) ...");
    try {
      const d = await webusb.request();
      const sig = d.signature;
      const dev = {
        model: d.product || `USB Device ${d.vidHex}:${d.pidHex}`,
        brand: d.manufacturer || sig?.brand || "Unknown vendor",
        platform: sig?.platform || "USB",
        imei: "N/A (WebUSB)",
        imei_masked: "N/A (WebUSB)",
        imei2: "N/A",
        imei2_masked: "N/A",
        serial: d.serial || "—",
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
      pushLog("INFO", "Note: full exploit I/O runs through the Aether CLI bridge.");
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

      // PATH A — bridge is live AND we have a real method for this action.
      // Stream mtkclient output line-by-line into the console.
      const bridgeMap = BRIDGE_METHODS[actionKey];
      if (
        bridgeMap &&
        cliBridge.status === "connected" &&
        typeof cliBridge.runJob === "function"
      ) {
        setActiveAction(label);
        setStatus("working");
        setProgress(0);
        pushLog("INFO", `>>> EXECUTING (LIVE): ${label}`);
        pushLog("INFO", `aether-cli → ${bridgeMap.method}`);

        cliBridge
          .runJob(bridgeMap.method, { ...(bridgeMap.params || {}), ...params }, (ev) => {
            if (ev.stream === "stdout" && ev.line) {
              pushLog("INFO", ev.line);
            } else if (ev.stream === "stderr" && ev.line) {
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
        return;
      }

      // PATH B — DEMO MODE. No bridge, no real CLI: play back the canned
      // mockData template so the dashboard still feels alive for prospects.
      const template = ACTION_LOG_TEMPLATES[actionKey];
      if (!template) return;
      // When the caller supplies IMEI values (IMEI Repair modal), reflect them
      // in the simulated log lines instead of the device's random IMEI.
      const fillDevice = params?.imei1
        ? { ...(device || {}), imei: params.imei1, imei2: params.imei2 || device?.imei2 }
        : device;
      setActiveAction(label);
      setStatus("working");
      setProgress(0);
      pushLog("INFO", `>>> EXECUTING (DEMO): ${label}`);

      template.forEach((step, idx) => {
        const t = setTimeout(
          () => {
            pushLog(step.level, fillTemplate(step.text, fillDevice));
            setProgress(Math.round(((idx + 1) / template.length) * 100));
            if (idx === template.length - 1) {
              const finishT = setTimeout(() => {
                setActiveAction(null);
                setStatus("connected");
                setProgress(0);
                toast.success(`${label} · demo complete`, {
                  description: "Install the CLI to run this operation on real hardware.",
                });
              }, 600);
              timersRef.current.push(finishT);
            }
          },
          (idx + 1) * 700
        );
        timersRef.current.push(t);
      });
    },
    [status, activeAction, device, pushLog, cliBridge]
  );

  // Boot sequence — ref-guarded so it runs once even if deps change.
  const bootedRef = useRef(false);
  useEffect(() => {
    if (bootedRef.current) return;
    bootedRef.current = true;
    pushLog("INFO", "[Aether] Initializing modules...");
    const boot = [
      { delay: 120, level: "INFO", text: "[Aether] Loading kernel driver aether-usb 2.4.1 ... OK" },
      { delay: 240, level: "INFO", text: "[Aether] Qualcomm Sahara Engine Loaded" },
      { delay: 360, level: "INFO", text: "[Aether] MediaTek BROM Engine Loaded" },
      { delay: 480, level: "INFO", text: "[Aether] Apple DFU Pipeline Loaded (checkm8 / pongoOS)" },
      { delay: 600, level: "INFO", text: "[Aether] Wallet sync · license active" },
      { delay: 720, level: "SUCCESS", text: "[Aether] Ready. Awaiting target device." },
    ];
    boot.forEach((b) => {
      const t = setTimeout(() => pushLog(b.level, b.text), b.delay);
      timersRef.current.push(t);
    });
    if (autoConnect) {
      const t = setTimeout(() => startSearch(), 900);
      timersRef.current.push(t);
    }
    return () => clearTimers();
    // Boot must run exactly once; bootedRef guards re-entry. Empty deps
    // are intentional — adding pushLog/startSearch would fire the cleanup
    // (clearTimers) on every state change and kill the boot sequence.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
