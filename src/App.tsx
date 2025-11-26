import React, { useState, useEffect } from "react";
import Sidebar, {type SidebarView } from "./components/Sidebar";
import HeaderBar from "./components/HeaderBar";
import DashboardScreen from "./screens/DashboardScreen";
import LogsScreen from "./screens/LogsScreen";
import LoginScreen from "./screens/LoginScreen";
import RegisterScreen from "./screens/RegisterScreen";
import SettingsScreen from "./screens/SettingsScreen";
import ThreatsModal, {type Threat } from "./components/ThreatsModal";
import type { ProtectionStatus, ScanLogEntry } from "./types";

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { UnlistenFn } from "@tauri-apps/api/event";

type View =
    | "antivirus_dashboard"
    | "antivirus_logs"
    | "antivirus_settings"
    | "login"
    | "register";

type ScanProgress = {
  current: number;
  total: number;
  file: string;
};

// Er vi i Tauri eller ren browser?
const isTauri =
    typeof window !== "undefined" &&
    !!(window as any).__TAURI_INTERNALS__; // v2-safe check

const App: React.FC = () => {
  const [view, setView] = useState<View>("antivirus_dashboard");
  const [status, setStatus] = useState<ProtectionStatus>("protected");
  const [realtimeEnabled, setRealtimeEnabled] = useState<boolean>(true);

  const [logs, setLogs] = useState<ScanLogEntry[]>([
    {
      id: 1,
      timestamp: "2025-11-26 00:05",
      scan_type: "realtime",
      result: "clean",
      details: "Blocked suspicious script from modifying system files.",
    },
    {
      id: 2,
      timestamp: "2025-11-25 23:59",
      scan_type: "full_scan",
      result: "threats_found",
      details: "Full system scan completed. 2 threats were found.",
    },
    {
      id: 3,
      timestamp: "2025-11-25 22:31",
      scan_type: "realtime",
      result: "clean",
      details: "Real-time protection scanned 14 new files.",
    },
    {
      id: 4,
      timestamp: "2025-11-25 20:01",
      scan_type: "full_scan",
      result: "clean",
      details: "Scheduled scan completed. No threats found.",
    },
  ]);

  const [scanProgress, setScanProgress] = useState<ScanProgress>({
    current: 0,
    total: 0,
    file: "",
  });

  const [showDisableModal, setShowDisableModal] = useState(false);
  const [pendingRealtimeValue, setPendingRealtimeValue] =
      useState<boolean | null>(null);

  const [showThreatsModal, setShowThreatsModal] = useState(false);
  const [threats, setThreats] = useState<Threat[]>([
    {
      id: 1,
      fileName: "invoice_2023.exe",
      filePath: "C:\\Users\\kalle\\Downloads\\invoice_2023.exe",
      detection: "Trojan.Generic",
      recommendedAction: "delete",
    },
    {
      id: 2,
      fileName: "crack.dll",
      filePath: "C:\\Games\\SomeGame\\crack.dll",
      detection: "Riskware",
      recommendedAction: "quarantine",
    },
  ]);

  // Lyt efter fake scanning events (kun i Tauri)
  useEffect(() => {
    if (!isTauri) return;

    let unlistenProgress: UnlistenFn | null = null;
    let unlistenFinished: UnlistenFn | null = null;

    listen("scan_progress", (event) => {
      const payload = event.payload as any;
      setScanProgress({
        current: payload.current ?? 0,
        total: payload.total ?? 0,
        file: payload.file ?? "",
      });
    }).then((fn) => {
      unlistenProgress = fn;
    });

    listen("scan_finished", (event) => {
      const payload = event.payload as any;
      const threatsArray = (payload.threats as [string, string][]) || [];

      setStatus(realtimeEnabled ? "protected" : "not_protected");

      if (threatsArray.length > 0) {
        const mapped: Threat[] = threatsArray.map((t, idx) => ({
          id: idx + 1,
          fileName: t[0],
          filePath: t[1],
          detection: "Malware.Generic",
          recommendedAction: "delete",
        }));

        setThreats(mapped);
        setShowThreatsModal(true);

        setLogs((prev) => [
          {
            id: prev.length + 1,
            timestamp: new Date().toISOString().slice(0, 16).replace("T", " "),
            scan_type: "full_scan",
            result: "threats_found",
            details: `${mapped.length} threats were found in system scan.`,
          },
          ...prev,
        ]);
      } else {
        setLogs((prev) => [
          {
            id: prev.length + 1,
            timestamp: new Date().toISOString().slice(0, 16).replace("T", " "),
            scan_type: "full_scan",
            result: "clean",
            details: "Full system scan completed. No threats found.",
          },
          ...prev,
        ]);
      }

      setScanProgress({ current: 0, total: 0, file: "" });
    }).then((fn) => {
      unlistenFinished = fn;
    });

    return () => {
      if (unlistenProgress) unlistenProgress();
      if (unlistenFinished) unlistenFinished();
    };
  }, [realtimeEnabled]);

  // Lyt efter realtime file events (FSEvents via notify)
  useEffect(() => {
    if (!isTauri) return;

    let unlisten: UnlistenFn | null = null;

    listen("realtime_file_event", (event) => {
      const payload = event.payload as any;
      const now = new Date().toISOString().slice(0, 16).replace("T", " ");
      const details = `Real-time protection observed ${payload.event} on ${payload.file}`;

      setLogs((prev) => {
        const last = prev[0];
        // hvis sidste log allerede er samme realtime-event → skip
        if (last && last.scan_type === "realtime" && last.details === details) {
          return prev;
        }

        return [
          {
            id: prev.length + 1,
            timestamp: now,
            scan_type: "realtime",
            result: "clean",
            details,
          },
          ...prev,
        ];
      });
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const handleToggleRealtime = (enabled: boolean) => {
    if (!enabled) {
      setPendingRealtimeValue(false);
      setShowDisableModal(true);
      return;
    }

    setRealtimeEnabled(true);
    setStatus("protected");

    if (isTauri) {
      invoke("set_realtime_enabled", { enabled: true }).catch(() => {});
    }

    setLogs((prev) => [
      {
        id: prev.length + 1,
        timestamp: new Date().toISOString().slice(0, 16).replace("T", " "),
        scan_type: "realtime",
        result: "clean",
        details: "Real-time protection enabled.",
      },
      ...prev,
    ]);
  };

  const confirmDisableRealtime = () => {
    if (pendingRealtimeValue === false) {
      setRealtimeEnabled(false);
      setStatus("not_protected");

      if (isTauri) {
        invoke("set_realtime_enabled", { enabled: false }).catch(() => {});
      }

      setLogs((prev) => [
        {
          id: prev.length + 1,
          timestamp: new Date().toISOString().slice(0, 16).replace("T", " "),
          scan_type: "realtime",
          result: "clean",
          details: "Real-time protection disabled by the user.",
        },
        ...prev,
      ]);
    }
    setShowDisableModal(false);
    setPendingRealtimeValue(null);
  };

  const cancelDisableRealtime = () => {
    setShowDisableModal(false);
    setPendingRealtimeValue(null);
  };

  const handleFullScan = async () => {
    if (status === "scanning") return;

    setStatus("scanning");
    setScanProgress({ current: 0, total: 0, file: "" });

    // Web preview: fake 2 sek. scan
    if (!isTauri) {
      const timestamp = new Date().toISOString().slice(0, 16).replace("T", " ");

      setTimeout(() => {
        setStatus(realtimeEnabled ? "protected" : "not_protected");
        setLogs((prev) => [
          {
            id: prev.length + 1,
            timestamp,
            scan_type: "full_scan",
            result: "clean",
            details:
                "Full system scan completed. No threats found (web preview mode).",
          },
          ...prev,
        ]);
        setScanProgress({ current: 0, total: 0, file: "" });
      }, 2000);

      return;
    }

    // Tauri: brug fake_full_scan command
    try {
      await invoke("fake_full_scan");
    } catch (err) {
      console.error("Scan error:", err);
      setStatus(realtimeEnabled ? "protected" : "not_protected");
      setLogs((prev) => [
        {
          id: prev.length + 1,
          timestamp: new Date().toISOString().slice(0, 16).replace("T", " "),
          scan_type: "full_scan",
          result: "clean",
          details: "Scan failed or Tauri backend not available.",
        },
        ...prev,
      ]);
      setScanProgress({ current: 0, total: 0, file: "" });
    }
  };

  const lastFullScan =
      logs.find((l) => l.scan_type === "full_scan") || null;

  const isAntivirusView =
      view === "antivirus_dashboard" ||
      view === "antivirus_logs" ||
      view === "antivirus_settings";

  const currentSidebarView: SidebarView =
      view === "antivirus_dashboard"
          ? "dashboard"
          : view === "antivirus_logs"
              ? "logs"
              : "settings";

  const handleSidebarChange = (v: SidebarView) => {
    if (v === "dashboard") setView("antivirus_dashboard");
    else if (v === "logs") setView("antivirus_logs");
    else setView("antivirus_settings");
  };

  const handleOpenThreatsModal = () => {
    setShowThreatsModal(true);
  };

  const handleRemoveThreats = (ids: number[]) => {
    const removedCount = ids.length;

    setThreats((prev) => prev.filter((t) => !ids.includes(t.id)));

    setLogs((prev) => [
      {
        id: prev.length + 1,
        timestamp: new Date().toISOString().slice(0, 16).replace("T", " "),
        scan_type: "full_scan",
        result: "clean",
        details: `${removedCount} threat${
            removedCount === 1 ? "" : "s"
        } were removed by Stellar Antivirus.`,
      },
      ...prev,
    ]);

    setShowThreatsModal(false);
  };

  const rootClass = isTauri
      ? "w-screen h-screen bg-[#F4F6FB] flex"
      : "min-h-screen bg-[#050816] flex items-center justify-center";

  const shellClass = isTauri
      ? "flex-1 bg-[#F4F6FB] flex flex-col relative overflow-hidden"
      : "w-[1100px] h-[680px] bg-[#F4F6FB] rounded-[32px] shadow-[0_24px_80px_rgba(15,23,42,0.45)] overflow-hidden flex flex-col relative";

  return (
      <div className={rootClass}>
        <div className={shellClass}>
          {/* Dev mode switch */}
          <div className="h-10 bg-[#020617] text-[11px] text-white/70 flex items-center justify-center gap-3">
            <span className="opacity-60">Preview:</span>
            <button
                className={buttonCls(view === "antivirus_dashboard")}
                onClick={() => setView("antivirus_dashboard")}
            >
              Antivirus dashboard
            </button>
            <button
                className={buttonCls(view === "antivirus_logs")}
                onClick={() => setView("antivirus_logs")}
            >
              Antivirus logs
            </button>
            <button
                className={buttonCls(view === "antivirus_settings")}
                onClick={() => setView("antivirus_settings")}
            >
              Antivirus settings
            </button>
            <button
                className={buttonCls(view === "login")}
                onClick={() => setView("login")}
            >
              Login flow
            </button>
            <button
                className={buttonCls(view === "register")}
                onClick={() => setView("register")}
            >
              Register flow
            </button>
          </div>

          {/* Main content */}
          <div className="flex flex-1">
            {isAntivirusView && (
                <Sidebar current={currentSidebarView} onChange={handleSidebarChange} />
            )}

            <div className="flex-1 flex flex-col">
              {isAntivirusView && <HeaderBar status={status} />}
              <main className="flex-1 px-8 pb-8 overflow-y-auto">
                {view === "antivirus_dashboard" && (
                    <DashboardScreen
                        status={status}
                        realtimeEnabled={realtimeEnabled}
                        onToggleRealtime={handleToggleRealtime}
                        onFullScan={handleFullScan}
                        lastScan={lastFullScan}
                        recentLogs={logs.slice(0, 3)}
                        onOpenActivityLog={() => setView("antivirus_logs")}
                        scanProgress={scanProgress}
                    />
                )}
                {view === "antivirus_logs" && (
                    <LogsScreen logs={logs} onViewThreats={handleOpenThreatsModal} />
                )}
                {view === "antivirus_settings" && <SettingsScreen />}
                {view === "login" && <LoginScreen />}
                {view === "register" && <RegisterScreen />}
              </main>
            </div>
          </div>

          {/* Modal: disable real-time */}
          {showDisableModal && (
              <div className="absolute inset-0 bg-black/40 flex items-center justify-center z-40">
                <div className="w-[380px] bg-white rounded-3xl shadow-[0_20px_60px_rgba(15,23,42,0.5)] px-6 py-6">
                  <h3 className="text-sm font-semibold text-[#111827] mb-2">
                    Turn off real-time protection?
                  </h3>
                  <p className="text-xs text-[#6B7280] mb-4">
                    If you disable real-time protection, Stellar Antivirus will no
                    longer scan new and modified files automatically. This can make
                    your device more vulnerable to malware.
                  </p>
                  <div className="flex justify-end gap-2 mt-2">
                    <button
                        onClick={cancelDisableRealtime}
                        className="px-4 h-9 rounded-full text-xs font-medium border border-[#E5E7EB] text-[#111827] hover:bg-[#F3F4F6]"
                    >
                      Keep enabled
                    </button>
                    <button
                        onClick={confirmDisableRealtime}
                        className="px-4 h-9 rounded-full text-xs font-semibold bg-[#DC2626] text-white shadow-[0_10px_30px_rgba(220,38,38,0.6)]"
                    >
                      Turn off anyway
                    </button>
                  </div>
                </div>
              </div>
          )}

          {/* Modal: threats */}
          <ThreatsModal
              open={showThreatsModal}
              threats={threats}
              onClose={() => setShowThreatsModal(false)}
              onRemove={handleRemoveThreats}
          />
        </div>
      </div>
  );
};

const buttonCls = (active: boolean) =>
    `px-3 py-1 rounded-full border text-[11px] ${
        active
            ? "bg-white text-black border-white"
            : "border-white/20 hover:bg-white/10"
    }`;

export default App;
