import React, { useState, useEffect } from "react";
import Sidebar from "./components/Sidebar";
import HeaderBar from "./components/HeaderBar";
import DashboardScreen from "./screens/DashboardScreen";
import LogsScreen from "./screens/LogsScreen";
import LoginScreen from "./screens/LoginScreen";
import RegisterScreen from "./screens/RegisterScreen";
import SettingsScreen from "./screens/SettingsScreen";
import ThreatsModal from "./components/ThreatsModal";
import type { ProtectionStatus, ScanLogEntry, Threat } from "./types";
import { isEnabled as isAutostartEnabled, enable as enableAutostart } from "@tauri-apps/plugin-autostart";


import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { UnlistenFn } from "@tauri-apps/api/event";

type View =
    | "antivirus_dashboard"
    | "antivirus_logs"
    | "antivirus_settings"
    | "login"
    | "register";

type SidebarView = "dashboard" | "logs" | "settings";

interface ScanProgress {
    current: number;
    total: number;
    file: string;
}

type QuarantineEntry = {
    id: number;
    fileName: string;
    originalPath: string;
    quarantinedAt: string;
    detection: string;
};

// Er vi i Tauri eller ren browser?
const isTauri =
    typeof window !== "undefined" &&
    !!(window as any).__TAURI_INTERNALS__; // v2-safe check

const DEFAULT_LOGS: ScanLogEntry[] = [];

const DEFAULT_THREATS: Threat[] = [];

const App: React.FC = () => {
    const [view, setView] = useState<View>(() => {
        if (typeof window !== "undefined") {
            const loggedIn = window.localStorage.getItem("stellar_logged_in");
            return loggedIn === "1" ? "antivirus_dashboard" : "register";
        }
        return "register";
    });
    const [status, setStatus] = useState<ProtectionStatus>("protected");
    const [realtimeEnabled, setRealtimeEnabled] = useState<boolean>(() => {
        if (typeof window === "undefined") return true;

        const raw = window.localStorage.getItem("stellar_realtime_enabled_v1");
        if (raw === "0") return false;
        return true; // default: enabled
    });

    const [logs, setLogs] = useState<ScanLogEntry[]>(() => {
        if (typeof window === "undefined") {
            return DEFAULT_LOGS;
        }

        try {
            const raw = window.localStorage.getItem("stellar_logs_v1");
            if (!raw) return DEFAULT_LOGS;

            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) return DEFAULT_LOGS;

            return parsed as ScanLogEntry[];
        } catch {
            return DEFAULT_LOGS;
        }
    });

    const [scanProgress, setScanProgress] = useState<ScanProgress>({
        current: 0,
        total: 0,
        file: "",
    });

    const [showRealtimeConfirm, setShowRealtimeConfirm] = useState(false);
    const [pendingRealtimeValue, setPendingRealtimeValue] = useState<boolean | null>(null);

    const [showThreatsModal, setShowThreatsModal] = useState(false);
    const [threats, setThreats] = useState<Threat[]>(() => {
        if (typeof window === "undefined") {
            return DEFAULT_THREATS;
        }

        try {
            const raw = window.localStorage.getItem("stellar_threats_v1");
            if (!raw) return DEFAULT_THREATS;

            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) return DEFAULT_THREATS;

            return parsed as Threat[];
        } catch {
            return DEFAULT_THREATS;
        }
    });


    const [quarantine, setQuarantine] = useState<QuarantineEntry[]>([]);
    const [pendingDeleteId, setPendingDeleteId] = useState<number | null>(null);
    const [showDeleteModal, setShowDeleteModal] = useState(false);



    useEffect(() => {
        if (!isTauri) return;

        let cancelled = false;

        const syncThreatDb = async () => {
            if (cancelled) return;

            try {
                const res = await fetch(
                    "https://stellarantivirusthreatdb.blob.core.windows.net/threat-db/v1/threats.json"
                );

                if (!res.ok) {
                    console.error(
                        "Failed to fetch threat DB:",
                        res.status,
                        res.statusText
                    );
                    return;
                }

                const jsonText = await res.text();

                await invoke("update_threat_db", { threatsJson: jsonText });

                console.log("Threat DB updated from Azure (auto-sync)");
            } catch (err) {
                console.error("Error updating threat DB:", err);
            }
        };

        syncThreatDb();

        const intervalId = setInterval(syncThreatDb, 60 * 60 * 1000);

        return () => {
            cancelled = true;
            clearInterval(intervalId);
        };
    }, []);


    useEffect(() => {
        if (typeof window === "undefined") return;

        try {
            window.localStorage.setItem("stellar_threats_v1", JSON.stringify(threats));
        } catch (err) {
            console.error("Failed to persist threats:", err);
        }
    }, [threats]);

    useEffect(() => {
        if (!isTauri) return;

        (async () => {
            try {
                const enabled = await isAutostartEnabled();
                if (!enabled) {
                    await enableAutostart();
                    console.log("Autostart enabled for Stellar Antivirus");
                }
            } catch (err) {
                console.error("Failed to configure autostart:", err);
            }
        })();
    }, []);

    useEffect(() => {
        if (typeof window === "undefined") return;

        try {
            window.localStorage.setItem("stellar_logs_v1", JSON.stringify(logs));
        } catch (err) {
            console.error("Failed to persist logs:", err);
        }
    }, [logs]);

    useEffect(() => {
        if (typeof window === "undefined") return;

        try {
            window.localStorage.setItem(
                "stellar_realtime_enabled_v1",
                realtimeEnabled ? "1" : "0"
            );
        } catch (err) {
            console.error("Failed to persist realtimeEnabled:", err);
        }
    }, [realtimeEnabled]);

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

            // Opdatér status efter scan
            setStatus(realtimeEnabled ? "protected" : "not_protected");

            if (threatsArray.length > 0) {
                const nowIso = new Date().toISOString();
                const mapped: Threat[] = threatsArray.map((t, idx) => ({
                    id: idx + 1,
                    fileName: t[0],
                    filePath: t[1],
                    detection: "Malware.Generic",
                    recommendedAction: "delete",
                    detectedAt: nowIso,
                    source: "full_scan",
                    status: "active",
                }));

                setThreats(mapped);
                setShowThreatsModal(true);

                setLogs((prev) => {
                    const timestamp = new Date().toISOString().slice(0, 16).replace("T", " ");
                    const details = `${mapped.length} threats were found in system scan.`;

                    const newEntry: ScanLogEntry = {
                        id: prev.length + 1,
                        timestamp,
                        scan_type: "full_scan",
                        result: "threats_found",
                        details,
                    };

                    const last = prev[0];
                    if (
                        last &&
                        last.scan_type === newEntry.scan_type &&
                        last.result === newEntry.result &&
                        last.details === newEntry.details &&
                        last.timestamp === newEntry.timestamp
                    ) {
                        // Hvis sidste log er identisk, så lad være med at tilføje igen
                        return prev;
                    }

                    return [newEntry, ...prev];
                });
            } else {
                setLogs((prev) => {
                    const timestamp = new Date().toISOString().slice(0, 16).replace("T", " ");
                    const details = "Full system scan completed. No threats found.";

                    const newEntry: ScanLogEntry = {
                        id: prev.length + 1,
                        timestamp,
                        scan_type: "full_scan",
                        result: "clean",
                        details,
                    };

                    const last = prev[0];
                    if (
                        last &&
                        last.scan_type === newEntry.scan_type &&
                        last.result === newEntry.result &&
                        last.details === newEntry.details &&
                        last.timestamp === newEntry.timestamp
                    ) {
                        return prev;
                    }

                    return [newEntry, ...prev];
                });
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


    // Lyt efter realtime file events (FSEvents/inotify) og coalescér spam
    // Lyt efter realtime file events (FSEvents/inotify) – men log ikke i Activity
    useEffect(() => {
        if (!isTauri) return;

        let unlisten: UnlistenFn | null = null;

        listen("realtime_file_event", (event) => {
            const payload = event.payload as any;
            // Hvis du vil debugge, kan du nøjes med console:
            // console.debug("Realtime file event:", payload);
            // Men vi rører ikke logs her.
        }).then((fn) => {
            unlisten = fn;
        });

        return () => {
            if (unlisten) unlisten();
        };
    }, []);

    const startFullScan = async () => {
        if (!isTauri) {
            setStatus("scanning");
            setScanProgress({ current: 0, total: 100, file: "Simulating scan..." });

            let current = 0;
            const interval = setInterval(() => {
                current += 5;
                if (current >= 100) {
                    clearInterval(interval);
                    setStatus(realtimeEnabled ? "protected" : "not_protected");
                    setScanProgress({ current: 0, total: 0, file: "" });
                    setLogs((prev) => [
                        {
                            id: prev.length + 1,
                            timestamp: new Date().toISOString().slice(0, 16).replace("T", " "),
                            scan_type: "full_scan",
                            result: "clean",
                            details: "Full scan completed (demo only, no real engine).",
                        },
                        ...prev,
                    ]);
                } else {
                    setScanProgress({ current, total: 100, file: "Simulating scan..." });
                }
            }, 200);

            return;
        }

        // Tauri: kald backend
        try {
            setStatus("scanning");
            setScanProgress({ current: 0, total: 0, file: "" });
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

    const handleQuarantineThreat = async (t: Threat) => {
        if (!isTauri) return; // fallback

        try {
            await invoke("quarantine_files", { paths: [t.filePath] });

            setLogs((prev) => [
                {
                    id: prev.length + 1,
                    timestamp: new Date().toISOString().slice(0, 16).replace("T", " "),
                    scan_type: "realtime",
                    result: "clean",
                    details: `Moved to quarantine: ${t.fileName}`,
                },
                ...prev,
            ]);

            setThreats((prev) => prev.filter((x) => x.id !== t.id));

        } catch (err) {
            console.error("Quarantine failed:", err);
        }
    };

    const handleDeleteThreat = async (t: Threat) => {
        if (!isTauri) return;

        try {
            await invoke("delete_files", { paths: [t.filePath] });

            setLogs((prev) => [
                {
                    id: prev.length + 1,
                    timestamp: new Date().toISOString().slice(0, 16).replace("T", " "),
                    scan_type: "realtime",
                    result: "clean",
                    details: `Permanently deleted: ${t.fileName}`,
                },
                ...prev,
            ]);

            // Fjern fra ThreatsModal list
            setThreats((prev) => prev.filter((x) => x.id !== t.id));

        } catch (err) {
            console.error("Delete failed:", err);
        }
    };

    const handleRemoveThreats = async (ids: number[]) => {
        const now = new Date().toISOString().slice(0, 16).replace("T", " ");

        const selectedThreats = threats.filter((t) => ids.includes(t.id));
        const removedCount = selectedThreats.length;

        const paths = selectedThreats
            .map((t) => t.filePath)
            .filter((p) => !!p);

        const newEntries: QuarantineEntry[] = selectedThreats.map((t, idx) => ({
            id: quarantine.length + idx + 1,
            fileName: t.fileName,
            originalPath: t.filePath,
            quarantinedAt: now,
            detection: t.detection,
        }));

        if (isTauri && paths.length > 0) {
            try {
                await invoke("quarantine_files", { paths });

                setQuarantine((prev) => [...newEntries, ...prev]);

                setLogs((prev) => [
                    {
                        id: prev.length + 1,
                        timestamp: now,
                        scan_type: "full_scan",
                        result: "clean",
                        details: `${removedCount} threat${
                            removedCount === 1 ? "" : "s"
                        } moved to quarantine.`,
                    },
                    ...prev,
                ]);
            } catch (err) {
                console.error("Quarantine error:", err);
                setLogs((prev) => [
                    {
                        id: prev.length + 1,
                        timestamp: now,
                        scan_type: "full_scan",
                        result: "clean",
                        details: "Failed to move threats to quarantine.",
                    },
                    ...prev,
                ]);
            }
        } else {
            setLogs((prev) => [
                {
                    id: prev.length + 1,
                    timestamp: now,
                    scan_type: "full_scan",
                    result: "clean",
                    details: `${removedCount} threat${
                        removedCount === 1 ? "" : "s"
                    } removed from list (demo only).`,
                },
                ...prev,
            ]);
        }

        setThreats((prev) => prev.filter((t) => !ids.includes(t.id)));
        setShowThreatsModal(false);
    };

    const handleRestoreQuarantine = (id: number) => {
        const entry = quarantine.find((q) => q.id === id);
        if (!entry) return;

        const now = new Date().toISOString().slice(0, 16).replace("T", " ");

        // Fjern fra quarantine-listen
        setQuarantine((prev) => prev.filter((q) => q.id !== id));

        // Log, at filen er "restored"
        setLogs((prev) => [
            {
                id: prev.length + 1,
                timestamp: now,
                scan_type: "realtime",
                result: "clean",
                details: `Restored file from quarantine: ${entry.fileName}`,
            },
            ...prev,
        ]);

        // Hvis vi senere laver rigtig backend-restore, kan vi her kalde et Tauri-kommando (restore_from_quarantine)
    };

    const handleDeleteQuarantine = (id: number) => {
        // Vi åbner bare confirm-modal og gemmer id’et
        setPendingDeleteId(id);
        setShowDeleteModal(true);
    };


    const handleToggleRealtime = (enabled: boolean) => {
        if (!enabled) {
            setPendingRealtimeValue(false);
            setShowRealtimeConfirm(true);
            return;
        }

        setRealtimeEnabled(true);
        setStatus("protected");
    };

    const confirmDisableRealtime = () => {
        setRealtimeEnabled(false);
        setStatus("not_protected");
        setShowRealtimeConfirm(false);
        setPendingRealtimeValue(null);

        setLogs((prev) => [
            {
                id: prev.length + 1,
                timestamp: new Date().toISOString().slice(0, 16).replace("T", " "),
                scan_type: "realtime",
                result: "clean",
                details: "Real-time protection was turned off by the user.",
            },
            ...prev,
        ]);
    };

    const cancelDisableRealtime = () => {
        setShowRealtimeConfirm(false);
        setPendingRealtimeValue(null);
    };

    const handleLoginSuccess = () => {
        if (typeof window !== "undefined") {
            window.localStorage.setItem("stellar_logged_in", "1");
        }
        setView("antivirus_dashboard");
    };

    const rootClass = isTauri
        ? "w-screen h-screen bg-[#F4F6FB] flex"
        : "min-h-screen bg-[#050816] flex items-center justify-center";

    const shellClass = isTauri
        ? "flex-1 bg-[#F4F6FB] flex flex-col relative min-h-0"
        : "w-[1100px] h-[680px] bg-[#F4F6FB] rounded-[32px] shadow-[0_24px_60px_rgba(15,23,42,0.45)] flex flex-col relative overflow-hidden";

    return (
        <div className={rootClass}>
            <div className={shellClass}>
                {/* Main content */}
                <div className="flex flex-1 min-h-0">
                    {isAntivirusView && (
                        <Sidebar current={currentSidebarView} onChange={handleSidebarChange} />
                    )}

                    <div className="flex-1 flex flex-col min-h-0">
                        {isAntivirusView && <HeaderBar realtimeEnabled={realtimeEnabled} />}

                        <main className="flex-1 px-8 pb-8 overflow-y-auto">
                            {view === "antivirus_dashboard" && (
                                <DashboardScreen
                                    status={status}
                                    realtimeEnabled={realtimeEnabled}
                                    onToggleRealtime={handleToggleRealtime}
                                    onFullScan={startFullScan}
                                    lastScan={lastFullScan}
                                    recentLogs={logs.slice(0, 4)}
                                    scanProgress={scanProgress}
                                    onViewThreats={handleOpenThreatsModal}
                                />
                            )}

                            {view === "antivirus_logs" && (
                                <LogsScreen
                                    logs={logs}
                                    quarantine={quarantine}
                                    onViewThreats={handleOpenThreatsModal}
                                    onRestoreQuarantine={handleRestoreQuarantine}
                                    onDeleteQuarantine={handleDeleteQuarantine}
                                />
                            )}

                            {view === "antivirus_settings" && (
                                <SettingsScreen />
                            )}

                            {view === "login" && (
                                <LoginScreen onAuthenticated={handleLoginSuccess} />
                            )}

                            {view === "register" && (
                                <RegisterScreen onAuthenticated={handleLoginSuccess} />
                            )}
                        </main>
                    </div>
                </div>

                {/* Modal: confirm realtime off */}
                {showRealtimeConfirm && (
                    <div className="absolute inset-0 bg-black/40 flex items-center justify-center z-50">
                        <div className="w-[420px] bg-white rounded-3xl shadow-[0_20px_60px_rgba(15,23,42,0.5)] px-6 py-6">
                            <h3 className="text-sm font-semibold text-[#111827] mb-2">
                                Turn off real-time protection?
                            </h3>
                            <p className="text-xs text-[#6B7280] mb-3">
                                Real-time protection helps block malware the moment it touches your
                                system. If you turn it off, Stellar Antivirus will only scan when you
                                run a manual scan.
                            </p>
                            <p className="text-xs text-[#B91C1C] mb-4">
                                We strongly recommend keeping it enabled unless you know exactly what
                                you&apos;re doing.
                            </p>
                            <div className="flex justify-end gap-2">
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

                {/* Modal: delete quarantined file */}
                {showDeleteModal && (
                    <div className="absolute inset-0 bg-black/40 flex items-center justify-center z-50">
                        <div className="w-[380px] bg-white rounded-3xl shadow-[0_20px_60px_rgba(15,23,42,0.5)] px-6 py-6">
                            <h3 className="text-sm font-semibold text-[#111827] mb-2">
                                Delete file permanently?
                            </h3>
                            <p className="text-xs text-[#6B7280] mb-3">
                                This will permanently delete the selected file from quarantine.
                            </p>
                            <div className="flex justify-end gap-2">
                                <button
                                    onClick={() => {
                                        setShowDeleteModal(false);
                                        setPendingDeleteId(null);
                                    }}
                                    className="px-4 h-9 rounded-full text-xs font-medium border border-[#E5E7EB] text-[#111827] hover:bg-[#F3F4F6]"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={async () => {
                                        if (pendingDeleteId != null) {
                                            const entry = quarantine.find((q) => q.id === pendingDeleteId);
                                            const now = new Date().toISOString().slice(0, 16).replace("T", " ");

                                            // 1) Hvis vi kører inde i Tauri, så bed backend om at slette filen på disk
                                            if (isTauri && entry?.originalPath) {
                                                try {
                                                    await invoke("delete_files", { paths: [entry.originalPath] });
                                                } catch (err) {
                                                    console.error("Failed to delete file on disk:", err);
                                                }
                                            }

                                            // 2) Fjern fra UI-quarantine
                                            setQuarantine((prev) =>
                                                prev.filter((q) => q.id !== pendingDeleteId)
                                            );

                                            // 3) Log handlingen
                                            if (entry) {
                                                setLogs((prev) => [
                                                    {
                                                        id: prev.length + 1,
                                                        timestamp: now,
                                                        scan_type: "full_scan",
                                                        result: "clean",
                                                        details: `Permanently deleted file from quarantine: ${entry.fileName}`,
                                                    },
                                                    ...prev,
                                                ]);
                                            }
                                        }

                                        setShowDeleteModal(false);
                                        setPendingDeleteId(null);
                                    }}
                                    className="px-4 h-9 rounded-full text-xs font-semibold bg-[#DC2626] text-white shadow-[0_10px_30px_rgba(220,38,38,0.6)]"
                                >
                                    Delete
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
