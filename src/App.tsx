import React, { useState, useEffect } from "react";
import Sidebar from "./components/Sidebar";
import HeaderBar from "./components/HeaderBar";
import DashboardScreen from "./screens/DashboardScreen";
import LogsScreen from "./screens/LogsScreen";
import LoginScreen from "./screens/LoginScreen";
import RegisterScreen from "./screens/RegisterScreen";
import SettingsScreen from "./screens/SettingsScreen";
import ThreatsModal from "./components/ThreatsModal";
import type { ProtectionStatus, ScanLogEntry } from "./types";
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

type ScanProgress = {
    current: number;
    total: number;
    file: string;
};

type Threat = {
    id: number;
    fileName: string;
    filePath: string;
    detection: string;
    recommendedAction: "delete" | "quarantine" | "ignore" | string;
};

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

const App: React.FC = () => {
    const [view, setView] = useState<View>(() => {
        if (typeof window !== "undefined") {
            const loggedIn = window.localStorage.getItem("stellar_logged_in");
            return loggedIn === "1" ? "antivirus_dashboard" : "register";
        }
        return "register";
    });
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

    const [quarantine, setQuarantine] = useState<QuarantineEntry[]>([]);
    const [pendingDeleteId, setPendingDeleteId] = useState<number | null>(null);
    const [showDeleteModal, setShowDeleteModal] = useState(false);

    useEffect(() => {
        if (!isTauri) return;

        (async () => {
            try {
                const res = await fetch(
                    "https://stellarantivirusthreatdb.blob.core.windows.net/threat-db/v1/threats.json"
                );

                if (!res.ok) {
                    console.error("Failed to fetch threat DB:", res.status, res.statusText);
                    return;
                }

                const jsonText = await res.text();

                await invoke("update_threat_db", {
                    threatsJson: jsonText,
                });

                console.log("Threat DB updated from Azure");
            } catch (e) {
                console.error("Error updating threat DB:", e);
            }
        })();
    }, []);

    useEffect(() => {
        if (!isTauri) return;

        (async () => {
            try {
                const alreadyEnabled = await isAutostartEnabled();
                if (!alreadyEnabled) {
                    await enableAutostart();
                    console.log("Stellar Antivirus autostart enabled");
                }
            } catch (e) {
                console.error("Failed to enable autostart", e);
            }
        })();
    }, []);

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

    // Lyt efter realtime file events (FSEvents/inotify) og coalescér spam
    useEffect(() => {
        if (!isTauri) return;

        let unlisten: UnlistenFn | null = null;

        listen("realtime_file_event", (event) => {
            const payload = event.payload as any;
            const now = new Date().toISOString().slice(0, 16).replace("T", " ");
            const details = `Real-time protection observed ${payload.event} on ${payload.file}`;

            setLogs((prev) => {
                const last = prev[0];
                if (
                    last &&
                    last.scan_type === "realtime" &&
                    last.details === details
                ) {
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

        // Web preview: fake scan
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

        // Tauri: kald backend
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
                        result: "threats_found",
                        details:
                            "Attempted to quarantine threats, but an error occurred. Please check file permissions.",
                    },
                    ...prev,
                ]);
            }
        } else {
            setQuarantine((prev) => [...newEntries, ...prev]);

            setLogs((prev) => [
                {
                    id: prev.length + 1,
                    timestamp: now,
                    scan_type: "full_scan",
                    result: "clean",
                    details: `${removedCount} threat${
                        removedCount === 1 ? "" : "s"
                    } marked as removed (preview mode).`,
                },
                ...prev,
            ]);
        }

        setThreats((prev) => prev.filter((t) => !ids.includes(t.id)));
        setShowThreatsModal(false);
    };

    const handleRestoreQuarantine = async (id: number) => {
        const entry = quarantine.find((q) => q.id === id);
        if (!entry) return;

        const now = new Date().toISOString().slice(0, 16).replace("T", " ");

        if (isTauri) {
            try {
                await invoke("restore_from_quarantine", {
                    items: [
                        {
                            file_name: entry.fileName,
                            original_path: entry.originalPath,
                        },
                    ],
                });

                setLogs((prev) => [
                    {
                        id: prev.length + 1,
                        timestamp: now,
                        scan_type: "full_scan",
                        result: "clean",
                        details: `Restored file ${entry.fileName} from quarantine.`,
                    },
                    ...prev,
                ]);
            } catch (err) {
                console.error("Restore error:", err);
                setLogs((prev) => [
                    {
                        id: prev.length + 1,
                        timestamp: now,
                        scan_type: "full_scan",
                        result: "threats_found",
                        details: `Failed to restore ${entry.fileName} from quarantine.`,
                    },
                    ...prev,
                ]);
                return;
            }
        }

        setQuarantine((prev) => prev.filter((q) => q.id !== id));
    };

    const handleDeleteQuarantine = (id: number) => {
        setPendingDeleteId(id);
        setShowDeleteModal(true);
    };

    const confirmDeleteQuarantine = async () => {
        if (pendingDeleteId === null) {
            setShowDeleteModal(false);
            return;
        }

        const entry = quarantine.find((q) => q.id === pendingDeleteId);
        if (!entry) {
            setShowDeleteModal(false);
            setPendingDeleteId(null);
            return;
        }

        const now = new Date().toISOString().slice(0, 16).replace("T", " ");

        if (isTauri) {
            try {
                await invoke("delete_quarantine_files", {
                    fileNames: [entry.fileName],
                });

                setLogs((prev) => [
                    {
                        id: prev.length + 1,
                        timestamp: now,
                        scan_type: "full_scan",
                        result: "clean",
                        details: `Deleted quarantined file ${entry.fileName}.`,
                    },
                    ...prev,
                ]);
            } catch (err) {
                console.error("Delete quarantine error:", err);
                setLogs((prev) => [
                    {
                        id: prev.length + 1,
                        timestamp: now,
                        scan_type: "full_scan",
                        result: "threats_found",
                        details: `Failed to delete quarantined file ${entry.fileName}.`,
                    },
                    ...prev,
                ]);
                setShowDeleteModal(false);
                setPendingDeleteId(null);
                return;
            }
        }

        setQuarantine((prev) => prev.filter((q) => q.id !== pendingDeleteId));
        setShowDeleteModal(false);
        setPendingDeleteId(null);
    };

    const cancelDeleteQuarantine = () => {
        setShowDeleteModal(false);
        setPendingDeleteId(null);
    };

    const handleLogout = () => {
        if (typeof window !== "undefined") {
            window.localStorage.removeItem("stellar_logged_in");
        }
        setView("login");
    };


    const handleAuthenticated = () => {
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
        : "w-[1100px] h-[680px] bg-[#F4F6FB] rounded-[32px] shadow-[0_24px_80px_rgba(15,23,42,0.45)] flex flex-col relative overflow-hidden";

    return (
        <div className={rootClass}>
            <div className={shellClass}>
                {/* Main content */}
                <div className="flex flex-1 min-h-0">
                {isAntivirusView && (
                        <Sidebar current={currentSidebarView} onChange={handleSidebarChange} />
                    )}

                    <div className="flex-1 flex flex-col min-h-0">

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
                                <LogsScreen
                                    logs={logs}
                                    quarantine={quarantine}
                                    onViewThreats={handleOpenThreatsModal}
                                    onRestoreQuarantine={handleRestoreQuarantine}
                                    onDeleteQuarantine={handleDeleteQuarantine}
                                />
                            )}
                            {view === "antivirus_settings" && (
                                <SettingsScreen onLogout={handleLogout} />
                            )}
                            {view === "login" && (
                                <LoginScreen onAuthenticated={handleAuthenticated} />
                            )}
                            {view === "register" && (
                                <RegisterScreen onAuthenticated={handleAuthenticated} />
                            )}
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

                {/* Modal: delete quarantined file */}
                {showDeleteModal && (
                    <div className="absolute inset-0 bg-black/40 flex items-center justify-center z-50">
                        <div className="w-[380px] bg-white rounded-3xl shadow-[0_20px_60px_rgba(15,23,42,0.5)] px-6 py-6">
                            <h3 className="text-sm font-semibold text-[#111827] mb-2">
                                Delete file permanently?
                            </h3>
                            <p className="text-xs text-[#6B7280] mb-3">
                                This will permanently delete the selected file from quarantine.
                                This action cannot be undone.
                            </p>
                            <p className="text-[11px] text-[#9CA3AF] mb-4">
                                We only recommend permanent deletion if you are sure this file
                                is not needed and is unsafe to keep.
                            </p>
                            <div className="flex justify-end gap-2 mt-2">
                                <button
                                    onClick={cancelDeleteQuarantine}
                                    className="px-4 h-9 rounded-full text-xs font-medium border border-[#E5E7EB] text-[#111827] hover:bg-[#F3F4F6]"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={confirmDeleteQuarantine}
                                    className="px-4 h-9 rounded-full text-xs font-semibold bg-[#DC2626] text-white shadow-[0_10px_30px_rgba(220,38,38,0.6)] hover:bg-[#B91C1C]"
                                >
                                    Delete permanently
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
