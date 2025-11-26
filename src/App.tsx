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
import {
    isEnabled as isAutostartEnabled,
    enable as enableAutostart,
} from "@tauri-apps/plugin-autostart";

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { UnlistenFn } from "@tauri-apps/api/event";

const THREAT_DB_URL =
    (import.meta as any).env?.VITE_THREAT_DB_URL ?? '';

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
    typeof window !== "undefined" && !!(window as any).__TAURI_INTERNALS__;

// --- Helper: merge threats by filePath (undgå dubletter) ---
const mergeThreatsByPath = (existing: Threat[], incoming: Threat[]): Threat[] => {
    const byPath = new Map<string, Threat>();

    for (const t of existing) {
        if (t.filePath) {
            byPath.set(t.filePath, t);
        }
    }
    for (const t of incoming) {
        if (t.filePath) {
            byPath.set(t.filePath, t);
        }
    }

    return Array.from(byPath.values());
};

// --- Helper: notifications ---
const canUseNotifications =
    typeof window !== "undefined" && "Notification" in window;

const showNotification = (title: string, body: string) => {
    if (!canUseNotifications) return;
    if (Notification.permission !== "granted") return;
    try {
        new Notification(title, { body });
    } catch {
        // ignore
    }
};

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

    // ✅ ingen sample data – starter tomt
    const [logs, setLogs] = useState<ScanLogEntry[]>([]);
    const [scanProgress, setScanProgress] = useState<ScanProgress>({
        current: 0,
        total: 0,
        file: "",
    });

    const [showRealtimeConfirm, setShowRealtimeConfirm] = useState(false);
    const [pendingRealtimeValue, setPendingRealtimeValue] =
        useState<boolean | null>(null);

    const [showThreatsModal, setShowThreatsModal] = useState(false);
    const [threats, setThreats] = useState<Threat[]>([]);

    const [quarantine, setQuarantine] = useState<QuarantineEntry[]>([]);
    const [pendingDeleteId, setPendingDeleteId] = useState<number | null>(null);
    const [showDeleteModal, setShowDeleteModal] = useState(false);

    // --- Notifikationstilladelse én gang ---
    useEffect(() => {
        if (!canUseNotifications) return;
        if (Notification.permission === "default") {
            Notification.requestPermission().catch(() => {});
        }
    }, []);

    // --- Hent gemte logs/threats/quarantine fra localStorage (persistens) ---
    useEffect(() => {
        if (typeof window === "undefined") return;

        try {
            const rawLogs = window.localStorage.getItem("stellar_logs");
            if (rawLogs) {
                const parsed = JSON.parse(rawLogs) as ScanLogEntry[];
                setLogs(parsed);
            }
        } catch {
            // ignore
        }

        try {
            const rawThreats = window.localStorage.getItem("stellar_threats");
            if (rawThreats) {
                const parsed = JSON.parse(rawThreats) as Threat[];
                setThreats(parsed);
            }
        } catch {
            // ignore
        }

        try {
            const rawQ = window.localStorage.getItem("stellar_quarantine");
            if (rawQ) {
                const parsed = JSON.parse(rawQ) as QuarantineEntry[];
                setQuarantine(parsed);
            }
        } catch {
            // ignore
        }
    }, []);

    // --- Gem til localStorage når ting ændrer sig ---
    useEffect(() => {
        if (typeof window === "undefined") return;
        window.localStorage.setItem("stellar_logs", JSON.stringify(logs));
    }, [logs]);

    useEffect(() => {
        if (typeof window === "undefined") return;
        window.localStorage.setItem("stellar_threats", JSON.stringify(threats));
    }, [threats]);

    useEffect(() => {
        if (typeof window === "undefined") return;
        window.localStorage.setItem("stellar_quarantine", JSON.stringify(quarantine));
    }, [quarantine]);

    // --- Hent Threat DB fra Azure ved start ---
// Auto-update Threat DB from Azure every hour
    useEffect(() => {
        if (!isTauri) return;

        let stopped = false;

        const syncThreatDb = async () => {
            if (stopped) return;

            try {
                const res = await fetch(THREAT_DB_URL, {
                    cache: "no-store",
                } as RequestInit);

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

                console.log(
                    "[Stellar AV] Threat DB synced at",
                    new Date().toISOString()
                );
            } catch (err) {
                console.error("Error updating threat DB:", err);
            }
        };

        // 1) Sync med det samme ved opstart
        syncThreatDb();

        // 2) Sync hver time
        const intervalId = window.setInterval(() => {
            syncThreatDb();
        }, 60 * 60 * 1000); // 1 hour

        // Cleanup når appen lukkes / komponenten unmountes
        return () => {
            stopped = true;
            window.clearInterval(intervalId);
        };
    }, []);

    // --- Autostart ---
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

    // --- Lyt på scan_progress + scan_finished ---
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

            const now = new Date();
            const ts = now.toISOString().slice(0, 16).replace("T", " ");

            setStatus(realtimeEnabled ? "protected" : "not_protected");

            if (threatsArray.length > 0) {
                const nowIso = now.toISOString();
                const mapped: Threat[] = threatsArray.map((t, idx) => ({
                    id: Date.now() + idx,
                    fileName: t[0],
                    filePath: t[1],
                    detection: "Malware.Generic",
                    recommendedAction: "delete",
                    detectedAt: nowIso,
                    source: "full_scan",
                    status: "active",
                }));

                setThreats((prev) => mergeThreatsByPath(prev, mapped));
                setShowThreatsModal(true);

                showNotification(
                    "Stellar Antivirus – threats found",
                    `${mapped.length} threat${
                        mapped.length === 1 ? "" : "s"
                    } detected during full scan.`
                );

                setLogs((prev) => {
                    const details = `${mapped.length} threats were found in system scan.`;
                    const last = prev[0];
                    if (
                        last &&
                        last.scan_type === "full_scan" &&
                        last.result === "threats_found" &&
                        last.timestamp === ts &&
                        last.details === details
                    ) {
                        return prev;
                    }
                    return [
                        {
                            id: prev.length + 1,
                            timestamp: ts,
                            scan_type: "full_scan",
                            result: "threats_found",
                            details,
                        },
                        ...prev,
                    ];
                });
            } else {
                showNotification(
                    "Stellar Antivirus – scan completed",
                    "Full system scan finished. No threats found."
                );

                setLogs((prev) => {
                    const details = "Full system scan completed. No threats found.";
                    const last = prev[0];
                    if (
                        last &&
                        last.scan_type === "full_scan" &&
                        last.result === "clean" &&
                        last.timestamp === ts &&
                        last.details === details
                    ) {
                        return prev;
                    }
                    return [
                        {
                            id: prev.length + 1,
                            timestamp: ts,
                            scan_type: "full_scan",
                            result: "clean",
                            details,
                        },
                        ...prev,
                    ];
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

    // --- Realtime threat detected (fra Rust) ---
    useEffect(() => {
        if (!isTauri) return;

        let unlistenRealtime: UnlistenFn | null = null;

        listen("realtime_threat_detected", (event) => {
            const payload = event.payload as any;
            const threatsArray = (payload.threats as [string, string][]) || [];
            if (!threatsArray.length) return;

            const now = new Date();
            const nowIso = now.toISOString();
            const ts = nowIso.slice(0, 16).replace("T", " ");

            const mapped: Threat[] = threatsArray.map((t, idx) => ({
                id: Date.now() + idx,
                fileName: t[0],
                filePath: t[1],
                detection: "Realtime.Detected",
                recommendedAction: "delete",
                detectedAt: nowIso,
                source: "realtime",
                status: "active",
            }));

            setThreats((prev) => mergeThreatsByPath(prev, mapped));
            setShowThreatsModal(true);

            showNotification(
                "Stellar Antivirus – threat blocked",
                `${mapped.length} threat${
                    mapped.length === 1 ? "" : "s"
                } blocked in real-time.`
            );

            setLogs((prev) => {
                const details = `Real-time protection blocked ${mapped.length} threat${
                    mapped.length === 1 ? "" : "s"
                }.`;
                const last = prev[0];
                if (
                    last &&
                    last.scan_type === "realtime" &&
                    last.result === "threats_found" &&
                    last.timestamp === ts &&
                    last.details === details
                ) {
                    return prev;
                }

                return [
                    {
                        id: prev.length + 1,
                        timestamp: ts,
                        scan_type: "realtime",
                        result: "threats_found",
                        details,
                    },
                    ...prev,
                ];
            });
        }).then((fn) => {
            unlistenRealtime = fn;
        });

        return () => {
            if (unlistenRealtime) unlistenRealtime();
        };
    }, []);

    const startFullScan = async () => {
        if (!isTauri) {
            // Browser-demo fallback
            setStatus("scanning");
            setScanProgress({ current: 0, total: 100, file: "Simulating scan..." });

            let current = 0;
            const interval = setInterval(() => {
                current += 5;
                if (current >= 100) {
                    clearInterval(interval);
                    setStatus(realtimeEnabled ? "protected" : "not_protected");
                    setScanProgress({ current: 0, total: 0, file: "" });
                } else {
                    setScanProgress({ current, total: 100, file: "Simulating scan..." });
                }
            }, 200);

            return;
        }

        try {
            setStatus("scanning");
            setScanProgress({ current: 0, total: 0, file: "" });
            await invoke("fake_full_scan");
        } catch (err) {
            console.error("Scan error:", err);
            setStatus(realtimeEnabled ? "protected" : "not_protected");
            const ts = new Date().toISOString().slice(0, 16).replace("T", " ");
            setLogs((prev) => [
                {
                    id: prev.length + 1,
                    timestamp: ts,
                    scan_type: "full_scan",
                    result: "clean",
                    details: "Scan failed or Tauri backend not available.",
                },
                ...prev,
            ]);
            setScanProgress({ current: 0, total: 0, file: "" });
        }
    };

    const lastFullScan = logs.find((l) => l.scan_type === "full_scan") || null;

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

    // Flyt valgte threats til quarantine + log + backend delete/quarantine
    const handleRemoveThreats = async (ids: number[]) => {
        const nowIso = new Date().toISOString();
        const ts = nowIso.slice(0, 16).replace("T", " ");

        const selectedThreats = threats.filter((t) => ids.includes(t.id));
        const removedCount = selectedThreats.length;
        if (!removedCount) {
            setShowThreatsModal(false);
            return;
        }

        const paths = selectedThreats
            .map((t) => t.filePath)
            .filter((p) => !!p);

        const newEntries: QuarantineEntry[] = selectedThreats.map((t, idx) => ({
            id: quarantine.length + idx + 1,
            fileName: t.fileName || t.filePath,
            originalPath: t.filePath,
            quarantinedAt: ts,
            detection: t.detection || "Threat",
        }));

        if (isTauri && paths.length > 0) {
            try {
                await invoke("quarantine_files", { paths });

                setQuarantine((prev) => [...newEntries, ...prev]);

                setLogs((prev) => [
                    {
                        id: prev.length + 1,
                        timestamp: ts,
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
                        timestamp: ts,
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
                    timestamp: ts,
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

        const now = new Date();
        const ts = now.toISOString().slice(0, 16).replace("T", " ");

        setQuarantine((prev) => prev.filter((q) => q.id !== id));

        setLogs((prev) => [
            {
                id: prev.length + 1,
                timestamp: ts,
                scan_type: "realtime",
                result: "clean",
                details: `Restored file from quarantine: ${entry.fileName}`,
            },
            ...prev,
        ]);

        // evt. senere: invoke("restore_from_quarantine", ...)
    };

    const handleDeleteQuarantine = async (id: number) => {
        const entry = quarantine.find((q) => q.id === id);
        if (!entry) return;

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
        if (isTauri) {
            invoke("set_realtime_enabled", { enabled: true }).catch(() => {});
        }
    };

    const confirmDisableRealtime = () => {
        setRealtimeEnabled(false);
        setStatus("not_protected");
        setShowRealtimeConfirm(false);
        setPendingRealtimeValue(null);

        if (isTauri) {
            invoke("set_realtime_enabled", { enabled: false }).catch(() => {});
        }

        const ts = new Date().toISOString().slice(0, 16).replace("T", " ");
        setLogs((prev) => [
            {
                id: prev.length + 1,
                timestamp: ts,
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
                <div className="flex flex-1 min-h-0">
                    {isAntivirusView && (
                        <Sidebar
                            current={currentSidebarView}
                            onChange={handleSidebarChange}
                        />
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

                            {view === "antivirus_settings" && <SettingsScreen />}

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
                                Real-time protection helps block malware the moment it touches
                                your system. If you turn it off, Stellar Antivirus will only
                                scan when you run a manual scan.
                            </p>
                            <p className="text-xs text-[#B91C1C] mb-4">
                                We strongly recommend keeping it enabled unless you know exactly
                                what you&apos;re doing.
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
                                    onClick={() => setShowDeleteModal(false)}
                                    className="px-4 h-9 rounded-full text-xs font-medium border border-[#E5E7EB] text-[#111827] hover:bg-[#F3F4F6]"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={async () => {
                                        if (pendingDeleteId != null) {
                                            const entry = quarantine.find(
                                                (q) => q.id === pendingDeleteId
                                            );
                                            if (entry && isTauri) {
                                                try {
                                                    await invoke("delete_quarantine_files", {
                                                        fileNames: [entry.fileName],
                                                    });
                                                } catch (err) {
                                                    console.error("Failed to delete quarantine file", err);
                                                }
                                            }
                                            setQuarantine((prev) =>
                                                prev.filter((q) => q.id !== pendingDeleteId)
                                            );
                                        }
                                        setShowDeleteModal(false);
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

export default App;
