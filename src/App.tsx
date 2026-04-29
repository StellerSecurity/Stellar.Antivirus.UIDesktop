import React, { useState, useEffect, useRef } from "react";
import Sidebar from "./components/Sidebar";
import HeaderBar from "./components/HeaderBar";
import DashboardScreen from "./screens/DashboardScreen";
import LogsScreen from "./screens/LogsScreen";
import SettingsScreen from "./screens/SettingsScreen";
import OnboardingScreen from "./screens/OnboardingScreen";
import ThreatsModal from "./components/ThreatsModal";
import Button from "./components/Button";
import type {
  ProtectionStatus,
  ScanLogEntry,
  Threat,
  QuarantineEntry,
} from "./types";
import {
  isEnabled as isAutostartEnabled,
  enable as enableAutostart,
} from "@tauri-apps/plugin-autostart";
import {
  isPermissionGranted as isNotificationPermissionGranted,
  requestPermission as requestNotificationPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { UnlistenFn } from "@tauri-apps/api/event";

import { fetchDashboard } from "./api/dashboard";
import type { DashboardResponse } from "./api/dashboard";
import Img from "../public/Icon-toffee.svg";
import Img1 from "../public/Icon-x-circle.svg";

type View =
    | "onboarding_step1"
    | "onboarding_step2"
    | "onboarding_step3"
    | "onboarding_step4"
    | "antivirus_dashboard"
    | "antivirus_logs"
    | "antivirus_settings";

type SidebarView = "dashboard" | "logs" | "settings";

interface ScanProgress {
  current: number;
  total: number;
  file: string;
}

// Detect if we are running inside Tauri or in the browser
const isTauri =
    typeof window !== "undefined" && !!(window as any).__TAURI_INTERNALS__;

// LocalStorage keys (DO NOT CHANGE)
const STORAGE_KEYS = {
  token: "stellar_auth_token",
  onboardingSeen: "stellar_onboarding_seen",
  permissionsGranted: "stellar_permissions_granted",
  dashboard: "stellar_dashboard",
  logs: "stellar_logs",
  threats: "stellar_threats",
  quarantine: "stellar_quarantine",
};

const canUseNotifications =
    typeof window !== "undefined" && "Notification" in window;

const showNotification = (title: string, body: string) => {
  void (async () => {
    try {
      if (isTauri) {
        const granted = await isNotificationPermissionGranted();
        if (!granted) return;
        sendNotification({ title, body });
        return;
      }

      if (!canUseNotifications) return;
      if (Notification.permission !== "granted") return;
      new Notification(title, { body });
    } catch (err) {
      console.error("Failed to show notification:", err);
    }
  })();
};

const getInitialToken = (): string | null => {
  if (typeof window !== "undefined") {
    return window.localStorage.getItem(STORAGE_KEYS.token);
  }
  return null;
};

const getInitialDashboard = (): DashboardResponse | null => {
  if (typeof window !== "undefined") {
    const raw = window.localStorage.getItem(STORAGE_KEYS.dashboard);
    if (raw) {
      try {
        return JSON.parse(raw) as DashboardResponse;
      } catch {
        return null;
      }
    }
  }
  return null;
};

// Keep auto-login logic intact
const getInitialView = (): View => {
  if (typeof window === "undefined") return "onboarding_step1";

  const hasToken = !!window.localStorage.getItem(STORAGE_KEYS.token);
  const permissionsGranted =
      window.localStorage.getItem(STORAGE_KEYS.permissionsGranted) === "1";
  const onboardingSeen =
      window.localStorage.getItem(STORAGE_KEYS.onboardingSeen) === "1";

  if (hasToken && permissionsGranted) return "antivirus_dashboard";
  if (hasToken) return "onboarding_step4";
  if (onboardingSeen) return "onboarding_step3";

  return "onboarding_step1";
};

// Helper: merge threats by filePath so we do not show duplicates
const mergeThreatsByPath = (existing: Threat[], incoming: Threat[]): Threat[] => {
  const byPath = new Map<string, Threat>();

  for (const t of existing) {
    if (t.filePath) byPath.set(t.filePath, t);
  }
  for (const t of incoming) {
    if (t.filePath) byPath.set(t.filePath, t);
  }

  return Array.from(byPath.values());
};

const baseNameFromPath = (p: string): string => {
  const normalized = (p ?? "").toString().replace(/\\/g, "/");
  const parts = normalized.split("/");
  const last = parts[parts.length - 1];
  return last && last.length > 0 ? last : normalized;
};

const formatQuarantineTimestamp = (value?: number): string => {
  if (!value) return new Date().toISOString().slice(0, 16).replace("T", " ");
  const millis = value > 10_000_000_000 ? value : value * 1000;
  return new Date(millis).toISOString().slice(0, 16).replace("T", " ");
};

type ScanStatsPayload = {
  files_discovered?: number;
  files_hashed?: number;
  files_skipped?: number;
  threats_found?: number;
  eicar_found?: number;
  duration_ms?: number;
  cancelled?: boolean;
  cloud_hashes_queued?: number;
  cloud_hashes_checked?: number;
  cloud_hashes_failed?: number;
  cloud_batches_total?: number;
  cloud_batches_succeeded?: number;
  cloud_batches_failed?: number;
  cloud_retry_count?: number;
  file_hash_cache_hits?: number;
  verdict_cache_hits?: number;
  cloud_hashes_skipped_cached?: number;
  completed_with_warnings?: boolean;
};


// Optional: avoid duplicate log spam within same minute for same scan_type/result/details
const pushLogDedup = (prev: ScanLogEntry[], entry: ScanLogEntry) => {
  const last = prev[0];
  if (!last) return [entry, ...prev];

  if (
      last.scan_type === entry.scan_type &&
      last.result === entry.result &&
      last.timestamp === entry.timestamp &&
      last.details === entry.details
  ) {
    return prev;
  }
  return [entry, ...prev];
};

// Rust probe payload (must match your tauri command)
type FsAccessProbe = {
  label: string;
  path: string;
  ok: boolean;
  error?: string | null;
};

type QuarantineResult = {
  quarantine_id: string;
  original_path: string;
  quarantine_file_name: string;
  display_name: string;
  detection?: string | null;
  quarantined_at?: number;
};

const App: React.FC = () => {
  const [view, setView] = useState<View>(getInitialView);

  const [status, setStatus] = useState<ProtectionStatus>("protected");
  const [realtimeEnabled, setRealtimeEnabled] = useState<boolean>(true);

  const [token, setToken] = useState<string | null>(getInitialToken);
  const [dashboard, setDashboard] = useState<DashboardResponse | null>(
      getInitialDashboard
  );

  const [logs, setLogs] = useState<ScanLogEntry[]>([]);

  const [scanProgress, setScanProgress] = useState<ScanProgress>({
    current: 0,
    total: 0,
    file: "",
  });

  const lastProgressRef = useRef<ScanProgress>({
    current: 0,
    total: 0,
    file: "",
  });

  // Which scan started the current run (UI-only labeling)
  const activeScanRef = useRef<"full" | "quick" | null>(null);

  const scanIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const [showRealtimeConfirm, setShowRealtimeConfirm] = useState(false);

  const [showThreatsModal, setShowThreatsModal] = useState(false);
  const [threats, setThreats] = useState<Threat[]>([]);

  const [quarantine, setQuarantine] = useState<QuarantineEntry[]>([]);
  const [pendingDeleteId, setPendingDeleteId] = useState<number | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);

  // Load stored logs/threats/quarantine from localStorage
  useEffect(() => {
    if (typeof window === "undefined") return;

    try {
      const rawLogs = window.localStorage.getItem(STORAGE_KEYS.logs);
      if (rawLogs) setLogs(JSON.parse(rawLogs) as ScanLogEntry[]);
    } catch {}

    try {
      const rawThreats = window.localStorage.getItem(STORAGE_KEYS.threats);
      if (rawThreats) setThreats(JSON.parse(rawThreats) as Threat[]);
    } catch {}

    try {
      const rawQ = window.localStorage.getItem(STORAGE_KEYS.quarantine);
      if (rawQ) setQuarantine(JSON.parse(rawQ) as QuarantineEntry[]);
    } catch {}
  }, []);

  // Load backend-owned quarantine manifest so quarantine view works after restart and after real-time quarantine.
  useEffect(() => {
    if (!isTauri) return;

    (async () => {
      try {
        const items = await invoke<QuarantineResult[]>("list_quarantine_items");
        const mapped: QuarantineEntry[] = items.map((item, idx) => ({
          id: Date.now() + idx,
          quarantineId: item.quarantine_id,
          fileName: item.display_name || baseNameFromPath(item.original_path),
          quarantineFileName: item.quarantine_file_name,
          originalPath: item.original_path,
          quarantinedAt: formatQuarantineTimestamp(item.quarantined_at),
          detection: item.detection || "Threat",
          source: "realtime",
        }));

        setQuarantine((prev) => {
          const byKey = new Map<string, QuarantineEntry>();
          for (const entry of prev) {
            byKey.set(entry.quarantineId || entry.quarantineFileName || entry.originalPath, entry);
          }
          for (const entry of mapped) {
            byKey.set(entry.quarantineId || entry.quarantineFileName || entry.originalPath, entry);
          }
          return Array.from(byKey.values());
        });
      } catch (err) {
        console.error("Failed to load quarantine manifest:", err);
      }
    })();
  }, []);

  // Persist logs/threats/quarantine
  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(STORAGE_KEYS.logs, JSON.stringify(logs));
  }, [logs]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(STORAGE_KEYS.threats, JSON.stringify(threats));
  }, [threats]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(
        STORAGE_KEYS.quarantine,
        JSON.stringify(quarantine)
    );
  }, [quarantine]);

  // Request native notification permission once so background/tray notifications can be shown on macOS.
  useEffect(() => {
    if (!isTauri) return;

    (async () => {
      try {
        const granted = await isNotificationPermissionGranted();
        if (!granted) {
          await requestNotificationPermission();
        }
      } catch (err) {
        console.error("Failed to request notification permission:", err);
      }
    })();
  }, []);

  // Configure autostart for Tauri
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

  // Show a visible "100%" completion moment, then clear progress to idle.
  const holdCompletionMomentThenClear = () => {
    const last = lastProgressRef.current;

    if (last.total > 0) {
      setScanProgress({ current: last.total, total: last.total, file: "" });
    } else {
      // Fallback so UI can still display "complete" even if backend never sent totals.
      setScanProgress({ current: 1, total: 1, file: "" });
    }

    if (typeof window !== "undefined") {
      window.setTimeout(() => {
        setScanProgress({ current: 0, total: 0, file: "" });
        lastProgressRef.current = { current: 0, total: 0, file: "" };
      }, 1200);
    } else {
      setScanProgress({ current: 0, total: 0, file: "" });
      lastProgressRef.current = { current: 0, total: 0, file: "" };
    }
  };

  // Listen for scan_progress + scan_finished events from Rust backend
  useEffect(() => {
    if (!isTauri) return;

    let unlistenProgress: UnlistenFn | null = null;
    let unlistenFinished: UnlistenFn | null = null;

    listen("scan_progress", (event) => {
      const payload = event.payload as any;

      const next: ScanProgress = {
        current: payload.current ?? 0,
        total: payload.total ?? 0,
        file: payload.file ?? "",
      };

      lastProgressRef.current = next;
      setScanProgress(next);
    }).then((fn) => {
      unlistenProgress = fn;
    });

    listen("scan_finished", (event) => {
      const payload = event.payload as any;
      const threatsArray = (payload.threats as [string, string][]) || [];
      const scanStats = payload.stats as ScanStatsPayload | undefined;

      const now = new Date();
      const ts = now.toISOString().slice(0, 16).replace("T", " ");

      const rawScanKind = typeof payload.scan_kind === "string" ? payload.scan_kind : null;
      const payloadScanKind = rawScanKind === "quick_scan" || rawScanKind === "quick"
          ? "quick"
          : rawScanKind === "full_scan" || rawScanKind === "full"
              ? "full"
              : null;
      const activeScanKind = payloadScanKind ?? activeScanRef.current ?? "full";
      const scanLabel = payload.scan_label || (activeScanKind === "quick" ? "Quick scan" : "Full scan");
      const scanLogType = activeScanKind === "quick" ? "quick_scan" : "full_scan";
      const completedWithWarnings = Boolean(scanStats?.completed_with_warnings);

      if (threatsArray.length > 0) {
        const nowIso = now.toISOString();
        const mapped: Threat[] = threatsArray.map((t, idx) => {
          const detection = t[0];
          const filePath = t[1];

          return {
            id: Date.now() + idx,
            fileName: baseNameFromPath(filePath),
            filePath,
            detection,
            recommendedAction: "delete",
            detectedAt: nowIso,
            source: scanLogType,
            status: "active",
          };
        });

        setStatus("at_risk");
        setThreats((prev) => mergeThreatsByPath(prev, mapped));
        setShowThreatsModal(true);

        setLogs((prev) =>
            pushLogDedup(prev, {
              id: prev.length + 1,
              timestamp: ts,
              scan_type: scanLogType,
              result: "threats_found",
              details: `${scanLabel} found ${mapped.length} threat${
                  mapped.length === 1 ? "" : "s"
              }.`,
            })
        );
      } else {
        setStatus(realtimeEnabled ? "protected" : "not_protected");

        setLogs((prev) =>
            pushLogDedup(prev, {
              id: prev.length + 1,
              timestamp: ts,
              scan_type: scanLogType,
              result: completedWithWarnings ? "completed_with_warnings" : "clean",
              details: completedWithWarnings
                  ? `${scanLabel} completed. Some items need attention.`
                  : `${scanLabel} completed. No threats found.`,
            })
        );
      }

      // End current scan label
      activeScanRef.current = null;

      // Make completion visible, then clear to idle.
      holdCompletionMomentThenClear();
    }).then((fn) => {
      unlistenFinished = fn;
    });

    return () => {
      if (unlistenProgress) unlistenProgress();
      if (unlistenFinished) unlistenFinished();
    };
  }, [realtimeEnabled]);

  // Listen for real-time threats from Rust backend
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

      const mapped: Threat[] = threatsArray.map((t, idx) => {
        const detection = t[0];
        const filePath = t[1];

        return {
          id: Date.now() + idx,
          fileName: baseNameFromPath(filePath),
          filePath,
          detection,
          recommendedAction: "quarantine",
          detectedAt: nowIso,
          source: "realtime",
          status: "active",
        };
      });

      setThreats((prev) => mergeThreatsByPath(prev, mapped));
      setShowThreatsModal(true);

      showNotification(
          "Stellar Antivirus – threat detected",
          `${mapped.length} threat${mapped.length === 1 ? "" : "s"} detected in real-time.`
      );

      setLogs((prev) =>
          pushLogDedup(prev, {
            id: prev.length + 1,
            timestamp: ts,
            scan_type: "realtime",
            result: "threats_found",
            details: `Real-time protection detected ${mapped.length} threat${
                mapped.length === 1 ? "" : "s"
            }.`,
          })
      );

      setStatus("at_risk");
    }).then((fn) => {
      unlistenRealtime = fn;
    });

    listen("realtime_threat_quarantined", (event) => {
      const payload = event.payload as QuarantineResult;
      if (!payload?.original_path) return;

      const now = new Date();
      const ts = now.toISOString().slice(0, 16).replace("T", " ");

      const entry: QuarantineEntry = {
        id: Date.now(),
        quarantineId: payload.quarantine_id,
        fileName: payload.display_name || baseNameFromPath(payload.original_path),
        quarantineFileName: payload.quarantine_file_name,
        originalPath: payload.original_path,
        quarantinedAt: formatQuarantineTimestamp(payload.quarantined_at),
        detection: payload.detection || "Threat",
        source: "realtime",
      };

      setQuarantine((prev) => [
        entry,
        ...prev.filter((q) => q.originalPath !== entry.originalPath),
      ]);
      setThreats((prev) => prev.filter((t) => t.filePath !== entry.originalPath));
      setStatus(realtimeEnabled ? "protected" : "not_protected");

      showNotification(
        "Stellar Antivirus – threat quarantined",
        `${entry.fileName} was automatically quarantined.`
      );

      setLogs((prev) =>
        pushLogDedup(prev, {
          id: prev.length + 1,
          timestamp: ts,
          scan_type: "realtime",
          result: "clean",
          details: `Real-time protection quarantined: ${entry.fileName}.`,
        })
      );
    }).then((fn) => {
      const existing = unlistenRealtime;
      unlistenRealtime = () => {
        existing?.();
        fn();
      };
    });

    return () => {
      if (unlistenRealtime) unlistenRealtime();
    };
  }, []);

  const startFullScan = async () => {
    // Stop any demo interval first
    if (scanIntervalRef.current) {
      clearInterval(scanIntervalRef.current);
      scanIntervalRef.current = null;
    }

    activeScanRef.current = "full";

    if (!isTauri) {
      // Browser demo fallback
      setStatus("scanning");
      setScanProgress({ current: 0, total: 100, file: "" });

      let current = 0;
      const interval = setInterval(() => {
        current += 5;
        if (current >= 100) {
          clearInterval(interval);
          scanIntervalRef.current = null;
          setStatus(realtimeEnabled ? "protected" : "not_protected");
          setScanProgress({ current: 1, total: 1, file: "" });

          window.setTimeout(() => {
            setScanProgress({ current: 0, total: 0, file: "" });
          }, 1200);
        } else {
          setScanProgress({ current, total: 100, file: "" });
        }
      }, 200);

      scanIntervalRef.current = interval;
      return;
    }

    try {
      setStatus("scanning");
      setScanProgress({ current: 0, total: 0, file: "" });
      await invoke("fake_full_scan");
    } catch (err) {
      console.error("Scan error:", err);
      activeScanRef.current = null;
      setStatus(realtimeEnabled ? "protected" : "not_protected");
      const ts = new Date().toISOString().slice(0, 16).replace("T", " ");
      setLogs((prev) =>
          pushLogDedup(prev, {
            id: prev.length + 1,
            timestamp: ts,
            scan_type: "full_scan",
            result: "failed",
            details: "Scan failed or Tauri backend not available.",
          })
      );
      setScanProgress({ current: 0, total: 0, file: "" });
    }
  };

  const startQuickScan = async () => {
    // Stop any demo interval first
    if (scanIntervalRef.current) {
      clearInterval(scanIntervalRef.current);
      scanIntervalRef.current = null;
    }

    activeScanRef.current = "quick";

    if (!isTauri) {
      // Browser demo fallback (faster)
      setStatus("scanning");
      setScanProgress({ current: 0, total: 40, file: "" });

      let current = 0;
      const interval = setInterval(() => {
        current += 2;
        if (current >= 40) {
          clearInterval(interval);
          scanIntervalRef.current = null;
          setStatus(realtimeEnabled ? "protected" : "not_protected");
          setScanProgress({ current: 1, total: 1, file: "" });

          window.setTimeout(() => {
            setScanProgress({ current: 0, total: 0, file: "" });
          }, 1200);
        } else {
          setScanProgress({ current, total: 40, file: "" });
        }
      }, 120);

      scanIntervalRef.current = interval;
      return;
    }

    try {
      setStatus("scanning");
      setScanProgress({ current: 0, total: 0, file: "" });
      await invoke("quick_scan");
    } catch (err) {
      console.error("Quick scan error:", err);
      activeScanRef.current = null;
      setStatus(realtimeEnabled ? "protected" : "not_protected");
      const ts = new Date().toISOString().slice(0, 16).replace("T", " ");
      setLogs((prev) =>
          pushLogDedup(prev, {
            id: prev.length + 1,
            timestamp: ts,
            scan_type: "quick_scan",
            result: "failed",
            details: "Quick scan failed or Tauri backend not available.",
          })
      );
      setScanProgress({ current: 0, total: 0, file: "" });
    }
  };

  const stopFullScan = async () => {
    if (scanIntervalRef.current) {
      clearInterval(scanIntervalRef.current);
      scanIntervalRef.current = null;
    }

    if (isTauri) {
      try {
        await invoke("cancel_scan");
      } catch (err) {
        console.error("Failed to cancel scan:", err);
      }
    }

    activeScanRef.current = null;
    setStatus(realtimeEnabled ? "protected" : "not_protected");
    setScanProgress({ current: 0, total: 0, file: "" });
    lastProgressRef.current = { current: 0, total: 0, file: "" };
  };

  const lastManualScan = logs.find((l) => l.scan_type === "quick_scan" || l.scan_type === "full_scan") || null;

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

  const handleOpenActivityLog = () => setView("antivirus_logs");
  const handleClearLogs = () => setLogs([]);
  const handleOpenThreatsModal = () => setShowThreatsModal(true);

  const handleRemoveThreats = async (ids: number[]) => {
    const nowIso = new Date().toISOString();
    const ts = nowIso.slice(0, 16).replace("T", " ");

    const selectedThreats = threats.filter((t) => ids.includes(t.id));
    const removedCount = selectedThreats.length;
    if (!removedCount) {
      setShowThreatsModal(false);
      return;
    }

    const paths = selectedThreats.map((t) => t.filePath).filter((p) => !!p);

    const newEntries: QuarantineEntry[] = selectedThreats.map((t, idx) => ({
      id: quarantine.length + idx + 1,
      fileName: t.fileName,
      originalPath: t.filePath,
      quarantinedAt: ts,
      detection: t.detection || "Threat",
      source: t.source,
    }));

    if (isTauri && paths.length > 0) {
      try {
        const quarantineResults = await invoke<QuarantineResult[]>("quarantine_files", { paths });
        const quarantineResultByPath = new Map(
            quarantineResults.map((item) => [item.original_path, item])
        );
        const storedEntries = newEntries.map((entry) => {
          const result = quarantineResultByPath.get(entry.originalPath);
          return {
            ...entry,
            quarantineId: result?.quarantine_id,
            quarantineFileName: result?.quarantine_file_name ?? entry.fileName,
            fileName: result?.display_name ?? entry.fileName,
            detection: result?.detection ?? entry.detection,
          };
        });

        setQuarantine((prev) => [...storedEntries, ...prev]);

        setLogs((prev) =>
            pushLogDedup(prev, {
              id: prev.length + 1,
              timestamp: ts,
              scan_type: "full_scan",
              result: "clean",
              details: `${removedCount} threat${
                  removedCount === 1 ? "" : "s"
              } moved to quarantine.`,
            })
        );
      } catch (err) {
        console.error("Quarantine error:", err);
        setLogs((prev) =>
            pushLogDedup(prev, {
              id: prev.length + 1,
              timestamp: ts,
              scan_type: "full_scan",
              result: "failed",
              details: "Failed to move threats to quarantine.",
            })
        );
      }
    } else {
      setLogs((prev) =>
          pushLogDedup(prev, {
            id: prev.length + 1,
            timestamp: ts,
            scan_type: "full_scan",
            result: "clean",
            details: `${removedCount} threat${
                removedCount === 1 ? "" : "s"
            } removed from list (demo only).`,
          })
      );

      setQuarantine((prev) => [...newEntries, ...prev]);
    }

    setThreats((prev) => {
      const remaining = prev.filter((t) => !ids.includes(t.id));
      if (remaining.length === 0) {
        setStatus(realtimeEnabled ? "protected" : "not_protected");
        setShowThreatsModal(false);
      }
      return remaining;
    });
  };

  const handleRestoreQuarantine = async (id: number) => {
    const entry = quarantine.find((q) => q.id === id);
    if (!entry) return;

    const ts = new Date().toISOString().slice(0, 16).replace("T", " ");

    if (isTauri) {
      try {
        await invoke("restore_from_quarantine", {
          items: [{ quarantineId: entry.quarantineId, fileName: entry.quarantineFileName ?? entry.fileName, originalPath: entry.originalPath }],
        });
      } catch (err) {
        console.error("Restore error:", err);
        setLogs((prev) =>
            pushLogDedup(prev, {
              id: prev.length + 1,
              timestamp: ts,
              scan_type: "realtime",
              result: "failed",
              details: `Failed to restore file from quarantine: ${entry.fileName}`,
            })
        );
        return;
      }
    }

    setQuarantine((prev) => prev.filter((q) => q.id !== id));

    setLogs((prev) =>
        pushLogDedup(prev, {
          id: prev.length + 1,
          timestamp: ts,
          scan_type: "realtime",
          result: "clean",
          details: `Restored file from quarantine: ${entry.fileName}`,
        })
    );
  };

  const handleDeleteQuarantine = async (id: number) => {
    const entry = quarantine.find((q) => q.id === id);
    if (!entry) return;

    setPendingDeleteId(id);
    setShowDeleteModal(true);
  };

  const handleToggleRealtime = (enabled: boolean) => {
    if (!enabled) {
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

    if (isTauri) {
      invoke("set_realtime_enabled", { enabled: false }).catch(() => {});
    }

    const ts = new Date().toISOString().slice(0, 16).replace("T", " ");
    setLogs((prev) =>
        pushLogDedup(prev, {
          id: prev.length + 1,
          timestamp: ts,
          scan_type: "realtime",
          result: "clean",
          details: "Real-time protection was turned off by the user.",
        })
    );
  };

  const cancelDisableRealtime = () => setShowRealtimeConfirm(false);

  // Poll dashboard home endpoint every 30 minutes when token is present
  useEffect(() => {
    if (!token) return;

    let cancelled = false;

    const loadDashboard = async () => {
      try {
        const res = await fetchDashboard(token);
        if (cancelled) return;

        setDashboard(res);

        if (typeof window !== "undefined") {
          window.localStorage.setItem(
              STORAGE_KEYS.dashboard,
              JSON.stringify(res)
          );
        }
      } catch (err) {
        console.error("Failed to fetch dashboard", err);
      }
    };

    loadDashboard();
    const intervalId = setInterval(loadDashboard, 30 * 60 * 1000);

    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, [token]);

  const handleLoginSuccess = (newToken?: string) => {
    if (typeof window !== "undefined" && newToken) {
      window.localStorage.setItem(STORAGE_KEYS.token, newToken);
    }

    if (newToken) setToken(newToken);

    const permissionsGranted =
        typeof window !== "undefined" &&
        window.localStorage.getItem(STORAGE_KEYS.permissionsGranted) === "1";

    setView(permissionsGranted ? "antivirus_dashboard" : "onboarding_step4");
  };

  const performLogout = () => {
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(STORAGE_KEYS.token);
      window.localStorage.removeItem(STORAGE_KEYS.dashboard);
      window.localStorage.removeItem("stellar_user");
      window.localStorage.removeItem("stellar_subscription_id");
      window.localStorage.removeItem(STORAGE_KEYS.permissionsGranted);
    }

    setShowLogoutConfirm(false);
    setToken(null);
    setDashboard(null);
    setView("onboarding_step1");
  };

  const handleLogout = () => {
    setShowLogoutConfirm(true);
  };

  const handleOnboardingNext = () => {
    if (view === "onboarding_step1") {
      setView("onboarding_step2");
    } else if (view === "onboarding_step2") {
      if (typeof window !== "undefined") {
        window.localStorage.setItem(STORAGE_KEYS.onboardingSeen, "1");
      }
      setView("onboarding_step3");
    }
  };

  // ✅ FIXED: this actually requests permissions (notifications + fs probe)
  const handleOnboardingAllow = async () => {
    // 1) Ask for notifications permission (if available)
    if (canUseNotifications && Notification.permission === "default") {
      try {
        await Notification.requestPermission();
      } catch {
        // ignore
      }
    }

    // 2) Probe filesystem access via Rust (Tauri only)
    if (isTauri) {
      try {
        const probes = await invoke<FsAccessProbe[]>("probe_fs_access");
        const failed = (probes || []).filter((p) => !p.ok);

        if (failed.length > 0) {
          console.warn("Folder access probe failed:", failed);

          alert(
              "Stellar Antivirus needs access to Desktop/Documents/Downloads.\n\n" +
              "macOS might be blocking it. Please allow access in the system prompt, or in System Settings.\n\n" +
              failed
                  .map(
                      (f) =>
                          `${f.label}: ${f.path}\n${f.error ?? "blocked"}`
                  )
                  .join("\n\n")
          );

          // Do NOT mark as granted if we know access is blocked
          return;
        }
      } catch (err) {
        console.error("probe_fs_access failed:", err);
        alert("Could not verify folder permissions. Please try again.");
        return;
      }
    }

    // 3) Mark granted and continue
    if (typeof window !== "undefined") {
      window.localStorage.setItem(STORAGE_KEYS.permissionsGranted, "1");
    }
    setView("antivirus_dashboard");
  };

  // Onboarding screens full-screen
  if (
      view === "onboarding_step1" ||
      view === "onboarding_step2" ||
      view === "onboarding_step3" ||
      view === "onboarding_step4"
  ) {
    const step =
        view === "onboarding_step1"
            ? 1
            : view === "onboarding_step2"
                ? 2
                : view === "onboarding_step3"
                    ? 3
                    : 4;

    return (
        <OnboardingScreen
            step={step}
            onNext={handleOnboardingNext}
            onAllow={handleOnboardingAllow}
            onAuthenticated={handleLoginSuccess}
        />
    );
  }

  const rootClass = isTauri
      ? "w-screen h-screen bg-[#F4F6FB] flex"
      : "min-h-screen bg-[#0B0C19] flex items-center justify-center";

  const shellClass = isTauri
      ? "flex-1 bg-[#F4F6FB] flex flex-col relative min-h-0"
      : "w-[1200px] h-[680px] flex flex-col relative overflow-hidden";

  return (
      <div className={rootClass}>
        <div className={shellClass}>
          <div className="flex flex-1 min-h-0">
            {isAntivirusView && (
                <Sidebar
                    current={currentSidebarView}
                    onChange={handleSidebarChange}
                    onLogout={handleLogout}
                />
            )}

            <div className="flex-1 flex flex-col min-h-0">
              {isAntivirusView && <HeaderBar realtimeEnabled={realtimeEnabled} />}

              <main className="flex-1 overflow-y-auto bg-[#F6F6FD] px-[20px] py-[20px]">
                {view === "antivirus_dashboard" && (
                    <DashboardScreen
                        status={status}
                        realtimeEnabled={realtimeEnabled}
                        onToggleRealtime={handleToggleRealtime}
                        onFullScan={startFullScan}
                        onQuickScan={startQuickScan}
                        onStopScan={stopFullScan}
                        lastScan={lastManualScan}
                        recentLogs={logs.slice(0, 4)}
                        scanProgress={scanProgress}
                        onOpenActivityLog={handleOpenActivityLog}
                    />
                )}

                {view === "antivirus_logs" && (
                    <LogsScreen
                        logs={logs}
                        quarantine={quarantine}
                        onViewThreats={handleOpenThreatsModal}
                        onRestoreQuarantine={handleRestoreQuarantine}
                        onDeleteQuarantine={handleDeleteQuarantine}
                        onClearLogs={handleClearLogs}
                    />
                )}

                {view === "antivirus_settings" && (
                    <SettingsScreen
                        onLogout={handleLogout}
                        dashboard={dashboard}
                        realtimeEnabled={realtimeEnabled}
                        status={status}
                        logs={logs}
                    />
                )}
              </main>
            </div>
          </div>

          {/* Modal: confirm realtime off */}
          {showRealtimeConfirm && (
              <div className="absolute inset-0 bg-[#0B0C1980] backdrop-blur-[10px] flex items-center justify-center z-50">
                <div className="w-[960px] h-[480px] bg-[#0B0C1980] rounded-3xl relative overflow-hidden flex flex-col justify-between">
                  <div className="absolute top-4 right-4 w-[19px] h-[19px] border-2 border-[#2761FC] flex items-center justify-center">
                    <button
                        onClick={cancelDisableRealtime}
                        className="w-[15px] h-[15px] rounded-full bg-white flex items-center justify-center hover:opacity-80 transition"
                    >
                      <span className="text-[#374151] text-sm">×</span>
                    </button>
                  </div>

                  <div className="flex flex-1">
                    <div className="w-1/2 h-full flex items-center justify-center p-8">
                      <div className="image">
                        <img src="/App.png" alt="Stellar Antivirus" />
                      </div>
                    </div>

                    <div className="w-1/2 pt-[20px] pb-[25px] px-6 flex flex-col">
                      <div className="flex items-center gap-2 mb-3">
                        <img
                            src="/reala-time-protection.svg"
                            alt=""
                            className="w-[15px] h-[19px]"
                        />
                        <span className="text-sm font-semibold text-white uppercase tracking-wide">
                      REAL-TIME PROTECTION
                    </span>
                      </div>

                      <h1 className="text-[30px] font-semibold font-poppins text-white mb-4">
                        Turn off real-time protection?
                      </h1>

                      <p className="text-[12px] font-normal text-[#CFCFFF] mb-3">
                        Real-time protection helps block malware the moment it
                        touches your system. If you turn it off, Stellar Antivirus
                        will only scan when you run a manual scan.
                      </p>
                      <p className="text-[12px] font-normal text-[#CFCFFF] mb-6">
                        We strongly recommend keeping it enabled unless you know
                        exactly what you&apos;re doing.
                      </p>

                      <div className="flex justify-end gap-3 mt-auto">
                        <Button
                            onClick={confirmDisableRealtime}
                            className="bg-white !text-[#62626A] hover:bg-white/90"
                        >
                          TURN OFF ANYWAY
                        </Button>
                        <Button
                            onClick={cancelDisableRealtime}
                            className="bg-[#2761FC] text-white hover:bg-[#1D4ED8]"
                        >
                          KEEP ACTIVE
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
          )}

          {showDeleteModal && (
              <div className="fixed inset-0 z-40 bg-[#0B0C1980] flex items-center justify-center backdrop-blur-[10px]">
                <div className="bg-[#0B0C1980] w-[960px] max-h-[600px] flex flex-col overflow-hidden shadow-2xl rounded-xl h-[500px] ">
                  <div className="flex items-center justify-between px-6 pt-3">
                    <div className="flex items-end gap-2">
                      <img src={Img} alt="" />
                      <span className="text-[14px] font-semibold text-white uppercase tracking-wider opacity-90">
                    ACTIVITY & QUARANTINE
                  </span>
                    </div>
                    <button
                        onClick={() => setShowDeleteModal(false)}
                        className="text-gray-400 hover:text-white transition-colors"
                    >
                      <img src={Img1} alt="" className="w-4 h-4 " />
                    </button>
                  </div>

                  <div className="px-6 py-6">
                    <h2 className="text-[30px] font-semibold text-white leading-tight font-poppins">
                      Delete file permanently?
                    </h2>
                    <p className="text-[12px] text-[#CFCFFF] mt-4">
                      This will permanently delete the selected file from quarantine.
                    </p>

                    {(() => {
                      const entry = quarantine.find((q) => q.id === pendingDeleteId);
                      if (!entry) return null;

                      const protectionLevel =
                          entry.source === "full_scan"
                              ? "Full scan"
                              : "Real-time protection";

                      return (
                          <div className="bg-white rounded-[20px] p-4 mb-6 mt-4">
                            <div className=" mb-1">
                        <span className="text-[#F96262] text-[14px] font-semibold">
                          [EXE] {entry.fileName}
                        </span>
                            </div>
                            <div className="flex justify-between">
                              <p className="text-[#F96262] text-xs break-all">
                                {entry.originalPath}
                              </p>
                              <div className="flex gap-2 items-center">
                                <p className="text-[#62626A] text-xs whitespace-nowrap">
                                  {entry.quarantinedAt}
                                </p>
                                <p className="text-[#62626A] text-xs">
                                  {protectionLevel}
                                </p>
                              </div>
                            </div>
                          </div>
                      );
                    })()}
                  </div>

                  <div className="flex items-center justify-end gap-3 px-6 py-4 rounded-b-lg mt-auto">
                    <button
                        onClick={() => setShowDeleteModal(false)}
                        className="px-5 py-2 text-sm font-medium text-white bg-[#4A4A54] hover:bg-[#525260] rounded-md transition-colors"
                    >
                      CANCEL
                    </button>
                    <button
                        onClick={async () => {
                          if (pendingDeleteId != null) {
                            const entry = quarantine.find((q) => q.id === pendingDeleteId);
                            if (entry && isTauri) {
                              try {
                                if (entry.quarantineId) {
                                  await invoke("delete_quarantine_items", {
                                    ids: [entry.quarantineId],
                                  });
                                } else {
                                  await invoke("delete_quarantine_files", {
                                    fileNames: [entry.quarantineFileName ?? entry.fileName],
                                  });
                                }
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
                        className="px-5 py-2 text-sm font-medium text-white bg-[#DC2626] hover:bg-[#B91C1C] rounded-md transition-colors"
                    >
                      DELETE
                    </button>
                  </div>
                </div>
              </div>
          )}

          {showLogoutConfirm && (
              <div className="fixed inset-0 z-50 bg-[#0B0C1980] backdrop-blur-[10px] flex items-center justify-center">
                <div className="relative w-[480px] bg-white rounded-[24px] shadow-2xl p-6">
                  <button
                      type="button"
                      aria-label="Close logout confirmation"
                      onClick={() => setShowLogoutConfirm(false)}
                      className="absolute right-5 top-5 w-9 h-9 rounded-full bg-[#F6F6FD] text-[#62626A] hover:bg-[#ECECF8] hover:text-[#303031] flex items-center justify-center text-[20px] leading-none transition-colors"
                  >
                    ×
                  </button>

                  <div className="flex items-center gap-3 mb-4 pr-10">
                    <div className="w-10 h-10 rounded-full bg-[#FEE2E2] flex items-center justify-center">
                      <span className="text-[#DC2626] text-xl font-semibold">!</span>
                    </div>
                    <div>
                      <h2 className="text-[20px] font-semibold text-[#303031] font-poppins">
                        Log out of Stellar Antivirus?
                      </h2>
                      <p className="text-[12px] text-[#62626A] mt-1">
                        You will need to log in again with your Stellar ID to use your account on this device.
                      </p>
                    </div>
                  </div>

                  <div className="flex justify-end gap-3 mt-6">
                    <Button
                        type="button"
                        onClick={() => setShowLogoutConfirm(false)}
                        className="bg-[#E0E7FF] !text-[#3730A3] hover:bg-[#C7D2FE]"
                    >
                      CANCEL
                    </Button>
                    <Button
                        type="button"
                        onClick={performLogout}
                        className="bg-white !text-[#111827] border border-[#D1D5DB] hover:bg-[#F9FAFB]"
                    >
                      LOG OUT
                    </Button>
                  </div>
                </div>
              </div>
          )}

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
