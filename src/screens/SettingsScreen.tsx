// src/screens/SettingsScreen.tsx
import React, { useEffect, useMemo, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { invoke } from "@tauri-apps/api/core";
import { check } from "@tauri-apps/plugin-updater";
import {
  isPermissionGranted as isNotificationPermissionGranted,
  requestPermission as requestNotificationPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import type { DashboardResponse } from "../api/dashboard";
import type { ProtectionStatus, ScanLogEntry } from "../types";
import Button from "../components/Button";

interface SettingsScreenProps {
  onLogout?: () => void;
  dashboard?: DashboardResponse | null;
  realtimeEnabled?: boolean;
  status?: ProtectionStatus;
  logs?: ScanLogEntry[];
}

type UpdateCheckState = "idle" | "checking" | "up_to_date" | "available" | "error";
type NotificationState = "unknown" | "allowed" | "denied" | "error";

type DiagnosticsSystemInfo = {
  os: string;
  arch: string;
  family: string;
  exe_path?: string | null;
  data_dir?: string | null;
  config_path: string;
  quarantine_dir: string;
  quarantine_manifest_path: string;
  quarantine_manifest_entries: number;
  realtime_enabled: boolean;
};

type FsAccessProbe = {
  label: string;
  path: string;
  ok: boolean;
  error?: string | null;
};

const OTA_LAST_CHECK_KEY = "stellar_antivirus_ota_last_check";
const OTA_STATE_KEY = "stellar_antivirus_ota_state";
const OTA_LATEST_VERSION_KEY = "stellar_antivirus_ota_latest_version";
const OTA_MESSAGE_KEY = "stellar_antivirus_ota_message";

const formatDateTime = (value: number | string | null): string => {
  if (!value) return "Never";

  const date = typeof value === "number" ? new Date(value) : new Date(value);
  if (Number.isNaN(date.getTime())) return "Never";

  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const normalizeVersion = (value: string | null | undefined): string | null => {
  if (!value) return null;
  return value.trim().replace(/^v/i, "").split("+")[0].split("-")[0];
};

const isUpdateCheckState = (value: string | null): value is UpdateCheckState =>
  value === "idle" ||
  value === "checking" ||
  value === "up_to_date" ||
  value === "available" ||
  value === "error";

const readStoredUpdateState = (): UpdateCheckState => {
  if (typeof window === "undefined") return "idle";
  const stored = window.localStorage.getItem(OTA_STATE_KEY);
  return isUpdateCheckState(stored) ? stored : "idle";
};

const readStoredString = (key: string): string | null => {
  if (typeof window === "undefined") return null;
  const value = window.localStorage.getItem(key);
  return value && value.trim().length > 0 ? value : null;
};

const SettingsScreen: React.FC<SettingsScreenProps> = ({
  onLogout,
  dashboard,
  realtimeEnabled = false,
  status = "not_protected",
  logs = [],
}) => {
  const stellarId = dashboard?.user?.email ?? "user@example.com";
  const expiresAtIso = dashboard?.subscription?.expires_at ?? null;

  const [currentVersion, setCurrentVersion] = useState<string>("Unknown");
  const [latestVersion, setLatestVersion] = useState<string | null>(() => readStoredString(OTA_LATEST_VERSION_KEY));
  const [updateState, setUpdateState] = useState<UpdateCheckState>(() => readStoredUpdateState());
  const [updateMessage, setUpdateMessage] = useState<string>(() => readStoredString(OTA_MESSAGE_KEY) ?? "Update check not run yet.");
  const [lastUpdateCheck, setLastUpdateCheck] = useState<number | null>(() => {
    if (typeof window === "undefined") return null;
    const raw = window.localStorage.getItem(OTA_LAST_CHECK_KEY);
    const parsed = raw ? Number(raw) : null;
    return parsed && Number.isFinite(parsed) ? parsed : null;
  });
  const [notificationState, setNotificationState] = useState<NotificationState>("unknown");
  const [notificationMessage, setNotificationMessage] = useState<string>("Notification permission not checked yet.");
  const [diagnosticsMessage, setDiagnosticsMessage] = useState<string>("Diagnostics export not run yet.");
  const [diagnosticsPath, setDiagnosticsPath] = useState<string | null>(null);
  const [openingDiagnostics, setOpeningDiagnostics] = useState(false);
  const [exportingDiagnostics, setExportingDiagnostics] = useState(false);

  const isTauri =
    typeof window !== "undefined" && !!(window as any).__TAURI_INTERNALS__;

  let expiryDisplay = "—";
  let daysLeftDisplay: string | number = "—";

  if (dashboard?.subscription?.remaining_days !== undefined) {
    daysLeftDisplay = dashboard.subscription.remaining_days;
  } else if (expiresAtIso) {
    const expiryDate = new Date(expiresAtIso);
    if (!Number.isNaN(expiryDate.getTime())) {
      const now = new Date();
      const diffMs = expiryDate.getTime() - now.getTime();
      const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
      daysLeftDisplay = diffDays > 0 ? diffDays : 0;
    }
  }

  if (expiresAtIso) {
    const expiryDate = new Date(expiresAtIso);
    if (!Number.isNaN(expiryDate.getTime())) {
      expiryDisplay = expiryDate.toISOString().slice(0, 10);
    }
  }

  const protectionLabel = useMemo(() => {
    if (status === "scanning") return "Scanning";
    if (!realtimeEnabled) return "Real-time disabled";
    if (status === "at_risk") return "Needs attention";
    if (status === "protected") return "Active";
    return "Not protected";
  }, [realtimeEnabled, status]);

  const updateStatusLabel = useMemo(() => {
    if (updateState === "checking") return "Checking";
    if (updateState === "available") return "Update available";
    if (updateState === "up_to_date") return "Up to date";
    if (updateState === "error") return "Check failed";
    return lastUpdateCheck ? "Last check completed" : "Not checked yet";
  }, [lastUpdateCheck, updateState]);

  useEffect(() => {
    if (!isTauri) {
      setCurrentVersion("Browser preview");
      setNotificationState("error");
      setNotificationMessage("Notifications are only available inside the desktop app.");
      return;
    }

    let cancelled = false;

    const loadRuntimeInfo = async () => {
      try {
        const version = await getVersion();
        if (!cancelled) setCurrentVersion(normalizeVersion(version) ?? version);
      } catch {
        if (!cancelled) setCurrentVersion("Unknown");
      }

      try {
        const allowed = await isNotificationPermissionGranted();
        if (!cancelled) {
          setNotificationState(allowed ? "allowed" : "denied");
          setNotificationMessage(
            allowed
              ? "Notifications are allowed."
              : "Notifications are not allowed yet. Click Request notifications to ask macOS again if possible."
          );
        }
      } catch {
        if (!cancelled) {
          setNotificationState("error");
          setNotificationMessage("Could not read notification permission status.");
        }
      }
    };

    loadRuntimeInfo();

    return () => {
      cancelled = true;
    };
  }, [isTauri]);

  const handleCheckForUpdates = async () => {
    if (!isTauri) {
      setUpdateState("error");
      setUpdateMessage("Updater is only available inside the desktop app.");
      return;
    }

    setUpdateState("checking");
    setUpdateMessage("Checking for updates...");
    window.localStorage.setItem(OTA_STATE_KEY, "checking");
    window.localStorage.setItem(OTA_MESSAGE_KEY, "Checking for updates...");

    try {
      const update = await check();
      const checkedAt = Date.now();
      window.localStorage.setItem(OTA_LAST_CHECK_KEY, String(checkedAt));
      setLastUpdateCheck(checkedAt);

      if (update) {
        const nextVersion = normalizeVersion(update.version);
        setLatestVersion(nextVersion);
        setUpdateState("available");
        const message = nextVersion
          ? `Update available: ${nextVersion} is ready to install from the dashboard.`
          : "A newer Stellar Antivirus release is available. The dashboard will show the install action.";
        setUpdateMessage(message);
        window.localStorage.setItem(OTA_STATE_KEY, "available");
        if (nextVersion) window.localStorage.setItem(OTA_LATEST_VERSION_KEY, nextVersion);
        window.localStorage.setItem(OTA_MESSAGE_KEY, message);
      } else {
        setLatestVersion(currentVersion !== "Unknown" ? currentVersion : null);
        setUpdateState("up_to_date");
        const message = currentVersion !== "Unknown"
          ? `Stellar Antivirus is up to date (${currentVersion}).`
          : "Stellar Antivirus is up to date.";
        setUpdateMessage(message);
        window.localStorage.setItem(OTA_STATE_KEY, "up_to_date");
        if (currentVersion !== "Unknown") window.localStorage.setItem(OTA_LATEST_VERSION_KEY, currentVersion);
        window.localStorage.setItem(OTA_MESSAGE_KEY, message);
      }
    } catch {
      const checkedAt = Date.now();
      window.localStorage.setItem(OTA_LAST_CHECK_KEY, String(checkedAt));
      setLastUpdateCheck(checkedAt);
      setUpdateState("error");
      const message = "Update check failed. Please check your connection and try again.";
      setUpdateMessage(message);
      window.localStorage.setItem(OTA_STATE_KEY, "error");
      window.localStorage.setItem(OTA_MESSAGE_KEY, message);
    }
  };

  const handleRequestNotifications = async () => {
    if (!isTauri) {
      setNotificationState("error");
      setNotificationMessage("Notifications are only available inside the desktop app.");
      return;
    }

    setNotificationMessage("Requesting notification permission...");

    try {
      const permission = await requestNotificationPermission();
      const allowed = permission === "granted" || (await isNotificationPermissionGranted());

      if (!allowed) {
        setNotificationState("denied");
        setNotificationMessage("Notifications are not allowed. Enable them for Stellar Antivirus in macOS System Settings.");
        return;
      }

      setNotificationState("allowed");
      sendNotification({
        title: "Stellar Antivirus",
        body: "Notifications are enabled. Stellar Antivirus can alert you while running in the background.",
      });
      setNotificationMessage("Notifications are allowed. Test notification sent.");
    } catch (err) {
      console.error("Failed to request notifications", err);
      setNotificationState("error");
      setNotificationMessage("Notification request failed. Check macOS notification settings and try again.");
    }
  };

  const handleExportDiagnostics = async () => {
    setExportingDiagnostics(true);
    setDiagnosticsPath(null);
    setDiagnosticsMessage("Preparing diagnostics export...");

    let systemInfo: DiagnosticsSystemInfo | null = null;
    let fsAccess: FsAccessProbe[] = [];

    if (isTauri) {
      try {
        systemInfo = await invoke<DiagnosticsSystemInfo>("get_diagnostics_system_info");
      } catch (err) {
        console.error("Failed to load system diagnostics", err);
      }

      try {
        fsAccess = await invoke<FsAccessProbe[]>("probe_fs_access");
      } catch (err) {
        console.error("Failed to probe filesystem access", err);
      }
    }

    const diagnostics = {
      exported_at: new Date().toISOString(),
      app: {
        name: "Stellar Antivirus",
        version: currentVersion,
        runtime: isTauri ? "tauri" : "browser_preview",
        user_agent: typeof navigator !== "undefined" ? navigator.userAgent : null,
        platform: typeof navigator !== "undefined" ? navigator.platform : null,
      },
      system: systemInfo,
      filesystem_access: fsAccess,
      protection: {
        status,
        realtime_enabled: realtimeEnabled,
        label: protectionLabel,
      },
      updates: {
        state: updateState,
        current_version: currentVersion,
        latest_version: latestVersion,
        last_checked_at: lastUpdateCheck ? new Date(lastUpdateCheck).toISOString() : null,
        message: updateMessage,
      },
      notifications: {
        state: notificationState,
        message: notificationMessage,
      },
      account: {
        stellar_id: stellarId,
        subscription_expires_on: expiryDisplay,
        subscription_days_remaining: daysLeftDisplay,
      },
      recent_logs: logs.slice(0, 25),
    };

    const content = JSON.stringify(diagnostics, null, 2);

    try {
      if (isTauri) {
        const path = await invoke<string>("export_diagnostics_file", { content });
        setDiagnosticsPath(path);
        setDiagnosticsMessage(`Diagnostics exported to: ${path}`);
        return;
      }

      const blob = new Blob([content], { type: "application/json;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `stellar-antivirus-diagnostics-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      setDiagnosticsMessage("Diagnostics export downloaded.");
    } catch (err) {
      console.error("Failed to export diagnostics", err);
      setDiagnosticsMessage("Diagnostics export failed. Please try again.");
    } finally {
      setExportingDiagnostics(false);
    }
  };

  const handleOpenDiagnostics = async () => {
    if (!diagnosticsPath) {
      setDiagnosticsMessage("Export diagnostics first, then open the exported file.");
      return;
    }

    if (!isTauri) {
      setDiagnosticsMessage("Opening diagnostics is only available inside the desktop app.");
      return;
    }

    setOpeningDiagnostics(true);

    try {
      await invoke("reveal_path_in_file_manager", { path: diagnosticsPath });
      setDiagnosticsMessage(`Opened diagnostics in Finder: ${diagnosticsPath}`);
    } catch (err) {
      console.error("Failed to open diagnostics", err);
      setDiagnosticsMessage("Could not open diagnostics automatically. Use the exported path shown above.");
    } finally {
      setOpeningDiagnostics(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="bg-white rounded-[24px] px-6 py-5 flex flex-col gap-4">
        <div>
          <div className="flex items-center gap-2 mb-[12px]">
            <img src="/settings/settings.svg" alt="" className="w-5 h-5" />
            <h2 className="text-[14px] font-semibold text-[#2761FC] uppercase">
              Settings
            </h2>
          </div>
          <p className="text-xs text-[#6B7280] mb-4 pb-4 border-b-2 border-[#F6F6FD]">
            Manage your Stellar ID, subscription and device diagnostics.
          </p>
          <div className="flex items-center gap-2 justify-between rounded-full border-2 border-[#F6F6FD] px-4 py-2">
            <div className="text-xs font-semibold text-[#62626A]">
              STELLAR ID
            </div>
            <div className="text-[12px] font-regular text-[#2761FC]">
              {stellarId}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4 text-xs">
          <div className="bg-[#F3F4FF] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Subscription
            </div>
            <div className="text-xs text-[#62626A]">Stellar Antivirus</div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Days remaining
            </div>
            <div className="text-xs text-[#62626A]">
              {daysLeftDisplay !== "—" ? `${daysLeftDisplay} days` : "—"}
            </div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Expires on
            </div>
            <div className="text-xs text-[#62626A]">{expiryDisplay}</div>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-[24px] px-6 py-5 flex flex-col gap-4">
        <div>
          <div className="flex items-center gap-2 mb-3">
            <img src="/settings/settings.svg" alt="" className="w-5 h-5" />
            <h3 className="text-sm font-semibold text-[#2761FC] uppercase">
              App status
            </h3>
          </div>
          <p className="text-[12px] font-normal text-[#62626A]">
            Check the installed app version, update state, notifications and protection status.
          </p>
        </div>

        <div className="grid grid-cols-3 gap-4 text-xs">
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              App version
            </div>
            <div className="text-xs text-[#2761FC]">{currentVersion}</div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Latest version
            </div>
            <div className="text-xs text-[#2761FC]">{latestVersion ?? (updateState === "idle" ? "Check required" : "—")}</div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Last update check
            </div>
            <div className="text-xs text-[#62626A]">{formatDateTime(lastUpdateCheck)}</div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Update status
            </div>
            <div className="text-xs text-[#62626A]">{updateStatusLabel}: {updateMessage}</div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Notifications
            </div>
            <div className="text-xs text-[#62626A]">
              {notificationState === "allowed"
                ? "Allowed"
                : notificationState === "denied"
                  ? "Not allowed"
                  : notificationState === "error"
                    ? "Unavailable"
                    : "Checking..."}
            </div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Real-time protection
            </div>
            <div className="text-xs text-[#62626A]">{protectionLabel}</div>
          </div>
        </div>

        <div className="rounded-[18px] bg-[#F6F6FD] px-4 py-3 text-[12px] text-[#62626A]">
          <div>{notificationMessage}</div>
          <div className="mt-1">{diagnosticsMessage}</div>
        </div>

        <div className="flex flex-wrap gap-3 pt-1">
          <Button
            type="button"
            disabled={updateState === "checking"}
            onClick={handleCheckForUpdates}
            className="text-[12px] h-[28px] py-0"
          >
            {updateState === "checking" ? "Checking..." : "Check for updates"}
          </Button>
          <Button
            type="button"
            onClick={handleRequestNotifications}
            className="text-[12px] h-[28px] py-0"
          >
            Request notifications
          </Button>
          <Button
            type="button"
            disabled={exportingDiagnostics}
            onClick={handleExportDiagnostics}
            className="text-[12px] h-[28px] py-0"
          >
            {exportingDiagnostics ? "Exporting..." : "Export diagnostics"}
          </Button>
          <Button
            type="button"
            disabled={!diagnosticsPath || openingDiagnostics}
            onClick={handleOpenDiagnostics}
            className="text-[12px] h-[28px] py-0"
          >
            {openingDiagnostics ? "Opening..." : "Open diagnostics"}
          </Button>
        </div>
      </div>

      <div className="bg-white rounded-[24px] px-6 py-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <img src="/settings/helpsupport.svg" alt="" className="w-5 h-5" />
              <h3 className="text-sm font-semibold text-[#2761FC] uppercase">
                Help & support
              </h3>
            </div>
            <p className="text-[12px] font-normal text-[#62626A]">
              Contact Stellar Security if you need assistance.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4 text-xs">
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Signal
            </div>
            <div className="text-xs  font-normal text-[#2761FC]">
              @StellarSecurity.30
            </div>
            <div className="text-[12px] text-[#62626A] mt-1">
              Preferred for secure chat.
            </div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Email
            </div>
            <div className="text-xs  font-normal text-[#2761FC]">
              info@stellarsecurity.com
            </div>
            <div className="text-[12px] text-[#62626A] mt-1">
              For billing and general questions.
            </div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#303031] mb-1 uppercase">
              Website
            </div>
            <div className="text-xs  font-normal text-[#2761FC]">
              StellarSecurity.com
            </div>
            <div className="text-[12px] text-[#62626A] mt-1">
              Docs, FAQ and product updates.
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-[24px] px-6 py-5 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 mb-[12px]">
            <img src="/settings/logout.svg" alt="" className="w-5 h-5" />
            <div className="text-[14px] font-semibold text-[#2761FC] uppercase w-[68px] !h-[20px] ">
              Log out
            </div>
          </div>
          <p className="text-[12px] text-[#6B7280]">
            Sign out of Stellar Antivirus on this device. You can log in again
            with your Stellar ID at any time.
          </p>
        </div>
        <Button
          onClick={onLogout}
          className="bg-[#F96262] hover:bg-[#F96262]/90 text-[12px] h-[20px] py-0"
        >
          Log out
        </Button>
      </div>
    </div>
  );
};

export default SettingsScreen;
