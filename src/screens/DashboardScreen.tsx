import React from "react";
import type { ProtectionStatus, ScanLogEntry } from "../types";
import Button from "../components/Button";
import Spinner from "../components/Spinner";

interface ScanProgress {
  current: number;
  total: number;
  file: string;
}

interface Props {
  status: ProtectionStatus;
  realtimeEnabled: boolean;
  onToggleRealtime: (enabled: boolean) => void;
  onFullScan: () => void;
  onQuickScan: () => void;
  onStopScan: () => void;
  lastScan: ScanLogEntry | null;
  recentLogs: ScanLogEntry[];
  onOpenActivityLog: () => void;
  scanProgress: ScanProgress;
}

const DashboardScreen: React.FC<Props> = ({
                                            status,
                                            realtimeEnabled,
                                            onToggleRealtime,
                                            onFullScan,
                                            onQuickScan,
                                            onStopScan,
                                            lastScan,
                                            recentLogs,
                                            onOpenActivityLog,
                                            scanProgress,
                                          }) => {
  const isScanning = status === "scanning";
  const hasProgress = scanProgress.total > 0;

  const percent = hasProgress
      ? Math.round((scanProgress.current / scanProgress.total) * 100)
      : 0;

  const progressDisplay = Math.min(100, Math.max(0, percent || 0));

  // When App.tsx holds 100% for ~1.2s after scan_finished, this becomes true.
  const isCompletionHold = !isScanning && hasProgress && progressDisplay >= 100;
  const isFinalizing = isScanning && progressDisplay >= 100;

  const spinnerActive = isScanning || isFinalizing || isCompletionHold;

  const currentFileDisplay =
      scanProgress && scanProgress.file
          ? (() => {
            const full = scanProgress.file;
            const parts = full.split(/[\\/]/); // Works on Windows/macOS/Linux
            const file = parts.pop() ?? "";
            const parent = parts.pop() ?? "";
            const short = parent ? `${parent}/${file}` : file;
            return { full, short };
          })()
          : null;

  const scanLabel = isFinalizing
      ? "FINALIZING RESULTS"
      : isCompletionHold
          ? "SCAN COMPLETE"
          : isScanning
              ? "SCANNING IN PROGRESS"
              : "READY";

  const scanTitle = isFinalizing
      ? "Stellar Antivirus is finishing up"
      : isCompletionHold
          ? status === "at_risk"
              ? "Scan finished, threats found"
              : "Scan finished, no threats found"
          : isScanning
              ? "Stellar Antivirus is scanning your device"
              : "Ready to scan your device";

  const scanBody = isFinalizing
      ? "Almost done. Verifying scan results and signatures."
      : isCompletionHold
          ? "Scan completed successfully. Check your activity for details."
          : isScanning
              ? "You can keep using your Mac or PC while the scan runs. We'll notify you here if any threats are found."
              : "Run a Quick scan for common locations, or Full scan for a deeper check.";

  // --- Linux update command (VPN-style) ---
  const isLinux =
      typeof navigator !== "undefined" &&
      /Linux/i.test(navigator.userAgent) &&
      !/Android/i.test(navigator.userAgent);

  const linuxUpdateCommand = `curl -fsSL https://desktopreleasesassetsprod.stellarsecurity.com/antivirus/latest.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['platforms']['linux-x86_64']['url'])" | xargs -I{} sh -lc 'set -e; TMP=$(mktemp -d); curl -fL \"{}\" -o \"$TMP/stellar-antivirus.deb\"; sudo apt-get update -y >/dev/null; sudo apt-get install -y \"$TMP/stellar-antivirus.deb\"'`;

  const onCopyLinuxCommand = async () => {
    try {
      await navigator.clipboard.writeText(linuxUpdateCommand);
    } catch {
      const el = document.createElement("textarea");
      el.value = linuxUpdateCommand;
      el.style.position = "fixed";
      el.style.left = "-9999px";
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
    }
  };

  return (
      <div className="h-full flex flex-col gap-6">
        <div className="grid grid-cols-2 gap-6">
          {/* Real-time card */}
          <div className="bg-white rounded-[24px] px-6 py-6 flex flex-col justify-between">
            <div>
              <div className="text-[14px] font-semibold text-[#2761FC] mb-2">
                REAL-TIME PROTECTION
              </div>
              <h2 className="text-[30px] font-semibold font-poppins text-[#0B0C19] mb-1">
                Live file monitoring
              </h2>
              <p className="text-[12px] font-normal text-[#62626A]">
                Scans new and modified files in real time to block threats before
                they spread.
              </p>
            </div>

            <div className="mt-6 flex items-center justify-between">
              <div className="flex flex-col">
              <span className="text-[10px] font-normal text-[#62626A]">
                Status
              </span>
                <span
                    className={`text-[14px] font-semibold ${
                        realtimeEnabled ? "text-[#2761FC]" : "text-[#111827]"
                    }`}
                >
                {realtimeEnabled ? "Enabled" : "Disabled"}
              </span>
              </div>

              <Toggle
                  enabled={realtimeEnabled}
                  onChange={onToggleRealtime}
                  disabled={isScanning}
              />
            </div>
          </div>

          {/* Full scan card */}
          <div className="bg-gradient-to-br from-[#2563EB] to-[#1D4ED8] rounded-[24px] px-[22px] py-[21px] text-white flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <img
                      src="/dashboard/dashboard.svg"
                      alt=""
                      className="w-4 h-4"
                  />
                  <span className="text-[14px] font-semibold text-white">
                  FULL DISK SCAN
                </span>
                </div>

                <button
                    type="button"
                    onClick={onQuickScan}
                    disabled={isScanning}
                    className={`bg-[#60D38E] text-[#fff] text-[12px] font-bold px-3 py-1 rounded-full transition uppercase h-[24px]
                  ${isScanning ? "opacity-60 cursor-not-allowed" : "hover:opacity-90"}`}
                >
                  Quick Scan
                </button>
              </div>

              <h2 className="text-[30px] font-semibold font-poppins mb-[12px]">
                Scan your entire device
              </h2>
              <p className="text-[12px] font-normal text-[#CFCFFF] mb-[12px]">
                Checks all files and locations for viruses, malware and spyware.
                Run a full scan to initiate.
              </p>
            </div>

            <div className="flex flex-row-reverse items-center justify-between gap-4">
              <Button
                  onClick={onFullScan}
                  disabled={isScanning}
                  className={`flex-1 py-2 max-w-[160px] ${
                      isScanning ? "!bg-[#4578FF]" : "!bg-[#60D38E]"
                  }`}
              >
              <span className="flex items-center gap-2 uppercase justify-around">
                {isScanning ? "Scanning..." : "Run Full Scan"}
                {isScanning ? (
                    <svg
                        className="animate-spin"
                        width="16"
                        height="16"
                        viewBox="0 0 16 16"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                    >
                      <g
                          stroke="currentColor"
                          strokeWidth="1.5"
                          strokeLinecap="round"
                      >
                        <line x1="8" y1="2" x2="8" y2="4" />
                        <line x1="8" y1="12" x2="8" y2="14" />
                        <line x1="2" y1="8" x2="4" y2="8" />
                        <line x1="12" y1="8" x2="14" y2="8" />
                        <line x1="4.343" y1="4.343" x2="5.657" y2="5.657" />
                        <line
                            x1="10.343"
                            y1="10.343"
                            x2="11.657"
                            y2="11.657"
                        />
                        <line
                            x1="4.343"
                            y1="11.657"
                            x2="5.657"
                            y2="10.343"
                        />
                        <line x1="10.343" y1="5.657" x2="11.657" y2="4.343" />
                      </g>
                    </svg>
                ) : (
                    <svg
                        width="3"
                        height="6"
                        viewBox="0 0 3 6"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                    >
                      <path
                          d="M1 0L3 3L1 6"
                          stroke="currentColor"
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                      />
                    </svg>
                )}
              </span>
              </Button>

              <div className="flex flex-col min-w-[160px]">
              <span className="text-[10px] font-normal text-[#CFCFFF] capitalize mb-1">
                Status:
              </span>
                <div className="flex items-center gap-1">
                <span className="text-[14px] font-semibold text-white">
                  Latest scan -
                </span>
                  {lastScan ? (
                      <span className="text-[14px] font-semibold text-white">
                    {lastScan.timestamp}
                  </span>
                  ) : (
                      <span className="text-[14px] font-semibold text-white">
                    No scans yet
                  </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Scanning animation + progress */}
        <div className="relative bg-gradient-to-br from-[#2563EB] to-[#1D4ED8] rounded-[24px] px-7 py-5 flex items-center gap-6 text-white">
          {/* STOP SCAN only while scanning */}
          {isScanning && (
              <button
                  onClick={onStopScan}
                  className="absolute rounded-full top-5 right-7 !text-[12px] font-semibold py-[0.5px] px-[9px] !text-[#62626A] bg-white !h-[20px] z-10"
              >
                STOP SCAN
              </button>
          )}

          {/* Circular progress indicator + glow */}
          <div className="relative flex items-center justify-center w-[170px] h-[145px] border-2 border-[#4578FF] rounded-[24px] overflow-hidden">
            {/* Tinder-ish glow pulse while scanning */}
            {isScanning && (
                <>
                  <div
                      className="absolute inset-[-20px] blur-2xl opacity-70 animate-pulse"
                      style={{
                        background:
                            "radial-gradient(circle, rgba(96,211,142,0.55) 0%, rgba(37,99,235,0.00) 70%)",
                      }}
                  />
                  <div
                      className="absolute inset-4 rounded-[22px] blur-md opacity-60 animate-spin"
                      style={{
                        background:
                            "conic-gradient(from 0deg, rgba(96,211,142,0.00), rgba(96,211,142,0.65), rgba(96,211,142,0.00))",
                      }}
                  />
                </>
            )}

            <div className="relative z-10">
              <Spinner
                  progress={spinnerActive ? progressDisplay : 0}
                  size={120}
                  strokeWidth={16}
                  bgStrokeColor="rgba(255, 255, 255, 0.2)"
                  progressStrokeColor="#60D38E"
                  showPercentage={true}
                  className="text-white"
              />
            </div>
          </div>

          <div className="flex-1">
            <div className="flex items-center gap-2 text-[14px] font-semibold text-white mb-[12px] uppercase">
              <img src="/dashboard/scan.svg" alt="" className="w-4 h-4" />
              {scanLabel}
            </div>

            <h3 className="text-[20px] font-semibold text-white mb-[12px]">
              {scanTitle}
            </h3>

            <p className="text-[12px] font-normal text-[#CFCFFF] mb-[12px]">
              {scanBody}
            </p>

            {/* Horizontal progress bar */}
            <div className="mb-2">
              <div className="bg-[#4578FF] rounded-full px-[22px] py-[7px] flex items-center gap-7 h-[30px]">
                <div className="flex-1 h-1 rounded-full bg-white overflow-hidden">
                  {(isScanning || isCompletionHold || isFinalizing) &&
                      hasProgress && (
                          <div
                              className="h-full bg-black transition-all duration-200"
                              style={{ width: `${progressDisplay || 0}%` }}
                          />
                      )}
                </div>

                {(isScanning || isCompletionHold || isFinalizing) && hasProgress && (
                    <span className="text-xs text-white whitespace-nowrap">
                  {isCompletionHold ? (
                      <>
                        Completed - <span className="font-semibold">100%</span>
                      </>
                  ) : (
                      <>
                        Scanning files -{" "}
                        <span className="font-semibold">{progressDisplay}%</span>
                      </>
                  )}
                </span>
                )}
              </div>
            </div>

            {/* Current file only while scanning */}
            {isScanning && currentFileDisplay && (
                <p
                    className="text-xs text-white mb-1 max-w-[480px] truncate"
                    title={currentFileDisplay.full}
                >
                  {currentFileDisplay.short}
                </p>
            )}
          </div>
        </div>

        {/* Linux update command card (VPN-style) */}
        {isLinux && (
            <div className="bg-white rounded-[24px] p-[22px] h-auto">
              <div className="flex items-center justify-between mb-[12px]">
                <div>
                  <div className="flex items-center gap-2 mb-[12px]">
                    <img
                        src="/dashboard/recent-activity.svg"
                        alt=""
                        className="w-4 h-4"
                    />
                    <h3 className="text-sm font-semibold text-[#2761FC] uppercase">
                      Update on Linux
                    </h3>
                  </div>
                  <p className="text-xs text-[#6B7280]">
                    Run this command in your terminal to download and install the
                    latest .deb (VPN-style).
                  </p>
                </div>

                <button
                    type="button"
                    onClick={onCopyLinuxCommand}
                    className="text-[12px] font-semibold text-[#62626A] bg-[#F6F6FD] uppercase hover:opacity-80 px-[8px] py-[6px] rounded-[20px] h-auto"
                >
                  Copy
                </button>
              </div>

              <div className="bg-[#0B0C19] text-white rounded-[18px] px-4 py-3 overflow-x-auto">
            <pre className="text-[11px] leading-5 whitespace-pre-wrap break-words">
              {linuxUpdateCommand}
            </pre>
              </div>

              <p className="text-[11px] text-[#6B7280] mt-2">
                Requires: curl + python3 + sudo access (apt). Installer is fetched
                from{" "}
                <span className="font-semibold">
              desktopreleasesassetsprod.stellarsecurity.com
            </span>
                .
              </p>
            </div>
        )}

        {/* Recent activity */}
        <div className="bg-white rounded-[24px] p-[22px] h-auto">
          <div className="flex items-center justify-between mb-[12px]">
            <div>
              <div className="flex items-center gap-2 mb-[12px]">
                <img
                    src="/dashboard/recent-activity.svg"
                    alt=""
                    className="w-4 h-4"
                />
                <h3 className="text-sm font-semibold text-[#2761FC] uppercase">
                  Recent activity
                </h3>
              </div>
              <p className="text-xs text-[#6B7280]">
                A quick view of your latest scans.
              </p>
            </div>

            <button
                type="button"
                onClick={onOpenActivityLog}
                className="text-[12px] font-semibold text-[#62626A] bg-[#F6F6FD] uppercase hover:opacity-80 px-[8px] py-[4px] rounded-[20px] h-auto"
            >
              Activity Log
            </button>
          </div>

          {recentLogs.length === 0 ? (
              <div className="flex items-center justify-between text-[12px] font-normal text-[#62626A] bg-[#F6F6FD] border border-[#F6F6FD] rounded-2xl py-[8px] px-[12px]">
                <span>Run a scan to create your first activity entry.</span>
                <div className="flex items-center gap-1">
                  <span className="text-[#62626A]">No scans yet</span>
                  <span className="w-1 h-1 rounded-full bg-[#62626A]"></span>
                  <span>Real-time protection</span>
                </div>
              </div>
          ) : (
              <div className="space-y-2">
                {recentLogs.map((log) => {
                  const isThreatFound = log.result === "threats_found";
                  const isRealtime = log.scan_type === "realtime";
                  const isThreatRemoved =
                      (log.details || "")
                          .toLowerCase()
                          .includes("moved to quarantine") ||
                      (log.details || "").toLowerCase().includes("removed");

                  const GRADIENTS = {
                    white:
                        "linear-gradient(282deg, rgba(246, 246, 253, 1) 28%, rgba(255, 255, 255, 1) 100%)",
                    red:
                        "linear-gradient(282deg, rgba(255, 233, 233, 1) 28%, rgba(255, 255, 255, 1) 100%)",
                    green:
                        "linear-gradient(282deg, rgba(166, 255, 199, 1) 28%, rgba(255, 255, 255, 1) 100%)",
                  };

                  let background = GRADIENTS.white;
                  let borderColor = "border-[#E5E7EB]";
                  let textColor = "text-[#6B7280]";

                  if (isThreatFound) {
                    background = GRADIENTS.red;
                    borderColor = "border-[#FFCCCC]";
                    textColor = "text-[#F87171]";
                  } else if (isThreatRemoved) {
                    background = GRADIENTS.green;
                    borderColor = "border-[#6EE7B7]";
                    textColor = "text-[#34D399]";
                  }

                  return (
                      <button
                          key={log.id}
                          type="button"
                          onClick={onOpenActivityLog}
                          className={`w-full flex items-center justify-between rounded-full border px-5 py-3 ${borderColor} ${textColor} cursor-pointer hover:opacity-90 transition`}
                          style={{ background }}
                      >
                  <span className="text-[12px] font-medium">
                    {log.details ||
                        (isRealtime ? "Real-time protection" : "Full scan")}
                  </span>

                        <div className="flex items-center gap-2 text-[12px] opacity-90 font-semibold text-[#62626A]">
                    <span className="font-[400]">
                      {log.timestamp.replace(" ", " — ")}
                    </span>
                          <span className="opacity-60">•</span>
                          <span className="font-[400]">
                      {isRealtime ? "Real-time protection" : "Full scan"}
                    </span>
                        </div>
                      </button>
                  );
                })}
              </div>
          )}
        </div>
      </div>
  );
};

interface ToggleProps {
  enabled: boolean;
  disabled?: boolean;
  onChange: (enabled: boolean) => void;
}

const Toggle: React.FC<ToggleProps> = ({ enabled, disabled, onChange }) => {
  return (
      <button
          type="button"
          disabled={disabled}
          onClick={() => !disabled && onChange(!enabled)}
          className={`relative w-[64px] h-[32px] rounded-full transition flex items-center px-1
      ${enabled ? "bg-[#2563EB]" : "bg-[#E5E7EB]"} ${
              disabled ? "opacity-60 cursor-not-allowed" : "cursor-pointer"
          }`}
      >
        {enabled && (
            <span className="absolute left-3 text-[12px] font-semibold text-white pointer-events-none z-10">
          On
        </span>
        )}
        <span
            className={`w-6 h-6 rounded-full bg-white transform transition-transform
        ${enabled ? "translate-x-[32px]" : "translate-x-0"} ${enabled ? "z-20" : ""}`}
        />
      </button>
  );
};

export default DashboardScreen;
