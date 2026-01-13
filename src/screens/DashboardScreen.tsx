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
  onStopScan,
  lastScan,
  recentLogs,
  onOpenActivityLog,
  scanProgress,
}) => {
  const isScanning = status === "scanning";

  const percent =
    scanProgress.total > 0
      ? Math.round((scanProgress.current / scanProgress.total) * 100)
      : 0;

  const progressDisplay = Math.min(100, Math.max(0, percent || 0));

  const currentFileDisplay =
    scanProgress && scanProgress.file
      ? (() => {
          const full = scanProgress.file;
          const parts = full.split(/[\\/]/); // virker på både Windows og Linux
          const file = parts.pop() ?? "";
          const parent = parts.pop() ?? "";
          const short = parent ? `${parent}/${file}` : file;
          return { full, short };
        })()
      : null;

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
            <div className="flex items-center gap-2 mb-2">
              <img src="/dashboard/dashboard.svg" alt="" className="w-4 h-4" />
              <span className="text-[14px] font-semibold text-white">
                FULL DISK SCAN
              </span>
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
                isScanning ? "bg-[#4578FF]" : "bg-[#60D38E]"
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
                      <line x1="10.343" y1="10.343" x2="11.657" y2="11.657" />
                      <line x1="4.343" y1="11.657" x2="5.657" y2="10.343" />
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
                  <>
                    <span className="text-[14px] font-semibold text-white">
                      {lastScan.timestamp}
                    </span>
                    <span className="text-[14px] font-semibold text-white">
                      {lastScan.result === "clean"
                        ? "No threats found"
                        : "Threats found"}
                    </span>
                  </>
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
        {/* STOP SCAN button - positioned top right */}
        <Button
          onClick={onStopScan}
          className="absolute top-5 right-7 !text-[12px] font-semibold py-0 px-[9px] !text-[#62626A] bg-white !h-[20px] z-10"
        >
          STOP SCAN
        </Button>
        {/* Circular progress indicator */}
        <div className="flex items-center justify-center w-[170px] h-[145px] border-2 border-[#4578FF] rounded-[24px]">
          <Spinner
            progress={isScanning ? progressDisplay : 0}
            size={120}
            strokeWidth={16}
            bgStrokeColor="rgba(255, 255, 255, 0.2)"
            progressStrokeColor="#60D38E"
            showPercentage={true}
            className="text-white"
          />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 text-[14px] font-semibold text-white mb-[12px] uppercase">
            <img src="/dashboard/scan.svg" alt="" className="w-4 h-4" />
            SCANNING IN PROGRESS
          </div>
          <h3 className="text-[20px] font-semibold text-white mb-[12px]">
            Stellar Antivirus is scanning your device
          </h3>
          <p className="text-[12px] font-normal text-[#CFCFFF] mb-[12px]">
            You can keep using your Mac or PC while the scan runs. We&apos;ll
            notify you here if any threats are found.
          </p>
          {/* Horizontal progress bar */}
          <div className="mb-2">
            <div className="bg-[#4578FF] rounded-full px-[22px] py-[7px] flex items-center gap-7 h-[30px]">
              <div className="flex-1 h-1 rounded-full bg-white overflow-hidden">
                {isScanning && (
                  <div
                    className="h-full bg-black transition-all duration-200"
                    style={{ width: `${progressDisplay || 0}%` }}
                  />
                )}
              </div>
              {scanProgress.total > 0 && (
                <span className="text-xs text-white whitespace-nowrap">
                  Scanning files -{" "}
                  <span className="font-semibold">{progressDisplay}%</span>
                </span>
              )}
            </div>
          </div>
          <p className="text-xs text-[#CFCFFF] mb-2">
            ... Desk/OneDrive_1_21.11.2025.zip
          </p>
          <div className="flex items-center justify-between">
            <div className="flex-1">
              {currentFileDisplay && (
                <p
                  className="text-xs text-white mb-1 max-w-[480px] truncate"
                  title={currentFileDisplay.full}
                >
                  {currentFileDisplay.short}
                </p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Bottom card – recent activity preview */}
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
              const isError = log.result === "threats_found";
              const isRealtime = log.scan_type === "realtime";

              // Use colors from log entry if provided, otherwise determine styling based on log type
              const bgColor =
                log.bgColor || (isError ? "bg-[#FEE2E2]" : "bg-[#D1FAE5]");
              const borderColor =
                log.borderColor ||
                (isError ? "border-[#FCA5A5]" : "border-[#86EFAC]");
              const textColor =
                log.textColor ||
                (isError ? "text-[#DC2626]" : "text-[#16A34A]");

              return (
                <button
                  key={log.id}
                  type="button"
                  onClick={onOpenActivityLog}
                  className={`w-full flex items-center justify-between border-2  rounded-2xl border ${bgColor} ${borderColor} cursor-pointer hover:opacity-90 transition`}
                >
                  <span
                    className={`text-[12px] py-[8px] font-normal ${textColor}`}
                  >
                    {log.details ||
                      (isRealtime ? "Real-time protection" : "Full scan")}
                  </span>
                  <div className="flex items-center gap-1 text-[12px]">
                    <span className="text-[12px] py-[8px] font-normal text-[#62626A]">
                      {log.timestamp || "2025-12-01 — 17:04"}
                    </span>
                    <span className="w-1 h-1 rounded-full bg-[#62626A]"></span>
                    <span className="text-[12px] py-[8px] font-normal text-[#62626A]">
                      Real-time protection
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
        ${enabled ? "translate-x-[32px]" : "translate-x-0"} ${
          enabled ? "z-20" : ""
        }`}
      />
    </button>
  );
};

export default DashboardScreen;
