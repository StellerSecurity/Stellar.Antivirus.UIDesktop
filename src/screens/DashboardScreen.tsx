import React from "react";
import type { ProtectionStatus, ScanLogEntry } from "../types";

interface Props {
  status: ProtectionStatus;
  realtimeEnabled: boolean;
  onToggleRealtime: (enabled: boolean) => void;
  onFullScan: () => void;
  lastScan: ScanLogEntry | null;
  recentLogs: ScanLogEntry[];
}

const DashboardScreen: React.FC<Props> = ({
                                            status,
                                            realtimeEnabled,
                                            onToggleRealtime,
                                            onFullScan,
                                            lastScan,
                                            recentLogs,
                                          }) => {
  const isScanning = status === "scanning";

  return (
      <div className="h-full flex flex-col gap-6 pt-6">
        <div className="grid grid-cols-2 gap-6">
          {/* Real-time card */}
          <div className="bg-white rounded-[24px] shadow-[0_16px_40px_rgba(15,23,42,0.06)] px-6 py-6 flex flex-col justify-between">
            <div>
              <div className="text-xs font-semibold text-[#3B82F6] mb-2">
                REAL-TIME PROTECTION
              </div>
              <h2 className="text-lg font-semibold text-[#111827] mb-1">
                Live file monitoring
              </h2>
              <p className="text-xs text-[#6B7280]">
                Scans new and modified files in real time to block threats before
                they spread.
              </p>
            </div>

            <div className="mt-6 flex items-center justify-between">
              <div className="flex flex-col">
                <span className="text-xs text-[#9CA3AF]">Status</span>
                <span className="text-sm font-medium text-[#111827]">
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
          <div className="bg-gradient-to-br from-[#2563EB] to-[#1D4ED8] rounded-[24px] shadow-[0_20px_40px_rgba(37,99,235,0.5)] px-6 py-6 text-white flex flex-col justify-between">
            <div>
              <div className="text-xs font-semibold opacity-80 mb-2">
                FULL DISK SCAN
              </div>
              <h2 className="text-lg font-semibold mb-1">
                Scan your entire device
              </h2>
              <p className="text-xs text-white/80">
                Checks all files and locations for viruses, malware, and spyware.
              </p>
            </div>

            <div className="mt-6 flex items-center justify-between gap-4">
              <button
                  onClick={onFullScan}
                  disabled={isScanning}
                  className="flex-1 h-11 rounded-full bg-white text-[#1D4ED8] text-sm font-semibold shadow-[0_10px_30px_rgba(15,23,42,0.25)] disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {isScanning ? "Scanning..." : "Run Full Scan"}
              </button>
              <div className="flex flex-col min-w-[160px]">
              <span className="text-[11px] uppercase tracking-wide text-white/60">
                Last full scan
              </span>
                {lastScan ? (
                    <>
                  <span className="text-xs font-medium">
                    {lastScan.timestamp}
                  </span>
                      <span className="text-[11px] text-white/80">
                    {lastScan.result === "clean"
                        ? "No threats found"
                        : "Threats found"}
                  </span>
                    </>
                ) : (
                    <span className="text-xs text-white/80">
                  No full scan has been run yet
                </span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Scanning animation */}
        {isScanning && (
            <div className="bg-white rounded-[24px] shadow-[0_16px_40px_rgba(15,23,42,0.06)] px-6 py-5 flex items-center gap-6">
              <div className="flex items-center justify-center w-[180px]">
                <div className="stellar-scan-orb">
                  <div className="stellar-scan-orb-ring" />
                  <div className="stellar-scan-orb-icon">🛡️</div>
                </div>
              </div>
              <div className="flex-1">
                <div className="text-xs font-semibold text-[#3B82F6] mb-1">
                  SCANNING IN PROGRESS
                </div>
                <h3 className="text-sm font-semibold text-[#111827] mb-1">
                  Stellar Antivirus is scanning your device
                </h3>
                <p className="text-xs text-[#6B7280] mb-3">
                  You can keep using your Mac or PC while the scan runs. We&apos;ll
                  notify you here if any threats are found.
                </p>
                <div className="flex items-center gap-3">
                  <div className="w-32 h-1.5 rounded-full bg-[#E5E7EB] overflow-hidden">
                    <div className="w-1/2 h-full bg-[#2563EB] animate-pulse" />
                  </div>
                  <span className="text-[11px] text-[#6B7280]">
                Scanning system files, apps and downloads…
              </span>
                </div>
              </div>
            </div>
        )}

        {/* Bottom card – recent activity preview */}
        <div className="bg-white rounded-[24px] shadow-[0_16px_40px_rgba(15,23,42,0.06)] px-6 py-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-[#111827]">
                Recent activity
              </h3>
              <p className="text-xs text-[#6B7280]">
                A quick view of your latest scans.
              </p>
            </div>
            <span className="text-xs text-[#2563EB] cursor-default">
            Activity Log
          </span>
          </div>

          {recentLogs.length === 0 ? (
              <p className="text-xs text-[#9CA3AF]">
                No activity yet. Run a full scan to create your first log entry.
              </p>
          ) : (
              <div className="space-y-2">
                {recentLogs.map((log) => {
                  const isError = log.result === "threats_found";
                  const isRealtime = log.scan_type === "realtime";

                  return (
                      <div
                          key={log.id}
                          className="flex items-center justify-between text-xs py-2 rounded-2xl px-3 hover:bg-[#F3F4FF]"
                      >
                        <div className="flex items-center gap-2">
                    <span
                        className={`w-2 h-2 rounded-full ${
                            isError ? "bg-[#DC2626]" : "bg-[#16A34A]"
                        }`}
                    />
                          <span className="font-medium text-[#111827]">
                      {isRealtime ? "Real-time protection" : "Full scan"}
                    </span>
                          <span className="text-[11px] text-[#6B7280] line-clamp-1 max-w-[260px]">
                      {log.details}
                    </span>
                        </div>
                        <div className="text-[11px] text-[#9CA3AF]">
                          {log.timestamp}
                        </div>
                      </div>
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
          className={`relative w-12 h-7 rounded-full transition flex items-center px-1
      ${
              enabled
                  ? "bg-[#2563EB] shadow-[0_8px_20px_rgba(37,99,235,0.55)]"
                  : "bg-[#E5E7EB]"
          } ${disabled ? "opacity-60 cursor-not-allowed" : "cursor-pointer"}`}
      >
      <span
          className={`w-5 h-5 rounded-full bg-white shadow transform transition-transform
        ${enabled ? "translate-x-5" : "translate-x-0"}`}
      />
      </button>
  );
};

export default DashboardScreen;
