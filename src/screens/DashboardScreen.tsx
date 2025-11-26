import React from "react";
import type { ActivityLogEntry } from "../types";

interface DashboardScreenProps {
    isScanning: boolean;
    scanProgress: number;
    currentFile: string | null;
    logs: ActivityLogEntry[];
    onStartFullScan: () => void;
    onViewThreats: () => void;
}

const DashboardScreen: React.FC<DashboardScreenProps> = ({
                                                             isScanning,
                                                             scanProgress,
                                                             currentFile,
                                                             logs,
                                                             onStartFullScan,
                                                             onViewThreats,
                                                         }) => {
    const recentLogs = logs.slice(0, 4);

    return (
        <div className="pt-6 flex flex-col gap-6">
            {/* Header */}
            <div>
                <h2 className="text-lg font-semibold text-[#111827] mb-1">
                    Stellar Antivirus
                </h2>
                <p className="text-xs text-[#6B7280]">
                    Real-time protection with full system scan when you need it.
                </p>
            </div>

            {/* Top row: Protection status + actions */}
            <div className="grid grid-cols-[minmax(0,2fr)_minmax(0,1.4fr)] gap-4">
                {/* Protection status card */}
                <div className="bg-white rounded-[24px] shadow-[0_16px_40px_rgba(15,23,42,0.06)] px-6 py-5 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <div className="text-xs font-semibold text-[#3B82F6] mb-1">
                                PROTECTION STATUS
                            </div>
                            <div className="flex items-center gap-2">
                                <span className="inline-flex h-2 w-2 rounded-full bg-[#16A34A]" />
                                <span className="text-sm font-semibold text-[#111827]">
                  {isScanning ? "Scanning your system..." : "You are protected"}
                </span>
                            </div>
                        </div>
                        <button
                            onClick={onViewThreats}
                            className="text-xs font-medium text-[#2563EB] hover:underline"
                        >
                            View detected threats
                        </button>
                    </div>

                    {/* Progress bar */}
                    <div>
                        <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] text-[#6B7280]">
                Full system scan
              </span>
                            <span className="text-[11px] text-[#111827]">
                {isScanning ? `${scanProgress}%` : "Idle"}
              </span>
                        </div>
                        <div className="h-1.5 w-full rounded-full bg-[#E5E7EB] overflow-hidden">
                            <div
                                className="h-full rounded-full bg-[#3B82F6] transition-all"
                                style={{ width: `${isScanning ? scanProgress : 0}%` }}
                            />
                        </div>
                        {currentFile && (
                            <div className="mt-2 text-[11px] text-[#9CA3AF] line-clamp-1">
                                Scanning: {currentFile}
                            </div>
                        )}
                    </div>
                </div>

                {/* Actions card */}
                <div className="bg-white rounded-[24px] shadow-[0_16px_40px_rgba(15,23,42,0.06)] px-6 py-5 flex flex-col justify-between">
                    <div>
                        <h3 className="text-sm font-semibold text-[#111827] mb-1">
                            Quick actions
                        </h3>
                        <p className="text-xs text-[#6B7280]">
                            Run a full system scan when you install new software or feel
                            unsure.
                        </p>
                    </div>

                    <div className="flex items-center gap-3 mt-4">
                        <button
                            onClick={onStartFullScan}
                            disabled={isScanning}
                            className="inline-flex items-center justify-center rounded-full px-4 py-2 text-xs font-semibold text-white bg-[#2563EB] disabled:bg-[#93C5FD] disabled:cursor-not-allowed"
                        >
                            {isScanning ? "Scanning..." : "Run full scan"}
                        </button>
                        <span className="text-[11px] text-[#9CA3AF]">
              Real-time protection runs automatically in the background.
            </span>
                    </div>
                </div>
            </div>

            {/* Bottom card – Recent activity */}
            <div className="bg-white rounded-[24px] shadow-[0_16px_40px_rgba(15,23,42,0.06)] px-6 py-5">
                <div className="flex items-center justify-between mb-4">
                    <div>
                        <h3 className="text-sm font-semibold text-[#111827]">
                            Recent activity
                        </h3>
                        <p className="text-xs text-[#6B7280]">
                            A quick view of your latest scans and real-time events.
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

export default DashboardScreen;
