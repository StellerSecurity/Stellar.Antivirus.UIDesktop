import React from "react";
import type { ScanLogEntry } from "../types";

interface Props {
    logs: ScanLogEntry[];
    onViewThreats?: () => void;
}

const LogsScreen: React.FC<Props> = ({ logs, onViewThreats }) => {
    return (
        <div className="pt-6 flex flex-col gap-4">
            <h2 className="text-lg font-semibold text-[#111827] mb-1">
                Activity Log
            </h2>
            <p className="text-xs text-[#6B7280] mb-2">
                Recent scans and real-time protection events on this device.
            </p>

            {logs.length === 0 && (
                <div className="mt-4 text-xs text-[#9CA3AF]">
                    No activity yet. Run a full scan to create your first log entry.
                </div>
            )}

            <div className="space-y-3">
                {logs.map((log) => (
                    <LogCard
                        key={log.id}
                        entry={log}
                        onViewThreats={
                            log.result === "threats_found" ? onViewThreats : undefined
                        }
                    />
                ))}
            </div>
        </div>
    );
};

const LogCard: React.FC<{
    entry: ScanLogEntry;
    onViewThreats?: () => void;
}> = ({ entry, onViewThreats }) => {
    const isError = entry.result === "threats_found";
    const isRealtime = entry.scan_type === "realtime";

    const iconBg = isError ? "bg-[#FEE2E2]" : "bg-[#DCFCE7]";
    const iconDot = isError ? "bg-[#EF4444]" : "bg-[#22C55E]";

    return (
        <div className="bg-white rounded-[20px] shadow-[0_12px_30px_rgba(15,23,42,0.04)] px-5 py-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
                <div className={`w-9 h-9 rounded-full ${iconBg} flex items-center justify-center`}>
                    <span className={`w-2 h-2 rounded-full ${iconDot}`} />
                </div>
                <div>
                    <div className="text-sm font-medium text-[#111827] flex items-center gap-2">
            <span>
              {isRealtime ? "Real-time protection" : "Full scan"}
            </span>
                        {isError && onViewThreats && (
                            <button
                                onClick={onViewThreats}
                                className="text-[11px] text-[#2563EB] underline-offset-2 hover:underline"
                            >
                                View details
                            </button>
                        )}
                    </div>
                    <div className="text-xs text-[#6B7280] line-clamp-1">
                        {entry.details}
                    </div>
                </div>
            </div>
            <div className="text-right">
                <div className="text-xs text-[#9CA3AF]">{entry.timestamp}</div>
                <div
                    className={`text-[11px] font-medium ${
                        isError ? "text-[#B91C1C]" : "text-[#16A34A]"
                    }`}
                >
                    {isError ? "Threats found" : "No threats"}
                </div>
            </div>
        </div>
    );
};

export default LogsScreen;
