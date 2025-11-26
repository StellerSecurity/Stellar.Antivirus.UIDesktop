import React, { useState } from "react";
import type { ScanLogEntry } from "../types";

type QuarantineEntry = {
    id: number;
    fileName: string;
    originalPath: string;
    quarantinedAt: string;
    detection: string;
};

interface LogsScreenProps {
    logs: ScanLogEntry[];
    quarantine: QuarantineEntry[];
    onViewThreats: () => void;
    onRestoreQuarantine: (id: number) => void;
    onDeleteQuarantine: (id: number) => void;
    onClearLogs: () => void;
}

const LogsScreen: React.FC<LogsScreenProps> = ({
                                                   logs,
                                                   quarantine,
                                                   onViewThreats,
                                                   onRestoreQuarantine,
                                                   onDeleteQuarantine,
                                                   onClearLogs,
                                               }) => {
    const [activeTab, setActiveTab] = useState<"activity" | "quarantine">(
        "activity"
    );

    const hasLogs = logs.length > 0;

    return (
        <div className="h-full flex flex-col pt-6">
            {/* Header */}
            <div className="flex items-center justify-between mb-4">
                <div>
                    <h1 className="text-lg font-semibold text-[#020617]">
                        Activity & Quarantine
                    </h1>
                    <p className="text-xs text-[#6B7280]">
                        Review recent scans and files moved to quarantine.
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    {/* Clear logs – kun relevant for Activity tab */}
                    <button
                        onClick={onClearLogs}
                        disabled={!hasLogs}
                        className={`px-3 h-9 rounded-full text-xs font-medium border text-[#111827] ${
                            hasLogs
                                ? "border-[#E5E7EB] bg-white hover:bg-[#F3F4F6]"
                                : "border-[#E5E7EB] bg-[#F9FAFB] text-[#9CA3AF] cursor-not-allowed"
                        }`}
                    >
                        Clear logs
                    </button>
                    <button
                        onClick={onViewThreats}
                        className="px-3 h-9 rounded-full text-xs font-semibold bg-[#1D4ED8] text-white shadow-[0_10px_30px_rgba(37,99,235,0.5)] hover:bg-[#1E40AF]"
                    >
                        View detected threats
                    </button>
                </div>
            </div>

            {/* Tabs */}
            <div className="inline-flex mb-4 bg-[#E5E7EB] rounded-full p-1">
                <button
                    className={tabButtonCls(activeTab === "activity")}
                    onClick={() => setActiveTab("activity")}
                >
                    Activity Log
                </button>
                <button
                    className={tabButtonCls(activeTab === "quarantine")}
                    onClick={() => setActiveTab("quarantine")}
                >
                    Quarantine
                </button>
            </div>

            {/* Content */}
            <div className="flex-1 bg-white rounded-[24px] shadow-[0_16px_40px_rgba(15,23,42,0.06)] p-5 overflow-hidden">
                {activeTab === "activity" ? (
                    <ActivityList logs={logs} />
                ) : (
                    <QuarantineList
                        entries={quarantine}
                        onRestore={onRestoreQuarantine}
                        onDelete={onDeleteQuarantine}
                    />
                )}
            </div>
        </div>
    );
};

const ActivityList: React.FC<{ logs: ScanLogEntry[] }> = ({ logs }) => {
    if (!logs.length) {
        return (
            <div className="h-full flex items-center justify-center">
                <p className="text-xs text-[#9CA3AF]">
                    No activity yet. Run a scan to see log entries.
                </p>
            </div>
        );
    }

    return (
        <div className="h-full overflow-y-auto pr-2">
            <ul className="space-y-3">
                {logs.map((log) => {
                    const isError = log.result === "threats_found";
                    const isRealtime = log.scan_type === "realtime";

                    return (
                        <li
                            key={log.id}
                            className="flex items-start justify-between rounded-2xl border border-[#E5E7EB] px-4 py-3"
                        >
                            <div className="flex items-start gap-3">
                                <span
                                    className={`mt-1 w-2 h-2 rounded-full ${
                                        isError ? "bg-[#DC2626]" : "bg-[#16A34A]"
                                    }`}
                                />
                                <div>
                                    <div className="flex items-center gap-2 mb-1">
                                        <span className="text-[11px] font-semibold uppercase tracking-wide text-[#6B7280]">
                                            {isRealtime ? "REAL-TIME" : "FULL SCAN"}
                                        </span>
                                        <span className="text-[11px] text-[#9CA3AF]">
                                            {log.timestamp}
                                        </span>
                                    </div>
                                    <p className="text-xs text-[#111827]">
                                        {log.details}
                                    </p>
                                </div>
                            </div>
                            <div className="text-[11px] text-[#9CA3AF]">
                                {isError ? "Threats found" : "Clean"}
                            </div>
                        </li>
                    );
                })}
            </ul>
        </div>
    );
};

interface QuarantineListProps {
    entries: QuarantineEntry[];
    onRestore: (id: number) => void;
    onDelete: (id: number) => void;
}

const QuarantineList: React.FC<QuarantineListProps> = ({
                                                           entries,
                                                           onRestore,
                                                           onDelete,
                                                       }) => {
    if (!entries.length) {
        return (
            <div className="h-full flex items-center justify-center">
                <div className="text-center">
                    <p className="text-xs text-[#9CA3AF] mb-1">
                        No files in quarantine.
                    </p>
                    <p className="text-[11px] text-[#9CA3AF]">
                        When Stellar Antivirus removes threats, they will appear here.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="h-full overflow-y-auto pr-2">
            <table className="w-full text-left border-separate border-spacing-y-2">
                <thead>
                <tr className="text-[11px] text-[#6B7280]">
                    <th className="font-medium px-3">File</th>
                    <th className="font-medium px-3">Original location</th>
                    <th className="font-medium px-3">Detection</th>
                    <th className="font-medium px-3 w-[120px]">Quarantined</th>
                    <th className="font-medium px-3 w-[120px]">Actions</th>
                </tr>
                </thead>
                <tbody>
                {entries.map((q) => (
                    <tr
                        key={q.id}
                        className="text-xs text-[#111827] bg-[#F9FAFB] rounded-2xl"
                    >
                        <td className="px-3 py-2 align-top">
                            <div className="flex items-center gap-2">
                                <div className="w-6 h-6 rounded-full bg-[#EEF2FF] flex items-center justify-center text-[10px] font-semibold text-[#4F46E5]">
                                    EXE
                                </div>
                                <span className="font-medium line-clamp-1">
                                        {q.fileName || "Unknown file"}
                                    </span>
                            </div>
                        </td>
                        <td className="px-3 py-2 align-top">
                                <span className="text-[11px] text-[#6B7280] break-all">
                                    {q.originalPath}
                                </span>
                        </td>
                        <td className="px-3 py-2 align-top">
                                <span className="text-[11px] text-[#DC2626]">
                                    {q.detection || "Threat"}
                                </span>
                        </td>
                        <td className="px-3 py-2 align-top">
                                <span className="text-[11px] text-[#6B7280]">
                                    {q.quarantinedAt}
                                </span>
                        </td>
                        <td className="px-3 py-2 align-top">
                            <div className="flex flex-col gap-1">
                                <button
                                    onClick={() => onRestore(q.id)}
                                    className="text-[11px] text-[#2563EB] hover:underline text-left"
                                >
                                    Restore
                                </button>
                                <button
                                    onClick={() => onDelete(q.id)}
                                    className="text-[11px] text-[#B91C1C] hover:underline text-left"
                                >
                                    Delete permanently
                                </button>
                            </div>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );
};

const tabButtonCls = (active: boolean) =>
    `px-4 h-8 rounded-full text-[11px] font-medium ${
        active
            ? "bg-white text-[#111827] shadow-[0_6px_18px_rgba(15,23,42,0.15)]"
            : "text-[#6B7280]"
    }`;

export default LogsScreen;
