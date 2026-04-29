import React, { useState } from "react";
import type { ScanLogEntry } from "../types";

type QuarantineEntry = {
  id: number;
  quarantineId?: string;
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

const getScanTypeLabel = (log: ScanLogEntry): string => {
  if (log.scan_type === "realtime") return "Real-time protection";
  if (log.scan_type === "quick_scan") return "Quick scan";
  if (log.scan_type === "full_scan") return "Full scan";
  return "Activity";
};

const formatTimestamp = (timestamp?: string): string => {
  if (!timestamp) return "Unknown time";
  return timestamp.replace(" ", " - ");
};

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
    <div className="flex flex-col pt-6 bg-white px-4 rounded-[20px]">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-[14px] font-semibold uppercase text-[#2761FC] mb-[12px]">
            Activity & Quarantine
          </h1>
          <p className="text-[12px] font-normal text-[#62626A] pb-[12px] mb-[12px] border-b-2 border-[#62626A]">
            Review recent scans and files moved to quarantine.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onClearLogs}
            disabled={!hasLogs}
            className={`text-[12px] rounded-full uppercase font-semibold text-[#62626A] bg-[#F6F6FD] px-4 py-2 ${
              !hasLogs ? "opacity-50" : ""
            }`}
          >
            Clear logs
          </button>
          <button
            onClick={onViewThreats}
            className="text-[12px] uppercase rounded-full font-semibold text-[#62626A] bg-[#F6F6FD] px-4 py-2"
          >
            View threats
          </button>
        </div>
      </div>

      <div className="inline-flex border-2 border-[#F6F6FD] mb-4 rounded-full">
        <button
          className={`px-4 h-8 rounded-full text-[11px] font-medium uppercase ${
            activeTab === "activity" ? "bg-[#2761FC] text-white" : "text-[#6B7280]"
          }`}
          onClick={() => setActiveTab("activity")}
        >
          Activity Log
        </button>
        <button
          className={`px-4 h-8 rounded-full text-[11px] font-medium uppercase ${
            activeTab === "quarantine" ? "bg-[#2761FC] text-white" : "text-[#6B7280]"
          }`}
          onClick={() => setActiveTab("quarantine")}
        >
          Quarantine
        </button>
      </div>

      <div className="flex-1 bg-white rounded-[24px] p-1 overflow-hidden">
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

  const gradients = {
    white:
      "linear-gradient(282deg, rgba(246, 246, 253, 1) 28%, rgba(255, 255, 255, 1) 100%)",
    red:
      "linear-gradient(282deg, rgba(255, 233, 233, 1) 28%, rgba(255, 255, 255, 1) 100%)",
    green:
      "linear-gradient(282deg, rgba(166, 255, 199, 1) 28%, rgba(255, 255, 255, 1) 100%)",
  };

  return (
    <div className="h-full overflow-y-auto pr-2 pb-2">
      <ul className="space-y-3">
        {logs.map((log, index) => {
          const details = log.details || "Activity recorded.";
          const isThreatFound = log.result === "threats_found";
          const lowerDetails = details.toLowerCase();
          const isThreatRemoved =
            lowerDetails.includes("moved to quarantine") ||
            lowerDetails.includes("quarantined") ||
            lowerDetails.includes("removed");

          let background = gradients.white;
          let borderColor = "border-[#E5E7EB]";
          let textColor = "text-[#6B7280]";

          if (isThreatFound) {
            background = gradients.red;
            borderColor = "border-[#FFCCCC]";
            textColor = "text-[#F87171]";
          } else if (isThreatRemoved) {
            background = gradients.green;
            borderColor = "border-[#6EE7B7]";
            textColor = "text-[#34D399]";
          }

          return (
            <li
              key={log.id ?? index}
              className={`flex items-center justify-between gap-4 rounded-full border px-5 py-3 ${borderColor} ${textColor}`}
              style={{ background }}
            >
              <div className="text-[12px] font-medium min-w-0 truncate">
                {details}
              </div>

              <div className="flex shrink-0 items-center gap-2 text-[12px] opacity-90">
                <span className="font-[400] text-[#62626A]">
                  {formatTimestamp(log.timestamp)}
                </span>
                <span className="opacity-60">•</span>
                <span className="font-[400] text-[#62626A]">
                  {getScanTypeLabel(log)}
                </span>
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
          <p className="text-xs text-[#9CA3AF] mb-1">No files in quarantine.</p>
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
          <tr className="text-[11px] text-[#62626A] uppercase">
            <th className="font-medium px-2">File</th>
            <th className="font-medium px-2">Original location</th>
            <th className="font-medium px-2">Detection</th>
            <th className="font-medium px-2 w-[120px]">Quarantined</th>
            <th className="font-medium px-2 w-[120px]">Actions</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((q, index) => (
            <tr key={q.id ?? index} className="text-xs text-[#F96262] rounded-2xl">
              <td className="px-1 py-2 align-top">
                <div className="flex items-start gap-1">
                  <div className="text-[10px] font-semibold text-[#F96262]">
                    FILE
                  </div>
                  <span className="font-medium line-clamp-1">
                    {q.fileName || "Unknown file"}
                  </span>
                </div>
              </td>
              <td className="px-1 py-2 align-top">
                <span className="text-[11px] text-[#F96262] break-all">
                  {q.originalPath || "Unknown location"}
                </span>
              </td>
              <td className="px-1 py-2 align-top">
                <span className="text-[11px] text-[#62626A]">
                  {q.detection || "Threat"}
                </span>
              </td>
              <td className="px-1 py-2 align-top">
                <span className="text-[11px] text-[#62626A]">
                  {q.quarantinedAt || "Unknown time"}
                </span>
              </td>
              <td className="px-1 py-0">
                <div>
                  <button
                    onClick={() => onRestore(q.id)}
                    className="text-[12px] text-[#62626A80] hover:underline text-left"
                  >
                    Restore
                  </button>
                  <button
                    onClick={() => onDelete(q.id)}
                    className="text-[12px] text-[#F96262] hover:underline text-left"
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

export default LogsScreen;
