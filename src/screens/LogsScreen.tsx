import React, { useState } from "react";
import type { ScanLogEntry } from "../types";
import Button from "../components/Button";

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
    <div className=" flex flex-col pt-6 bg-white px-4 rounded-[20px]">
      {/* Header */}
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
          {/* Clear logs – kun relevant for Activity tab */}
          <button
            onClick={onClearLogs}
            disabled={!hasLogs}

            className={`text-[12px] rounded-full uppercase font-semibold text-[#62626A] bg-[#F6F6FD] ${!hasLogs ? "opacity-50" : ""
              }`}
          >
            Clear logs
          </button>
          <button

            onClick={onViewThreats}
            className="text-[12px] uppercase rounded-full font-semibold text-[#62626A] bg-[#F6F6FD]"
          >
            View  threats
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="inline-flex border-2 border-[#F6F6FD] mb-4 rounded-full ">
        <button
          className={`px-4 h-8 rounded-full text-[11px] font-medium uppercase ${activeTab === "activity"
            ? "bg-[#2761FC] text-white"
            : "text-[#6B7280]"
            }`}
          onClick={() => setActiveTab("activity")}
        >
          Activity Log
        </button>
        <button
          className={`px-4 h-8 rounded-full text-[11px] font-medium uppercase ${activeTab === "quarantine"
            ? "bg-[#2761FC] text-white"
            : "text-[#6B7280]"
            }`}
          onClick={() => setActiveTab("quarantine")}
        >
          Quarantine
        </button>
      </div>

      {/* Content */}
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

  // User-provided gradients
  const GRADIENTS = {
    white: "linear-gradient(282deg, rgba(246, 246, 253, 1) 28%, rgba(255, 255, 255, 1) 100%)",
    red: "linear-gradient(282deg, rgba(255, 233, 233, 1) 28%, rgba(255, 255, 255, 1) 100%)",
    green: "linear-gradient(282deg, rgba(166, 255, 199, 1) 28%, rgba(255, 255, 255, 1) 100%)",
  };

  return (
    <div className="h-full overflow-y-auto pr-2 pb-2">
      <ul className="space-y-3">
        {logs.map((log) => {
          // Logic:
          // Threat Found -> Red
          // Threat Removed (quarantined/removed) -> Green
          // Clean/Neutral -> White

          const isThreatFound = log.result === "threats_found";
          const isThreatRemoved =
            log.details.toLowerCase().includes("moved to quarantine") ||
            log.details.toLowerCase().includes("removed");
          const isRealtime = log.scan_type === "realtime";

          let background = GRADIENTS.white;
          let borderColor = "border-[#E5E7EB]";
          let textColor = "text-[#6B7280]";

          if (isThreatFound) {
            background = GRADIENTS.red;
            borderColor = "border-[#FFCCCC]";
            textColor = "text-[#F87171]"; // Red text for threats found
          } else if (isThreatRemoved) {
            background = GRADIENTS.green;
            borderColor = "border-[#6EE7B7]";
            textColor = "text-[#34D399]"; // Green text for removed
          } else {
            // Clean / Neutral -> White gradient
            background = GRADIENTS.white;
            borderColor = "border-[#E5E7EB]";
            textColor = "text-[#6B7280]";
          }

          return (
            <li
              key={log.id}
              className={`flex items-center justify-between rounded-full border px-5 py-3 ${borderColor} ${textColor}`}
              style={{ background }}
            >
              <div className="text-[12px] font-medium">
                {log.details}
              </div>

              <div className="flex items-center gap-2 text-[12px] opacity-90">
                <span className="font-[400] text-[#62626A]">{log.timestamp.replace(" ", " — ")}</span>
                <span className="opacity-60">•</span>
                <span className="font-[400] text-[#62626A]">{isRealtime ? "Real-time protection" : "Full scan"}</span>
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
          {entries.map((q) => (
            <tr
              key={q.id}
              className="text-xs text-[#F96262]  rounded-2xl"
            >
              <td className="px-1 py-2 align-top">
                <div className="flex items-start gap-1">
                  <div className=" text-[10px] font-semibold text-[#F96262]">
                    EXE
                  </div>
                  <span className="font-medium line-clamp-1">
                    {q.fileName || "Unknown file"}
                  </span>
                </div>
              </td>
              <td className="px-1 py-2 align-top">
                <span className="text-[11px] text-[#F96262] break-all">
                  {q.originalPath}
                </span>
              </td>
              <td className="px-1 py-2 align-top">
                <span className="text-[11px] text-[#62626A]">
                  {q.detection || "Threat"}
                </span>
              </td>
              <td className="px-1 py-2 align-top">
                <span className="text-[11px] text-[#62626A]">
                  {q.quarantinedAt}
                </span>
              </td>
              <td className="px-1 py-0 ">
                <div className="">
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
