import React from "react";
import type { ProtectionStatus } from "../types";


interface Props {
  status: ProtectionStatus;
}

const statusConfig: Record<
  ProtectionStatus,
  { label: string; bg: string; dot: string; text: string }
> = {
  protected: {
    label: "You are protected",
    bg: "bg-[#E5F9EB]",
    dot: "bg-[#22C55E]",
    text: "text-[#166534]",
  },
  not_protected: {
    label: "Protection disabled",
    bg: "bg-[#FEE2E2]",
    dot: "bg-[#EF4444]",
    text: "text-[#991B1B]",
  },
  scanning: {
    label: "Scanning in progress",
    bg: "bg-[#DBEAFE]",
    dot: "bg-[#3B82F6]",
    text: "text-[#1D4ED8]",
  },
};

const HeaderBar: React.FC<Props> = ({ status }) => {
  const cfg = statusConfig[status];

  return (
    <header className="h-20 px-8 flex items-center justify-between border-b border-[#E0E4F2] bg-[#F9FAFF]">
      <div>
        <h1 className="text-xl font-semibold text-[#111827]">
          Stellar Antivirus
        </h1>
        <p className="text-xs text-[#6B7280]">
          Protects your Mac and Windows devices in real time.
        </p>
      </div>

      <div
        className={`flex items-center gap-2 px-4 py-2 rounded-full text-xs font-medium ${cfg.bg} ${cfg.text}`}
      >
        <span className={`w-2 h-2 rounded-full ${cfg.dot}`} />
        <span>{cfg.label}</span>
      </div>
    </header>
  );
};

export default HeaderBar;
