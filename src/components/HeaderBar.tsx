import React from "react";

type StatusChipConfig = {
    id: string;
    label: string;
    bg: string;
    text: string;
    dotColor: string;
};

type HeaderBarProps = {
    realtimeEnabled: boolean;
};

const HeaderBar: React.FC<HeaderBarProps> = ({ realtimeEnabled }) => {
    const realtimeChip: StatusChipConfig = realtimeEnabled
        ? {
            id: "realtime_on",
            label: "Real-time protection enabled",
            bg: "bg-[#ECFDF3]",
            text: "text-[#166534]",
            dotColor: "bg-[#22C55E]",
        }
        : {
            id: "realtime_off",
            label: "Real-time protection disabled",
            bg: "bg-[#FEF2F2]",
            text: "text-[#B91C1C]",
            dotColor: "bg-[#EF4444]",
        };



    const chips = [realtimeChip];

    return (
        <header className="h-[72px] px-6 border-b border-[#E5E7EB] bg-white flex items-center justify-between">
            <div className="flex items-center gap-3">
                <img
                    src="/stellar-logo.svg"
                    alt="Stellar Antivirus"
                    className="h-7 w-auto"
                    onError={(e) => {
                        (e.currentTarget as HTMLImageElement).style.display = "none";
                    }}
                />
                <div className="flex flex-col">
          <span className="text-sm font-semibold text-[#111827]">
            Stellar Antivirus
          </span>
                    <span className="text-[11px] text-[#6B7280]">
            Swiss-grade protection for Mac, Windows &amp; Linux.
          </span>
                </div>
            </div>

            <div className="flex items-center gap-3">
                {chips.map((cfg) => (
                    <div
                        key={cfg.id}
                        className={`flex items-center gap-2 px-4 py-2 rounded-full text-xs font-medium ${cfg.bg} ${cfg.text}`}
                    >
            <span
                className={`inline-flex h-1.5 w-1.5 rounded-full ${cfg.dotColor}`}
            />
                        <span>{cfg.label}</span>
                    </div>
                ))}
            </div>
        </header>
    );
};

export default HeaderBar;
