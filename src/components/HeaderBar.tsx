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
          <span className="text-[14px] font-semibold uppercase text-[#111827]">
            Stellar Antivirus
          </span>
          <div className="text-[12px] font-normal text-[#62626A] flex items-center gap-1 flex-wrap">
            Swiss-grade protection for{" "}
            <img src="/dashboard/apple.svg" alt="Mac" className="w-3 h-3" />
            Mac,{" "}
            <img
              src="/dashboard/windows.svg"
              alt="Windows"
              className="w-3 h-3"
            />
            Windows &amp;{" "}
            <img src="/dashboard/linux.svg" alt="Linux" className="w-3 h-3" />
            Linux.
          </div>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {chips.map((cfg) => {
          if (cfg.id === "realtime_on") {
            return (
              <div
                key={cfg.id}
                className="flex items-center gap-2 px-[18px] py-[8px] rounded-full text-xs font-medium border-2 border-[#A6FFC7] bg-gradient-to-r from-[#A6FFC7] to-white"
                style={{
                  background: "linear-gradient(to right, #FFFFFF, #A6FFC7)",
                }}
              >
                <img
                  src="/dashboard/protection.svg"
                  alt=""
                  className="w-4 h-4"
                />
                <span className="text-[#60D38E]">{cfg.label}</span>
              </div>
            );
          }
          return (
            <div
              key={cfg.id}
              className={`flex items-center gap-2 px-4 py-2 rounded-full text-xs font-medium ${cfg.bg} ${cfg.text}`}
            >
              <span
                className={`inline-flex h-1.5 w-1.5 rounded-full ${cfg.dotColor}`}
              />
              <span>{cfg.label}</span>
            </div>
          );
        })}
      </div>
    </header>
  );
};

export default HeaderBar;
