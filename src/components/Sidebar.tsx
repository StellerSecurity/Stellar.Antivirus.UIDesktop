import React from "react";

export type SidebarView = "dashboard" | "logs" | "settings";

interface Props {
  current: SidebarView;
  onChange: (view: SidebarView) => void;
  onLogout?: () => void;
}

const Sidebar: React.FC<Props> = ({ current, onChange, onLogout }) => {
  return (
    <aside className="w-[240px] bg-[#0B0C19] text-white flex flex-col px-[20px] py-[14px] rounded-l-[32px]">
      {/* Logo Section */}
      <div className="flex items-center gap-3 mb-8">
        <img
          src="/dashboard/dashboard-logo.svg"
          alt="Stellar"
          className="w-full"
        />
      </div>

      <nav className="space-y-6 flex-1">
        {/* OVERVIEW Section */}
        <div>
          <div className="text-[10px] font-medium text-[#62626A] uppercase tracking-wide mb-3">
            OVERVIEW
          </div>
          <div className="space-y-1">
            <SidebarItem
              icon="/dashboard/dashboard.svg"
              label="DASHBOARD"
              active={current === "dashboard"}
              onClick={() => onChange("dashboard")}
            />
            <SidebarItem
              icon="/dashboard/recent-activity.svg"
              label="ACTIVITY LOG"
              active={current === "logs"}
              onClick={() => onChange("logs")}
            />
          </div>
        </div>

        {/* SETTINGS Section */}
        <div>
          <div className="text-[10px] font-medium text-[#62626A] uppercase tracking-wide mb-3">
            SETTINGS
          </div>
          <div className="space-y-1">
            <SidebarItem
              icon="/dashboard/settings.svg"
              label="SETTINGS"
              active={current === "settings"}
              onClick={() => onChange("settings")}
            />
            <SidebarItem
              icon="/dashboard/logout.svg"
              label="LOG OUT"
              active={false}
              onClick={() => onLogout?.()}
              isLogout
            />
          </div>
        </div>
      </nav>

      {/* Footer */}
      <div className="mt-auto pt-6">
        <div className="text-[10px] font-medium text-[#2761FC] text-center mb-2">
          POWERED BY
        </div>
        <div className="flex justify-center items-center gap-2">
          <img
            src="dashboard/security.svg"
            alt=""
            className="w-[15px] h-[15px]"
          />
          <span className="text-sm font-semibold text-white">
            Stellar Security
          </span>
        </div>
      </div>
    </aside>
  );
};

interface ItemProps {
  icon: string;
  label: string;
  active?: boolean;
  onClick: () => void;
  isLogout?: boolean;
}

const SidebarItem: React.FC<ItemProps> = ({
  icon,
  label,
  active,
  onClick,
  isLogout,
}) => {
  const textColor = isLogout
    ? "text-red-500"
    : active
      ? "text-[#2761FC]"
      : "text-white";

  return (
    <button
      onClick={onClick}
      className="w-full flex items-center gap-3 px-3 py-3 rounded-2xl text-[14px] font-semibold font-poppins transition hover:opacity-80"
    >
      <div
        className={`w-5 h-5 ${textColor}`}
        style={{
          maskImage: `url(${icon})`,
          WebkitMaskImage: `url(${icon})`,
          maskSize: "contain",
          WebkitMaskSize: "contain",
          maskRepeat: "no-repeat",
          WebkitMaskRepeat: "no-repeat",
          maskPosition: "center",
          WebkitMaskPosition: "center",
          backgroundColor: "currentColor",
        }}
      />
      <span className={textColor}>{label}</span>
    </button>
  );
};

export default Sidebar;
