import React from "react";

export type SidebarView = "dashboard" | "logs" | "settings";

interface Props {
    current: SidebarView;
    onChange: (view: SidebarView) => void;
}

const Sidebar: React.FC<Props> = ({ current, onChange }) => {
    return (
        <aside className="w-64 bg-[#0B1240] text-white flex flex-col px-6 py-6">
            <div className="flex items-center gap-3 mb-8">
                <div className="w-10 h-10 rounded-2xl bg-white/10 flex items-center justify-center">
                    <span className="text-xl">🛡️</span>
                </div>
                <div>
                    <div className="text-sm opacity-70">Stellar Security</div>
                    <div className="text-lg font-semibold">Stellar Antivirus</div>
                </div>
            </div>

            <nav className="space-y-2 flex-1">
                <SidebarItem
                    label="Dashboard"
                    active={current === "dashboard"}
                    onClick={() => onChange("dashboard")}
                />
                <SidebarItem
                    label="Activity Log"
                    active={current === "logs"}
                    onClick={() => onChange("logs")}
                />
                <SidebarItem
                    label="Settings"
                    active={current === "settings"}
                    onClick={() => onChange("settings")}
                />
            </nav>

            <div className="mt-auto pt-6 text-xs text-white/60">
                Powered by Stellar Security
            </div>
        </aside>
    );
};

interface ItemProps {
    label: string;
    active?: boolean;
    onClick: () => void;
}

const SidebarItem: React.FC<ItemProps> = ({ label, active, onClick }) => {
    return (
        <button
            onClick={onClick}
            className={`w-full flex items-center justify-between px-3 py-3 rounded-2xl text-sm transition
      ${
                active
                    ? "bg-white text-[#0B1240] font-semibold shadow-[0_8px_24px_rgba(15,23,42,0.18)]"
                    : "text-white/80 hover:bg-white/5"
            }`}
        >
            <span>{label}</span>
            <span className="text-xs opacity-60">›</span>
        </button>
    );
};

export default Sidebar;
