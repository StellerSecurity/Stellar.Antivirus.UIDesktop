// src/screens/SettingsScreen.tsx
import React from "react";
import type { DashboardResponse } from "../api/dashboard";
import Button from "../components/Button";

interface SettingsScreenProps {
  onLogout?: () => void;
  dashboard?: DashboardResponse | null;
}

const SettingsScreen: React.FC<SettingsScreenProps> = ({
  onLogout,
  dashboard,
}) => {
  // Username (Stellar ID) from dashboard, fallback if missing
  const stellarId = dashboard?.user?.username ?? "user@example.com";

  // Expiry from subscription (ISO string from backend)
  const expiresAtIso = dashboard?.subscription?.expires_at ?? null;

  let expiryDisplay = "—";
  let daysLeftDisplay: string | number = "—";

  if (expiresAtIso) {
    const expiryDate = new Date(expiresAtIso);
    if (!isNaN(expiryDate.getTime())) {
      expiryDisplay = expiryDate.toISOString().slice(0, 10); // YYYY-MM-DD

      const now = new Date();
      const diffMs = expiryDate.getTime() - now.getTime();
      const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
      daysLeftDisplay = diffDays > 0 ? diffDays : 0;
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Stellar ID + subscription */}
      <div className="bg-white rounded-[24px] px-6 py-5 flex flex-col gap-4">
        <div>
          <div className="flex items-center gap-2 mb-[12px]">
            <img src="/settings/settings.svg" alt="" className="w-5 h-5" />
            <h2 className="text-[14px] font-semibold text-[#2761FC] uppercase">
              Settings
            </h2>
          </div>
          <p className="text-xs text-[#6B7280] mb-4 pb-4 border-b-2 border-[#F6F6FD]">
            Manage your Stellar ID, subscription and support options.
          </p>
          <div className="flex items-center gap-2 justify-between rounded-full border-2 border-[#F6F6FD] px-4 py-2">
            <div className="text-xs font-semibold text-[#62626A]">
              STELLAR ID
            </div>
            <div className="text-[12px] font-regular text-[#2761FC]">
              {stellarId}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4 text-xs">
          <div className="bg-[#F3F4FF] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Subscription
            </div>
            <div className="text-xs text-[#62626A]">Stellar Antivirus</div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Days remaining
            </div>
            <div className="text-xs text-[#62626A]">
              {daysLeftDisplay !== "—" ? `${daysLeftDisplay} days` : "—"}
            </div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Expires on
            </div>
            <div className="text-xs text-[#62626A]">{expiryDisplay}</div>
          </div>
        </div>
      </div>

      {/* Help & support */}
      <div className="bg-white rounded-[24px] px-6 py-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <img src="/settings/helpsupport.svg" alt="" className="w-5 h-5" />
              <h3 className="text-sm font-semibold text-[#2761FC] uppercase">
                Help & support
              </h3>
            </div>
            <p className="text-[12px] font-normal text-[#62626A]">
              Contact Stellar Security if you need assistance.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4 text-xs">
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Signal
            </div>
            <div className="text-xs  font-normal text-[#2761FC]">
              @StellarSecurity
            </div>
            <div className="text-[12px] text-[#62626A] mt-1">
              Preferred for secure chat.
            </div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#62626A] mb-1 uppercase">
              Email
            </div>
            <div className="text-xs  font-normal text-[#2761FC]">
              info@stellarsecurity.com
            </div>
            <div className="text-[12px] text-[#62626A] mt-1">
              For billing and general questions.
            </div>
          </div>
          <div className="bg-[#F6F6FD] rounded-[20px] p-3">
            <div className="text-[12px] font-semibold text-[#303031] mb-1 uppercase">
              Website
            </div>
            <div className="text-xs  font-normal text-[#2761FC]">
              StellarSecurity.com
            </div>
            <div className="text-[12px] text-[#62626A] mt-1">
              Docs, FAQ and product updates.
            </div>
          </div>
        </div>
      </div>

      {/* Log out card */}
      <div className="bg-white rounded-[24px] px-6 py-5 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 mb-[12px]">
            <img src="/settings/logout.svg" alt="" className="w-5 h-5" />
            <div className="text-[14px] font-semibold text-[#2761FC] uppercase w-[68px] !h-[20px] ">
              Log out
            </div>
          </div>
          <p className="text-[12px] text-[#6B7280]">
            Sign out of Stellar Antivirus on this device. You can log in again
            with your Stellar ID at any time.
          </p>
        </div>
        <Button
          onClick={onLogout}
          className="bg-[#F96262] hover:bg-[#F96262]/90 text-[12px] h-[20px] py-0"
        >
          Log out
        </Button>
      </div>
    </div>
  );
};

export default SettingsScreen;
