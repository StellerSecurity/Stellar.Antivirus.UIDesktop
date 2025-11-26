import React from "react";

const SettingsScreen: React.FC = () => {
    // Demo-data – kan senere hentes fra backend
    const stellarId = "bc@stellarsecurity.com";
    const expiry = "2026-01-15";
    const daysLeft = 247;

    return (
        <div className="pt-6 flex flex-col gap-6">
            <div>
                <h2 className="text-lg font-semibold text-[#111827] mb-1">
                    Settings
                </h2>
                <p className="text-xs text-[#6B7280]">
                    Manage your Stellar ID, subscription and support options.
                </p>
            </div>

            {/* Stellar ID + subscription */}
            <div className="bg-white rounded-[24px] shadow-[0_16px_40px_rgba(15,23,42,0.06)] px-6 py-5 flex flex-col gap-4">
                <div>
                    <div className="text-xs font-semibold text-[#3B82F6] mb-1">
                        STELLAR ID
                    </div>
                    <div className="text-sm font-medium text-[#111827]">
                        {stellarId}
                    </div>
                </div>

                <div className="grid grid-cols-3 gap-4 text-xs">
                    <div className="bg-[#F3F4FF] rounded-2xl px-4 py-3">
                        <div className="text-[11px] text-[#6B7280] mb-1">
                            Subscription
                        </div>
                        <div className="text-sm font-semibold text-[#111827]">
                            Stellar Antivirus
                        </div>
                    </div>
                    <div className="bg-[#ECFDF3] rounded-2xl px-4 py-3">
                        <div className="text-[11px] text-[#6B7280] mb-1">
                            Days remaining
                        </div>
                        <div className="text-sm font-semibold text-[#166534]">
                            {daysLeft} days
                        </div>
                    </div>
                    <div className="bg-[#FEF3C7] rounded-2xl px-4 py-3">
                        <div className="text-[11px] text-[#92400E] mb-1">
                            Expires on
                        </div>
                        <div className="text-sm font-semibold text-[#92400E]">
                            {expiry}
                        </div>
                    </div>
                </div>
            </div>

            {/* Help & support */}
            <div className="bg-white rounded-[24px] shadow-[0_16px_40px_rgba(15,23,42,0.06)] px-6 py-5">
                <div className="flex items-center justify-between mb-4">
                    <div>
                        <h3 className="text-sm font-semibold text-[#111827]">
                            Help & support
                        </h3>
                        <p className="text-xs text-[#6B7280]">
                            Contact Stellar Security if you need assistance.
                        </p>
                    </div>
                </div>

                <div className="grid grid-cols-3 gap-4 text-xs">
                    <div className="border border-[#E5E7EB] rounded-2xl px-4 py-3">
                        <div className="text-[11px] text-[#6B7280] mb-1">Signal</div>
                        <div className="text-sm font-semibold text-[#111827]">
                            @StellarSecurity
                        </div>
                        <div className="text-[11px] text-[#9CA3AF] mt-1">
                            Preferred for secure chat.
                        </div>
                    </div>
                    <div className="border border-[#E5E7EB] rounded-2xl px-4 py-3">
                        <div className="text-[11px] text-[#6B7280] mb-1">Email</div>
                        <div className="text-sm font-semibold text-[#111827]">
                            info@stellarsecurity.com
                        </div>
                        <div className="text-[11px] text-[#9CA3AF] mt-1">
                            For billing and general questions.
                        </div>
                    </div>
                    <div className="border border-[#E5E7EB] rounded-2xl px-4 py-3">
                        <div className="text-[11px] text-[#6B7280] mb-1">Website</div>
                        <div className="text-sm font-semibold text-[#2563EB]">
                            StellarSecurity.com
                        </div>
                        <div className="text-[11px] text-[#9CA3AF] mt-1">
                            Docs, FAQ and product updates.
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SettingsScreen;
