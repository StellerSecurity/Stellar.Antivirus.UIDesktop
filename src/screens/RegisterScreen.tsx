import React from "react";

const RegisterScreen: React.FC = () => {
    return (
        <div className="min-h-full flex items-center justify-center">
            <div className="w-[460px] bg-white rounded-[24px] shadow-[0_18px_50px_rgba(15,23,42,0.12)] px-8 py-8">
                <h2 className="text-xl font-semibold text-[#0B1240] mb-2">
                    Create your Stellar ID
                </h2>
                <p className="text-xs text-[#6B7280] mb-6">
                    One secure account for Stellar Antivirus, Stellar Phone and more.
                </p>

                <div className="grid grid-cols-2 gap-4 mb-4">
                    <div className="space-y-1">
                        <label className="text-xs font-medium text-[#4B5563]">
                            First name
                        </label>
                        <input
                            className="w-full h-10 rounded-xl border border-[#E5E7EB] px-3 text-sm outline-none focus:ring-2 focus:ring-[#2563EB] focus:border-[#2563EB]"
                            placeholder="Blerim"
                        />
                    </div>
                    <div className="space-y-1">
                        <label className="text-xs font-medium text-[#4B5563]">
                            Last name
                        </label>
                        <input
                            className="w-full h-10 rounded-xl border border-[#E5E7EB] px-3 text-sm outline-none focus:ring-2 focus:ring-[#2563EB] focus:border-[#2563EB]"
                            placeholder="Cazimi"
                        />
                    </div>
                </div>

                <div className="space-y-1 mb-4">
                    <label className="text-xs font-medium text-[#4B5563]">
                        Email (Stellar ID)
                    </label>
                    <input
                        type="email"
                        className="w-full h-10 rounded-xl border border-[#E5E7EB] px-3 text-sm outline-none focus:ring-2 focus:ring-[#2563EB] focus:border-[#2563EB]"
                        placeholder="you@example.com"
                    />
                </div>

                <div className="space-y-1 mb-4">
                    <label className="text-xs font-medium text-[#4B5563]">
                        Password
                    </label>
                    <input
                        type="password"
                        className="w-full h-10 rounded-xl border border-[#E5E7EB] px-3 text-sm outline-none focus:ring-2 focus:ring-[#2563EB] focus:border-[#2563EB]"
                        placeholder="Create a strong password"
                    />
                    <p className="text-[11px] text-[#9CA3AF]">
                        Minimum 10 characters. Use a unique password for Stellar.
                    </p>
                </div>

                <button className="w-full h-10 rounded-full bg-[#0B1240] text-white text-sm font-semibold shadow-[0_12px_30px_rgba(15,23,42,0.5)] mt-2">
                    Create Stellar ID
                </button>

                <div className="mt-6 text-xs text-center text-[#6B7280]">
                    Already have a Stellar ID?{" "}
                    <span className="text-[#2563EB]">Log in</span>
                </div>
            </div>
        </div>
    );
};

export default RegisterScreen;
