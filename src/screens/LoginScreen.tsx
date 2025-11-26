import React from "react";

const LoginScreen: React.FC = () => {
    return (
        <div className="min-h-full flex items-center justify-center">
            <div className="w-[420px] bg-white rounded-[24px] shadow-[0_18px_50px_rgba(15,23,42,0.12)] px-8 py-8">
                <h2 className="text-xl font-semibold text-[#0B1240] mb-2">
                    Log in to Stellar
                </h2>
                <p className="text-xs text-[#6B7280] mb-6">
                    Use your Stellar ID to access your devices and subscriptions.
                </p>

                <div className="space-y-4">
                    <div className="space-y-1">
                        <label className="text-xs font-medium text-[#4B5563]">
                            Email
                        </label>
                        <input
                            type="email"
                            className="w-full h-10 rounded-xl border border-[#E5E7EB] px-3 text-sm outline-none focus:ring-2 focus:ring-[#2563EB] focus:border-[#2563EB]"
                            placeholder="you@example.com"
                        />
                    </div>

                    <div className="space-y-1">
                        <label className="text-xs font-medium text-[#4B5563]">
                            Password
                        </label>
                        <input
                            type="password"
                            className="w-full h-10 rounded-xl border border-[#E5E7EB] px-3 text-sm outline-none focus:ring-2 focus:ring-[#2563EB] focus:border-[#2563EB]"
                            placeholder="••••••••••"
                        />
                        <button className="mt-1 text-[11px] text-[#2563EB]">
                            Forgot password?
                        </button>
                    </div>

                    <button className="w-full h-10 rounded-full bg-[#2563EB] text-white text-sm font-semibold shadow-[0_12px_30px_rgba(37,99,235,0.5)] mt-2">
                        Log in
                    </button>
                </div>

                <div className="mt-6 text-xs text-center text-[#6B7280]">
                    Don’t have a Stellar ID?{" "}
                    <span className="text-[#2563EB]">Create one</span>
                </div>
            </div>
        </div>
    );
};

export default LoginScreen;