import React from "react";

interface LoginScreenProps {
    onAuthenticated?: () => void;
}

const LoginScreen: React.FC<LoginScreenProps> = ({ onAuthenticated }) => {
    const handleLogin = (e: React.FormEvent) => {
        e.preventDefault();
        onAuthenticated?.();
    };

    return (
        <div className="h-full flex items-center justify-center">
            <div className="w-[420px] bg-white rounded-3xl shadow-[0_20px_60px_rgba(15,23,42,0.35)] px-8 py-8">
                <h1 className="text-xl font-semibold text-[#020617] mb-2">
                    Log in to Stellar
                </h1>
                <p className="text-xs text-[#6B7280] mb-6">
                    Sign in with your Stellar ID to sync your devices and protection.
                </p>

                <form onSubmit={handleLogin} className="space-y-4">
                    <div>
                        <label className="block text-xs font-medium text-[#4B5563] mb-1">
                            Email (Stellar ID)
                        </label>
                        <input
                            type="email"
                            className="w-full h-9 rounded-xl border border-[#E5E7EB] px-3 text-xs focus:outline-none focus:ring-1 focus:ring-[#2563EB]"
                            placeholder="you@example.com"
                            required
                        />
                    </div>

                    <div>
                        <label className="block text-xs font.medium text-[#4B5563] mb-1">
                            Password
                        </label>
                        <input
                            type="password"
                            className="w-full h-9 rounded-xl border border-[#E5E7EB] px-3 text-xs focus:outline-none focus:ring-1 focus:ring-[#2563EB]"
                            placeholder="••••••••••"
                            required
                        />
                        <div className="flex justify-end mt-1">
                            <button
                                type="button"
                                className="text-[11px] text-[#2563EB] hover:underline"
                            >
                                Forgot password?
                            </button>
                        </div>
                    </div>

                    <button
                        type="submit"
                        className="w-full h-9 rounded-full text-xs font-semibold bg-[#1D4ED8] text-white shadow-[0_10px_30px_rgba(37,99,235,0.6)] hover:bg-[#1E40AF]"
                    >
                        Log in
                    </button>
                </form>
            </div>
        </div>
    );
};

export default LoginScreen;
