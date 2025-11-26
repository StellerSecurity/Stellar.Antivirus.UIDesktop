import React from "react";

interface RegisterScreenProps {
    onAuthenticated?: () => void;
}

const RegisterScreen: React.FC<RegisterScreenProps> = ({ onAuthenticated }) => {
    const handleRegister = (e: React.FormEvent) => {
        e.preventDefault();
        onAuthenticated?.();
    };

    return (
        <div className="h-full flex items-center justify-center">
            <div className="w-[460px] bg-white rounded-3xl shadow-[0_20px_60px_rgba(15,23,42,0.35)] px-8 py-8">
                <h1 className="text-xl font-semibold text-[#020617] mb-2">
                    Create your Stellar ID
                </h1>
                <p className="text-xs text-[#6B7280] mb-6">
                    Your Stellar ID keeps your devices, subscriptions and security in one
                    place.
                </p>

                <form onSubmit={handleRegister} className="space-y-4">
                    <div className="grid grid-cols-2 gap-3">
                        <div>
                            <label className="block text-xs font-medium text-[#4B5563] mb-1">
                                First name
                            </label>
                            <input
                                type="text"
                                className="w-full h-9 rounded-xl border border-[#E5E7EB] px-3 text-xs focus:outline-none focus:ring-1 focus:ring-[#2563EB]"
                                required
                            />
                        </div>
                        <div>
                            <label className="block text-xs font-medium text-[#4B5563] mb-1">
                                Last name
                            </label>
                            <input
                                type="text"
                                className="w-full h-9 rounded-xl border border-[#E5E7EB] px-3 text-xs focus:outline-none focus:ring-1 focus:ring-[#2563EB]"
                                required
                            />
                        </div>
                    </div>

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
                        <label className="block text-xs font-medium text-[#4B5563] mb-1">
                            Password
                        </label>
                        <input
                            type="password"
                            className="w-full h-9 rounded-xl border border-[#E5E7EB] px-3 text-xs focus:outline-none focus:ring-1 focus:ring-[#2563EB]"
                            placeholder="At least 10 characters"
                            required
                        />
                        <p className="text-[11px] text-[#9CA3AF] mt-1">
                            Use a strong, unique password. Stellar never stores it in
                            plaintext.
                        </p>
                    </div>

                    <button
                        type="submit"
                        className="w-full h-9 rounded-full text-xs font-semibold bg-[#1D4ED8] text-white shadow-[0_10px_30px_rgba(37,99,235,0.6)] hover:bg-[#1E40AF] mt-2"
                    >
                        Create Stellar ID
                    </button>
                </form>
            </div>
        </div>
    );
};

export default RegisterScreen;
