// src/screens/LoginScreen.tsx

import React, { useState } from "react";
import { login } from "../api/auth";

interface LoginScreenProps {
    onAuthenticated?: (token?: string) => void;
    onGoToRegister?: () => void;
}

const LoginScreen: React.FC<LoginScreenProps> = ({
                                                     onAuthenticated,
                                                     onGoToRegister,
                                                 }) => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        setLoading(true);

        try {
            // login() is typed in auth.ts to return ApiEnvelope
            const res = await login({ username, password });

            if (!res.token) {
                throw new Error("No token returned from server");
            }

            // Store user and subscription locally (optional but useful)
            if (typeof window !== "undefined") {
                window.localStorage.setItem(
                    "stellar_user",
                    JSON.stringify(res.user)
                );
                if (res.subscription_id) {
                    window.localStorage.setItem(
                        "stellar_subscription_id",
                        res.subscription_id
                    );
                }
            }

            onAuthenticated?.(res.token);
        } catch (err: any) {
            console.error(err);
            if (err?.response?.response_message) {
                setError(err.response.response_message);
            } else if (err?.message) {
                setError(err.message);
            } else {
                setError("Login failed. Please try again.");
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="h-full flex items-center justify-center bg-[#050816]">
            <div className="w-[420px] bg-white rounded-3xl shadow-[0_20px_60px_rgba(15,23,42,0.35)] px-8 py-8">
                <h1 className="text-xl font-semibold text-[#020617] mb-1">
                    Log in to Stellar Antivirus
                </h1>
                <p className="text-[13px] text-slate-500 mb-6">
                    Use your Stellar ID (email/username) to continue.
                </p>

                <form onSubmit={handleSubmit} className="space-y-4">
                    <div>
                        <label className="block text-[12px] font-medium text-slate-600 mb-1.5">
                            Email / Username
                        </label>
                        <input
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            className="w-full h-9 rounded-xl border border-slate-200 px-3 text-[13px] focus:outline-none focus:ring-2 focus:ring-slate-900/80"
                            autoComplete="username"
                            required
                        />
                    </div>

                    <div>
                        <label className="block text-[12px] font-medium text-slate-600 mb-1.5">
                            Password
                        </label>
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            className="w-full h-9 rounded-xl border border-slate-200 px-3 text-[13px] focus:outline-none focus:ring-2 focus:ring-slate-900/80"
                            autoComplete="current-password"
                            required
                        />
                    </div>

                    {error && (
                        <div className="text-[12px] text-red-600 bg-red-50 border border-red-100 rounded-xl px-3 py-2">
                            {error}
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full h-9 rounded-full text-[13px] font-semibold text-white bg-[#111827] shadow-[0_10px_30px_rgba(15,23,42,0.6)] hover:bg-black disabled:opacity-70 disabled:cursor-not-allowed transition"
                    >
                        {loading ? "Logging in..." : "Log in"}
                    </button>
                </form>

                <div className="mt-4 text-[12px] text-slate-500 text-center">
                    <span>Don&apos;t have a Stellar ID?</span>{" "}
                    <button
                        type="button"
                        onClick={onGoToRegister}
                        className="font-semibold text-[#111827] hover:underline"
                    >
                        Create Stellar ID
                    </button>
                </div>
            </div>
        </div>
    );
};

export default LoginScreen;
