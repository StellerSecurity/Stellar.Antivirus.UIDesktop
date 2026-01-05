// src/screens/LoginScreen.tsx

import React, { useState } from "react";
import { login } from "../api/auth";
import Input from "../components/Input";
import Button from "../components/Button";

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
        window.localStorage.setItem("stellar_user", JSON.stringify(res.user));
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
    <div className="h-full flex items-center justify-center relative">
      <div className="flex items-center justify-center p-[90px] gap-5">
        <div className="image">
          <img src="/App.png" alt="Login" />
        </div>
        <div className="w-[420px]">
          {/* Subtitle */}
          <div className="flex items-center gap-2 mb-3">
            <span className="text-primary text-sm">⚡</span>
            <span className="text-white text-xs font-semibold uppercase tracking-wide">
              REAL-TIME PROTECTION
            </span>
          </div>

          <h1 className="text-[30px] font-semibold font-poppins text-white mb-1">
            3. Log in to Stellar Antivirus
          </h1>
          <p className="text-[16px] text-[#CFCFFF] font-semibold mb-6 mt-2">
            Use your Stellar ID email to continue.
          </p>

          <form onSubmit={handleSubmit} className="">
            <div className="space-y-4">
              <Input
                label="STELLAR ID EMAIL"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                placeholder="Your email"
                required
              />

              <Input
                label="PASSWORD"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                placeholder="Your password"
                required
              />

              {error && (
                <div className="text-[12px] text-red-600 bg-red-50 border border-red-100 rounded-xl px-3 py-2">
                  {error}
                </div>
              )}
            </div>

            <div className="flex items-center justify-between mt-6">
              <Button type="submit" disabled={loading}>
                {loading ? "Logging in..." : "LOG IN"}
              </Button>
              <button
                type="button"
                className="text-primary text-sm hover:underline"
              >
                FORGOT PASSWORD?
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Progress Indicator - Absolute bottom left */}
      <div className="absolute bottom-8 left-8 flex items-center gap-2">
        {[1, 2, 3, 4, 5].map((stepNum) => (
          <div
            key={stepNum}
            className={`h-1 w-8 rounded ${
              stepNum === 3 ? "bg-primary" : "bg-white/30"
            }`}
          />
        ))}
      </div>

      {/* CREATE STELLAR ID Button - Absolute bottom right */}
      <div className="absolute bottom-8 right-8">
        <Button type="button" onClick={onGoToRegister}>
          CREATE STELLAR ID
        </Button>
      </div>
    </div>
  );
};

export default LoginScreen;
