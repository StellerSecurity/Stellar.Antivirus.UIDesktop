// src/screens/RegisterScreen.tsx

import React, { useState } from "react";
import { register } from "../api/auth";
import Input from "../components/Input";
import Button from "../components/Button";

interface RegisterScreenProps {
  onAuthenticated?: (token?: string) => void;
  onGoToLogin?: () => void;
}

const RegisterScreen: React.FC<RegisterScreenProps> = ({
  onAuthenticated,
  onGoToLogin,
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
      // register() is typed in auth.ts to return ApiEnvelope
      const res = await register({ username, password });

      // Check response_code === 200 before storing
      if (res.response_code !== 200) {
        throw new Error(res.response_message || "Registration failed");
      }

      if (!res.token) {
        throw new Error("No token returned from server");
      }

      // Store user and subscription metadata locally (optional but useful)
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
        setError("Registration failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-full flex items-center justify-center">
      <div className="flex items-center justify-center p-[90px] gap-5">
        <div className="image">
          <img src="/App.png" alt="Register" />
        </div>
        <div className="w-[420px]">
          <h1 className="text-[30px] font-semibold font-poppins text-white mb-1">
            Create your Stellar ID
          </h1>
          <p className="text-[16px] text-[#CFCFFF] font-semibold mb-6 mt-2">
            Your Stellar ID is used across Stellar Antivirus and the rest of the
            Stellar ecosystem.
          </p>

          <form onSubmit={handleSubmit} className="">
            <div className="space-y-4">
              <Input
                label="Stellar ID email"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                required
                labelClassName="!text-[#CFCFFF]"
              />

              <Input
                label="Password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                required
                labelClassName="!text-[#CFCFFF]"
              />

              {error && (
                <div className="text-[12px] text-red-600 bg-red-50 border border-red-100 rounded-xl px-3 py-2">
                  {error}
                </div>
              )}
            </div>

            <Button type="submit" disabled={loading} className="!mt-6">
              {loading ? "Creating account..." : "Create Stellar ID"}
            </Button>
          </form>

          <div className="mt-4 text-[12px] text-[#CFCFFF] text-center bg-[#F6F6FD] rounded-full px-4 py-2">
            <span>Already have a Stellar ID?</span>{" "}
            <Button
              type="button"
              onClick={() => {
                setError(null);
                onGoToLogin?.();
              }}
              variant="secondary"
              className="bg-transparent border-none hover:underline text-[#CFCFFF]"
            >
              Log in
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RegisterScreen;
