// src/screens/OnboardingScreen.tsx

import React, { useState } from "react";
import Button from "../components/Button";
import Input from "../components/Input";

interface OnboardingScreenProps {
  step: number;
  onNext: () => void;
  onAllow?: () => void;
  onAuthenticated?: (token?: string) => void;
}

const OnboardingScreen: React.FC<OnboardingScreenProps> = ({
  step,
  onNext,
  onAllow,
  onAuthenticated,
}) => {
  // Auth state for login/register
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Step 1: What Stellar Antivirus does
  const renderStep1 = () => (
    <>
      {/* Subtitle */}
      <div className="flex items-center gap-2 mb-3">
        <span className="text-primary text-sm">🛡️</span>
        <span className="text-white text-xs font-semibold uppercase tracking-wide">
          REAL-TIME PROTECTION
        </span>
      </div>

      {/* Main Heading */}
      <h1 className="text-[30px] font-semibold font-poppins text-white mb-4">
        1. What Stellar Antivirus does
      </h1>

      {/* Tagline */}
      <p className="text-[16px] text-[#CFCFFF] font-semibold mb-3">
        Keeps your computer safe — <em>automatically</em>.
      </p>

      {/* Description */}
      <p className="text-sm text-white/80 mb-6">
        Stellar Antivirus protects your device in real time by finding and
        blocking dangerous files before they can cause harm.
      </p>

      {/* Feature List */}
      <div className="space-y-3 mb-6">
        <div className="flex items-center gap-3">
          <span className="text-primary text-lg">✓</span>
          <span className="text-white text-sm">Detects viruses</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-primary text-lg">✓</span>
          <span className="text-white text-sm">Blocks threats instantly</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-primary text-lg">✓</span>
          <span className="text-white text-sm">Real-time protection</span>
        </div>
      </div>

      {/* Concluding Statement */}
      <p className="text-base text-white font-medium mb-8">
        Protection runs quietly in the background.
      </p>
    </>
  );

  // Step 2: How Stellar protects you
  const renderStep2 = () => (
    <>
      {/* Subtitle */}
      <div className="flex items-center gap-2 mb-3">
        <span className="text-primary text-sm">⚡</span>
        <span className="text-white text-xs font-semibold uppercase tracking-wide">
          REAL-TIME PROTECTION
        </span>
      </div>

      {/* Main Heading */}
      <h1 className="text-[30px] font-semibold font-poppins text-white mb-4">
        2. How Stellar protects you
      </h1>

      {/* Core Message */}
      <p className="text-[16px] text-[#CFCFFF] font-semibold mb-3">
        Your files never leave your computer.
      </p>

      {/* Explanation */}
      <p className="text-sm text-white/80 mb-6">
        Stellar Antivirus checks files using an unique fingerprint. Your actual
        files are never uploaded or shared.
      </p>

      {/* Feature List */}
      <div className="space-y-3 mb-6">
        <div className="flex items-center gap-3">
          <span className="text-primary text-lg">✓</span>
          <span className="text-white text-sm">Files stay on your device</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-primary text-lg">✓</span>
          <span className="text-white text-sm">
            Open-source client (fully transparent)
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-primary text-lg">✓</span>
          <span className="text-white text-sm">
            Built with a secure Rust engine
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-red-500 text-lg">⊕</span>
          <span className="text-white text-sm">Hosted in Switzerland</span>
        </div>
      </div>

      {/* Concluding Statements */}
      <p className="text-base text-white font-medium mb-2">
        Protected by strict Swiss data-protection laws.
      </p>
      <p className="text-base text-white font-medium mb-8">
        Private. Transparent. Secure.
      </p>
    </>
  );

  // Handle auth form submission
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    // Basic validation
    if (!username || !password) {
      setError("Please fill in all fields");
      setLoading(false);
      return;
    }

    // Simulate API call delay for better UX
    await new Promise((resolve) => setTimeout(resolve, 500));

    try {
      // For now, bypass API and proceed directly
      // TODO: Integrate actual API later
      const mockToken = `mock_token_${Date.now()}`;
      const mockUser = {
        id: 1,
        username: username,
        email: username,
      };

      // Store user locally
      if (typeof window !== "undefined") {
        window.localStorage.setItem("stellar_user", JSON.stringify(mockUser));
      }

      // Proceed to next step
      onAuthenticated?.(mockToken);
    } catch (err: any) {
      console.error(err);
      setError(
        authMode === "login"
          ? "Login failed. Please try again."
          : "Registration failed. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  // Step 3: Login/Register form
  const renderStep3 = () => (
    <>
      {/* Subtitle */}
      <div className="flex items-center gap-2 mb-3">
        <span className="text-primary text-sm">⚡</span>
        <span className="text-white text-xs font-semibold uppercase tracking-wide">
          REAL-TIME PROTECTION
        </span>
      </div>

      {/* Main Heading */}
      <h1 className="text-[30px] font-semibold font-poppins text-white mb-4">
        {authMode === "login"
          ? "3. Log in to Stellar Antivirus"
          : "3. Create your Stellar ID"}
      </h1>

      {/* Description */}
      {authMode === "login" ? (
        <p className="text-[16px] text-[#CFCFFF] font-semibold mb-6">
          Use your Stellar ID to activate your antivirus and unlock the rest of
          the Stellar ecosystem.
        </p>
      ) : (
        <p className="text-sm text-white/80 mb-6">
          Your Stellar ID is used across Stellar Antivirus and the rest of the
          Stellar ecosystem.
        </p>
      )}

      {/* Auth Form */}
      <form onSubmit={handleAuthSubmit} className="space-y-4">
        <Input
          label="STELLAR ID EMAIL"
          type="email"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Your email"
          required
          autoComplete={authMode === "login" ? "email" : "username"}
        />

        <Input
          label="PASSWORD"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Your password"
          required
          autoComplete={
            authMode === "login" ? "current-password" : "new-password"
          }
        />

        {error && (
          <div className="text-[12px] text-red-400 bg-red-900/20 border border-red-800 rounded-xl px-3 py-2">
            {error}
          </div>
        )}

        <div className="flex items-center justify-between mt-6">
          <Button type="submit" disabled={loading}>
            {loading
              ? authMode === "login"
                ? "Logging in..."
                : "Creating..."
              : authMode === "login"
              ? "LOG IN"
              : "CREATE STELLAR ID"}
          </Button>
          {authMode === "login" ? (
            <button
              type="button"
              className="text-primary text-sm hover:underline"
              onClick={() => setAuthMode("register")}
            >
              CREATE STELLAR ID
            </button>
          ) : (
            <button
              type="button"
              className="text-primary text-sm hover:underline"
              onClick={() => setAuthMode("login")}
            >
              Already have a Stellar ID? Log in
            </button>
          )}
        </div>
      </form>
    </>
  );

  // Step 4: What Stellar needs
  const renderStep4 = () => (
    <>
      {/* Subtitle */}
      <div className="flex items-center gap-2 mb-3">
        <span className="text-primary text-sm">⚡</span>
        <span className="text-white text-xs font-semibold uppercase tracking-wide">
          REAL-TIME PROTECTION
        </span>
      </div>

      {/* Main Heading */}
      <h1 className="text-[30px] font-semibold font-poppins text-white mb-4">
        4. What Stellar needs
      </h1>

      {/* Primary Instruction */}
      <p className="text-[16px] text-[#CFCFFF] font-semibold mb-3">
        We need permission to protect your device.
      </p>

      {/* Explanation */}
      <p className="text-sm text-white/80 mb-6">
        To scan for threats, Stellar Antivirus needs access to your files. This
        is only used to check for viruses — nothing else.
      </p>

      {/* Assurances List */}
      <div className="space-y-3 mb-6">
        <div className="flex items-center gap-3">
          <span className="text-primary text-lg">✓</span>
          <span className="text-white text-sm">
            We do not read your documents
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-primary text-lg">✓</span>
          <span className="text-white text-sm">
            We do not upload your files
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-primary text-lg">✓</span>
          <span className="text-white text-sm">
            We only scan locally on your device
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-primary text-lg">✓</span>
          <span className="text-white text-sm">You stay in full control</span>
        </div>
      </div>

      {/* Call to Action */}
      <p className="text-base text-white font-semibold mb-8">
        Allow access to stay protected.
      </p>
    </>
  );

  return (
    <div className="h-full flex items-center justify-center relative">
      <div className="flex items-center justify-center p-[90px] gap-5">
        {step === 4 ? (
          // Step 4: Shield icon with lightning bolt
          <div className="relative flex items-center justify-center">
            {/* Sparkling stars */}
            <div className="absolute -top-8 -left-8 text-primary text-2xl animate-pulse">
              ✨
            </div>
            <div
              className="absolute -top-4 -left-12 text-primary text-xl animate-pulse"
              style={{ animationDelay: "300ms" }}
            >
              ✨
            </div>
            {/* Glowing shield */}
            <div className="relative w-48 h-48 flex items-center justify-center">
              <div
                className="absolute inset-0 bg-primary/20 blur-2xl animate-pulse"
                style={{ borderRadius: "50%" }}
              />
              <div className="relative w-full h-full flex items-center justify-center">
                {/* Shield shape using SVG */}
                <svg
                  width="192"
                  height="192"
                  viewBox="0 0 192 192"
                  className="absolute inset-0"
                >
                  <defs>
                    <radialGradient id="shieldGradient" cx="50%" cy="30%">
                      <stop offset="0%" stopColor="#2761FC" stopOpacity="0.6" />
                      <stop
                        offset="70%"
                        stopColor="#2761FC"
                        stopOpacity="0.3"
                      />
                      <stop
                        offset="100%"
                        stopColor="#2761FC"
                        stopOpacity="0.1"
                      />
                    </radialGradient>
                  </defs>
                  {/* Shield path */}
                  <path
                    d="M96 20 L40 40 L40 100 C40 130, 60 150, 96 172 C132 150, 152 130, 152 100 L152 40 Z"
                    fill="url(#shieldGradient)"
                    stroke="#2761FC"
                    strokeWidth="2"
                    strokeOpacity="0.5"
                    className="backdrop-blur-sm"
                  />
                </svg>
                {/* Lightning bolt inside shield */}
                <span className="text-6xl text-primary relative z-10">⚡</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="image">
            <img src="/App.png" alt="Onboarding" />
          </div>
        )}
        <div className="w-[420px]">
          {step === 1
            ? renderStep1()
            : step === 2
            ? renderStep2()
            : step === 3
            ? renderStep3()
            : renderStep4()}
        </div>
      </div>

      {/* Progress Indicator - Absolute bottom left */}
      <div className="absolute bottom-8 left-8 flex items-center gap-2">
        {[1, 2, 3, 4].map((stepNum) => (
          <div
            key={stepNum}
            className={`h-1 w-8 rounded ${
              stepNum === step ? "bg-primary" : "bg-white/30"
            }`}
          />
        ))}
      </div>

      {/* Action Buttons - Absolute bottom right */}
      <div className="absolute bottom-8 right-8 flex items-center gap-3">
        {step === 3 ? null : step === 4 ? (
          <Button
            onClick={onAllow}
            className="!bg-[#10B981] hover:!bg-[#059669] text-white"
          >
            ALLOW
          </Button>
        ) : (
          <Button onClick={onNext} className="!bg-white text-[#62626A]">
            NEXT
          </Button>
        )}
      </div>
    </div>
  );
};

export default OnboardingScreen;
