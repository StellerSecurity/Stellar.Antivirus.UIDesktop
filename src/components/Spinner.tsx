import React from "react";

type Props = {
  progress: number; // 0..100
  size?: number;
  strokeWidth?: number;
  bgStrokeColor?: string;
  progressStrokeColor?: string;
  showPercentage?: boolean;
  className?: string;

  // Motion
  animate?: boolean;        // rotating sweep arc
  indeterminate?: boolean;  // shows "SCAN" instead of %

  // NEW: Tinder-ish glow pulse
  glowPulse?: boolean;
};

const clamp = (n: number, min: number, max: number) => Math.min(max, Math.max(min, n));

const Spinner: React.FC<Props> = ({
                                    progress,
                                    size = 120,
                                    strokeWidth = 14,
                                    bgStrokeColor = "rgba(255,255,255,0.2)",
                                    progressStrokeColor = "#60D38E",
                                    showPercentage = true,
                                    className = "",
                                    animate = false,
                                    indeterminate = false,
                                    glowPulse = false,
                                  }) => {
  const p = clamp(Number.isFinite(progress) ? progress : 0, 0, 100);

  const half = size / 2;
  const r = half - strokeWidth / 2;
  const c = 2 * Math.PI * r;

  const dashOffset = c - (p / 100) * c;

  // Sweep arc: ~22% of the circle, rest gap
  const sweepLen = c * 0.22;
  const sweepGap = c - sweepLen;

  const label = indeterminate ? "SCAN" : `${Math.round(p)}%`;

  // Make pulse scale relative to spinner size
  const pulseSize = Math.round(size * 1.35);

  return (
      <div
          className={`relative inline-flex items-center justify-center ${className}`}
          style={{ width: size, height: size }}
      >
        <style>{`
        @keyframes stellarSpin {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }

        /* Tinder-ish outer glow pulse */
        @keyframes stellarGlowPulse {
          0%   { transform: translate(-50%, -50%) scale(0.82); opacity: 0.55; filter: blur(10px); }
          60%  { transform: translate(-50%, -50%) scale(1.12); opacity: 0.20; filter: blur(16px); }
          100% { transform: translate(-50%, -50%) scale(1.28); opacity: 0;    filter: blur(22px); }
        }

        /* A second pulse, offset, for “continuous” energy */
        @keyframes stellarGlowPulse2 {
          0%   { transform: translate(-50%, -50%) scale(0.78); opacity: 0.40; filter: blur(10px); }
          70%  { transform: translate(-50%, -50%) scale(1.18); opacity: 0.12; filter: blur(18px); }
          100% { transform: translate(-50%, -50%) scale(1.34); opacity: 0;    filter: blur(24px); }
        }

        @keyframes stellarPulseInner {
          0%, 100% { opacity: 0.55; }
          50%      { opacity: 1; }
        }

        .stellar-sweep {
          transform-origin: 50% 50%;
          animation: stellarSpin 1.1s linear infinite;
        }

        .stellar-glow-ring {
          filter: drop-shadow(0 0 10px rgba(96, 211, 142, 0.35));
        }

        .stellar-inner-pulse {
          animation: stellarPulseInner 1.05s ease-in-out infinite;
        }

        .stellar-glow-pulse {
          position: absolute;
          left: 50%;
          top: 50%;
          width: ${pulseSize}px;
          height: ${pulseSize}px;
          border-radius: 9999px;

          /* Radial glow “blob” */
          background: radial-gradient(
            circle,
            rgba(96, 211, 142, 0.45) 0%,
            rgba(96, 211, 142, 0.18) 38%,
            rgba(96, 211, 142, 0.08) 58%,
            rgba(96, 211, 142, 0.00) 72%
          );

          mix-blend-mode: screen;
          pointer-events: none;
          animation: stellarGlowPulse 1.55s ease-out infinite;
        }

        .stellar-glow-pulse.two {
          animation: stellarGlowPulse2 1.55s ease-out infinite;
          animation-delay: 0.75s;
          opacity: 0.35;
        }

        /* Subtle constant halo so it doesn't “blink” between pulses */
        .stellar-halo {
          position: absolute;
          inset: -10px;
          border-radius: 9999px;
          background: radial-gradient(
            circle,
            rgba(96, 211, 142, 0.18) 0%,
            rgba(96, 211, 142, 0.08) 42%,
            rgba(96, 211, 142, 0.00) 70%
          );
          filter: blur(14px);
          opacity: 0.55;
          pointer-events: none;
        }
      `}</style>

        {/* Tinder-style glow pulses */}
        {glowPulse && animate && (
            <>
              <div className="stellar-halo" />
              <div className="stellar-glow-pulse" />
              <div className="stellar-glow-pulse two" />
            </>
        )}

        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="block relative z-10">
          <defs>
            <linearGradient id="stellarProgress" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor={progressStrokeColor} stopOpacity="0.75" />
              <stop offset="100%" stopColor={progressStrokeColor} stopOpacity="1" />
            </linearGradient>
          </defs>

          {/* Background ring */}
          <circle
              cx={half}
              cy={half}
              r={r}
              fill="none"
              stroke={bgStrokeColor}
              strokeWidth={strokeWidth}
          />

          {/* Determinate progress ring */}
          {!indeterminate && (
              <circle
                  cx={half}
                  cy={half}
                  r={r}
                  fill="none"
                  stroke="url(#stellarProgress)"
                  strokeWidth={strokeWidth}
                  strokeLinecap="round"
                  strokeDasharray={c}
                  strokeDashoffset={dashOffset}
                  style={{
                    transform: "rotate(-90deg)",
                    transformOrigin: "50% 50%",
                    transition: "stroke-dashoffset 250ms ease",
                  }}
                  className="stellar-glow-ring"
              />
          )}

          {/* Rotating sweep arc overlay */}
          {animate && (
              <g className="stellar-sweep">
                <circle
                    cx={half}
                    cy={half}
                    r={r}
                    fill="none"
                    stroke="rgba(255,255,255,0.90)"
                    strokeWidth={Math.max(3, Math.floor(strokeWidth * 0.28))}
                    strokeLinecap="round"
                    strokeDasharray={`${sweepLen} ${sweepGap}`}
                    strokeDashoffset={c * 0.08}
                    className="stellar-inner-pulse"
                    style={{ opacity: 0.9 }}
                />
              </g>
          )}
        </svg>

        {/* Center label */}
        <div className="absolute inset-0 flex items-center justify-center select-none z-20">
          <div className="flex flex-col items-center">
            <div className="text-[18px] font-semibold leading-none">
              {showPercentage ? label : ""}
            </div>
            <div className="text-[10px] opacity-80 mt-1">
              {animate ? "Scanning…" : "Ready"}
            </div>
          </div>
        </div>
      </div>
  );
};

export default Spinner;
