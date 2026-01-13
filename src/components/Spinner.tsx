import React from "react";

interface SpinnerProps {
  progress?: number; // 0-100
  size?: number; // diameter in pixels
  strokeWidth?: number;
  className?: string;
  bgStrokeColor?: string;
  progressStrokeColor?: string;
  showPercentage?: boolean;
}

const Spinner: React.FC<SpinnerProps> = ({
  progress = 0,
  size = 40,
  strokeWidth = 12,
  className = "",
  bgStrokeColor = "#E5E7EB",
  progressStrokeColor = "#6B7280",
  showPercentage = false,
}) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (progress / 100) * circumference;

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg
        width={size}
        height={size}
        className={`transform -rotate-90 ${className}`}
      >
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={bgStrokeColor}
          strokeWidth={strokeWidth}
        />
        {/* Progress circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={progressStrokeColor}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-300"
        />
      </svg>
    </div>
  );
};

export default Spinner;
