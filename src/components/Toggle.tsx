import React from "react";

interface ToggleProps {
  enabled: boolean;
  onChange: (enabled: boolean) => void;
  disabled?: boolean;
  showLabel?: boolean;
  variant?: "blue" | "gray";
  size?: "default" | "small" | "large";
}

const Toggle: React.FC<ToggleProps> = ({
  enabled,
  onChange,
  disabled = false,
  showLabel = false,
  variant = "blue",
  size = "default",
}) => {
  const sizeClasses = {
    small: "w-10 h-6",
    default: "w-12 h-7",
    large: "w-14 h-8",
  };

  const handleClasses = {
    small: "w-4 h-4",
    default: "w-5 h-5",
    large: "w-6 h-6",
  };

  const translateClasses = {
    small: enabled ? "translate-x-4" : "translate-x-0",
    default: enabled ? "translate-x-5" : "translate-x-0",
    large: enabled ? "translate-x-6" : "translate-x-0",
  };

  const bgColor = disabled
    ? "bg-gray-300"
    : enabled
    ? variant === "blue"
      ? "bg-[#2563EB]"
      : "bg-gray-600"
    : variant === "blue"
    ? "bg-gray-300"
    : "bg-gray-600";

  const textColor = disabled
    ? "text-gray-400"
    : enabled
    ? "text-white"
    : "text-white";

  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => !disabled && onChange(!enabled)}
      className={`relative ${
        sizeClasses[size]
      } rounded-full transition-all flex items-center px-1 ${
        disabled ? "opacity-60 cursor-not-allowed" : "cursor-pointer"
      } ${bgColor}`}
    >
      {showLabel && (
        <span
          className={`absolute ${
            enabled ? "left-2" : "right-2"
          } text-xs font-medium ${textColor} pointer-events-none`}
        >
          {enabled ? "On" : "Off"}
        </span>
      )}
      <span
        className={`${
          handleClasses[size]
        } rounded-full bg-white transform transition-transform ${
          translateClasses[size]
        } ${showLabel ? "z-10" : ""}`}
      />
    </button>
  );
};

export default Toggle;
