// src/components/Button.tsx

import React from "react";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary";
  children: React.ReactNode;
}

const Button: React.FC<ButtonProps> = ({
  variant = "primary",
  children,
  className = "",
  ...props
}) => {
  const baseClasses =
    "inline-block w-auto h-[36px] font-poppins text-sm font-semibold px-4 py-2 rounded-full transition focus:outline-none disabled:opacity-70 disabled:cursor-not-allowed";

  const variantClasses = {
    primary: "bg-primary text-white hover:opacity-90",
    secondary:
      "bg-white text-[#111827] border border-[#E5E7EB] hover:bg-[#F3F4F6]",
  };

  return (
    <button
      className={`${baseClasses} ${variantClasses[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
};

export default Button;
