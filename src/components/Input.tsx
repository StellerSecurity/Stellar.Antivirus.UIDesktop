// src/components/Input.tsx

import React from "react";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  containerClassName?: string;
}

const Input: React.FC<InputProps> = ({
  label,
  className = "",
  containerClassName = "",
  ...props
}) => {
  return (
    <div className={containerClassName}>
      {label && (
        <label className="block text-text-primary font-poppins text-xs font-normal uppercase mb-3">
          {label}
        </label>
      )}
      <input
        className={`w-full bg-input-bg text-text-primary font-poppins text-xs h-[41px] px-3 rounded-full placeholder:text-text-primary placeholder:font-poppins placeholder:text-xs focus:outline-none ${className}`}
        {...props}
      />
    </div>
  );
};

export default Input;
