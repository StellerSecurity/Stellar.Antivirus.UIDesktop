// src/components/Input.tsx

import React from "react";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  containerClassName?: string;
  labelClassName?: string;
}

const Input: React.FC<InputProps> = ({
  label,
  className = "",
  containerClassName = "",
  labelClassName = "",
  ...props
}) => {
  return (
    <div className={containerClassName}>
      {label && (
        <label
          className={`block text-text-primary font-poppins text-xs font-normal uppercase mb-3 ${labelClassName}`}
        >
          {label}
        </label>
      )}
      <input
        className={`w-full bg-[#1D1E34] text-text-primary font-poppins text-xs h-[41px] px-3 rounded-full placeholder:text-text-primary placeholder:font-poppins placeholder:text-xs focus:outline-none ${className}`}
        {...props}
      />
    </div>
  );
};

export default Input;
