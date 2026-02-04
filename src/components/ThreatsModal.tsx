import React from "react";
import type { Threat } from "../types";
import Img from '../../public/reala-time-protection.svg'
import Img1 from '../../public/Icon-x-circle.svg'


interface ThreatsModalProps {
  open: boolean;
  onClose: () => void;
  threats: Threat[];
  onRemove: (ids: number[]) => void;
}

const ThreatsModal: React.FC<ThreatsModalProps> = ({
  open,
  onClose,
  threats,
  onRemove,
}) => {
  if (!open) return null;

  const hasThreats = threats.length > 0;

  const handleRemoveAll = () => {
    if (!hasThreats) return;
    const ids = threats.map((t) => t.id);
    onRemove(ids);
  };

  const handleRemoveSingle = (id: number) => {
    onRemove([id]);
  };

  return (
    <div className="fixed inset-0 z-40 bg-[#0B0C1980] flex items-center justify-center backdrop-blur-[10px]">
      <div className="bg-[#0B0C1980] w-[960px] max-h-[600px] flex flex-col overflow-hidden shadow-2xl rounded-xl h-[600px]">

        {/* Header */}
        <div className="px-4 pt-4 pb-4 flex flex-col gap-1">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <img src={Img} alt="" className="w-4 h-4 " />
              <span className="text-[14px] font-semibold text-white uppercase tracking-wider opacity-90">
                REAL-TIME PROTECTION
              </span>
            </div>

            <button
              onClick={onClose}
              className="text-white/60 hover:text-white transition-colors"
            >
                <img src={Img1} alt="" className="w-4 h-4 " />
            </button>
          </div>

          <h2 className="text-[30px] font-semibold text-white leading-tight font-poppins ">
            Detected threats
          </h2>
          <p className="text-[12px] text-[#CFCFFF] mt-2">
            Files that have been flagged by Stellar Antivirus.
          </p>
        </div>

        {/* Body */}
        <div className="px-4 py-0 flex-1 overflow-hidden">
          {!hasThreats ? (
            <div className="flex items-center justify-center h-full text-white/50 text-sm">
              No active threats detected.
            </div>
          ) : (
            <div className="space-y-4 max-h-[380px] overflow-auto pr-2 custom-scrollbar">
              {threats.map((t) => {
                const dateLabel = t.detectedAt
                  ? new Date(t.detectedAt).toLocaleString('en-GB', {
                    year: 'numeric', month: '2-digit', day: '2-digit',
                    hour: '2-digit', minute: '2-digit'
                  }).replace(',', ' —')
                  : "Just now";

                
                const sourceLabel =
                  t.source === "full_scan"
                    ? "Full scan"
                    : "Real-time protection";

                return (
                  <div
                    key={t.id}
                    className="bg-white rounded-2xl p-5 flex items-start justify-between relative group shadow-sm"
                  >

                    <div className="flex flex-col gap-2">
                      {/* Name */}
                      <div className="flex items-center gap-2 text-[14px] font-semibold text-[#F96262]">
                        <span className="uppercase">[EXE]</span>
                        <span>{t.detection || t.fileName}</span>
                      </div>

                      {/* Path */}
                      <div className="text-[13px] font-medium text-[#FF5A5A]/90 break-all max-w-[500px]">
                        {t.filePath}
                      </div>
                    </div>

                    <div className="flex flex-col items-end justify-between  gap-6">
                      <div className="flex items-center gap-3">
                        <span className="text-[11px] font-bold text-[#6B7280] uppercase tracking-wide">
                          ACTIVE
                        </span>
                        <div>
                        <button
                          onClick={() => handleRemoveSingle(t.id)}
                          className="bg-[#F96262] h-[22px] hover:bg-[#E04545] text-white text-[12px] font-semibold px-3 py-0 rounded-full uppercase"
                        >
                          REMOVE
                        </button>
                        </div>
                      </div>
                      <div className="text-[11px] font-medium text-[#6B7280]">
                        {dateLabel} • {sourceLabel}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer actions */}
        <div className="px-4 pb-8 pt-4 flex items-center justify-between mt-auto">
          <p className="text-[12px] text-[#CFCFFF] max-w-[320px] leading-relaxed">
            Threats will be moved to quarantine when removed.<br />
            (Quarantined files are safely isolated).
          </p>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="h-[36px] px-[16px] py-[8px] rounded-full bg-[#F6F6FD] text-[#111827] text-[14px] font-semibold hover:bg-gray-100 transition-colors uppercase tracking-wide"
            >
              CLOSE
            </button>
            <button
              onClick={handleRemoveAll}
              disabled={!hasThreats}
              className={`h-[36px] px-6 rounded-full text-[14px] font-semibold text-white transition-colors uppercase tracking-wide ${hasThreats
                ? "bg-[#F96262] hover:bg-[#E04545] shadow-lg shadow-red-500/20"
                : "bg-gray-600 cursor-not-allowed opacity-50"
                }`}
            >
              REMOVE ALL THREATS
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatsModal;
