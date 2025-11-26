import React from "react";
import type { Threat } from "../types";

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
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40">
            <div className="bg-white rounded-3xl shadow-[0_24px_60px_rgba(15,23,42,0.45)] w-[560px] max-h-[480px] flex flex-col overflow-hidden">
                {/* Header */}
                <div className="px-6 pt-5 pb-3 border-b border-[#E5E7EB] flex items-center justify-between">
                    <div>
                        <h2 className="text-sm font-semibold text-[#111827]">
                            Detected threats
                        </h2>
                        <p className="text-xs text-[#6B7280]">
                            Files that have been flagged by Stellar Antivirus.
                        </p>
                    </div>
                    <button
                        onClick={onClose}
                        className="text-[11px] text-[#6B7280] hover:text-[#111827]"
                    >
                        Close
                    </button>
                </div>

                {/* Body */}
                <div className="px-6 py-4 flex-1 overflow-hidden">
                    {!hasThreats ? (
                        <p className="text-xs text-[#6B7280]">
                            No threats have been detected yet. Run a full scan or keep
                            real-time protection enabled.
                        </p>
                    ) : (
                        <div className="space-y-2 max-h-[320px] overflow-auto pr-1">
                            {threats.map((t) => {
                                const dateLabel = t.detectedAt
                                    ? new Date(t.detectedAt).toLocaleString()
                                    : "Detected just now";
                                const sourceLabel =
                                    t.source === "full_scan"
                                        ? "Full scan"
                                        : t.source === "realtime"
                                            ? "Real-time protection"
                                            : "Unknown source";

                                const status = t.status ?? "active";

                                return (
                                    <div
                                        key={t.id}
                                        className="flex items-start justify-between rounded-2xl border border-[#E5E7EB] px-4 py-3"
                                    >
                                        <div className="flex flex-col gap-1">
                                            <div className="flex items-center gap-2">
                                                <span className="inline-flex h-2 w-2 rounded-full bg-[#DC2626]" />
                                                <span className="text-sm font-semibold text-[#111827]">
                          {t.fileName ?? t.filePath}
                        </span>
                                            </div>
                                            <div className="text-[11px] text-[#6B7280] line-clamp-1 max-w-[320px]">
                                                {t.filePath}
                                            </div>
                                            <div className="flex items-center gap-3 text-[11px] text-[#9CA3AF]">
                                                <span>{dateLabel}</span>
                                                <span>•</span>
                                                <span>{sourceLabel}</span>
                                            </div>
                                        </div>

                                        <div className="flex flex-col items-end gap-2">
                      <span className="text-[11px] px-2 py-0.5 rounded-full bg-[#FEF2F2] text-[#B91C1C]">
                        {status === "active"
                            ? "Active"
                            : status === "quarantined"
                                ? "Quarantined"
                                : "Deleted"}
                      </span>

                                            {/* Ny: per-threat remove-knap */}
                                            <button
                                                onClick={() => handleRemoveSingle(t.id)}
                                                className="px-3 h-7 rounded-full text-[11px] font-medium bg-[#DC2626] text-white hover:bg-[#B91C1C]"
                                            >
                                                Remove
                                            </button>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>

                {/* Footer actions */}
                <div className="px-6 py-4 border-t border-[#E5E7EB] flex items-center justify-between">
                    <p className="text-[11px] text-[#6B7280]">
                        Removing threats will move them to quarantine (where supported).
                    </p>
                    <div className="flex items-center gap-2">
                        <button
                            onClick={onClose}
                            className="px-4 h-8 rounded-full text-[11px] font-medium border border-[#E5E7EB] text-[#111827] hover:bg-[#F3F4F6]"
                        >
                            Close
                        </button>
                        <button
                            onClick={handleRemoveAll}
                            disabled={!hasThreats}
                            className={`px-4 h-8 rounded-full text-[11px] font-semibold text-white shadow-[0_10px_30px_rgba(220,38,38,0.6)] ${
                                hasThreats
                                    ? "bg-[#DC2626] hover:bg-[#B91C1C]"
                                    : "bg-[#FCA5A5] cursor-not-allowed"
                            }`}
                        >
                            Remove all threats
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ThreatsModal;
