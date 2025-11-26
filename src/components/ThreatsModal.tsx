import React from "react";
import type { Threat } from "../types";

interface ThreatsModalProps {
    open: boolean;
    onClose: () => void;
    threats: Threat[];
}

const ThreatsModal: React.FC<ThreatsModalProps> = ({ open, onClose, threats }) => {
    if (!open) return null;

    const hasThreats = threats.length > 0;

    return (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40">
            <div className="bg-white rounded-3xl shadow-2xl w-full max-w-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                    <div>
                        <h2 className="text-lg font-semibold text-[#111827]">
                            Detected threats
                        </h2>
                        <p className="text-xs text-[#6B7280]">
                            Files that have been flagged by Stellar Antivirus.
                        </p>
                    </div>
                    <button
                        onClick={onClose}
                        className="text-xs text-[#6B7280] hover:text-[#111827]"
                    >
                        Close
                    </button>
                </div>

                {!hasThreats ? (
                    <p className="text-xs text-[#6B7280]">
                        No threats have been detected yet. Run a full scan or keep real-time
                        protection enabled.
                    </p>
                ) : (
                    <div className="space-y-2 max-h-[380px] overflow-auto pr-1">
                        {threats.map((t) => {
                            const dateLabel = new Date(t.detectedAt).toLocaleString();
                            const sourceLabel =
                                t.source === "full_scan" ? "Full scan" : "Real-time protection";

                            return (
                                <div
                                    key={t.id}
                                    className="flex items-start justify-between rounded-2xl border border-[#E5E7EB] px-4 py-3"
                                >
                                    <div className="flex flex-col gap-1">
                                        <div className="flex items-center gap-2">
                                            <span className="inline-flex h-2 w-2 rounded-full bg-[#DC2626]" />
                                            <span className="text-sm font-semibold text-[#111827]">
                        {t.name}
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
                      {t.status === "active"
                          ? "Active"
                          : t.status === "quarantined"
                              ? "Quarantined"
                              : "Deleted"}
                    </span>
                                        {/* Knapper kan senere kobles til quarantine/delete-commands */}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>
        </div>
    );
};

export default ThreatsModal;
