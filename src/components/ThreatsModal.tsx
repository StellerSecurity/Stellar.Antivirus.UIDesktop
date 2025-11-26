import React, { useState } from "react";

export type Threat = {
    id: number;
    fileName: string;
    filePath: string;
    detection: string;
    recommendedAction: "delete" | "quarantine" | "ignore" | string;
};

interface ThreatsModalProps {
    open: boolean;
    threats: Threat[];
    onClose: () => void;
    onRemove: (ids: number[]) => void | Promise<void>;
}

const ThreatsModal: React.FC<ThreatsModalProps> = ({
                                                       open,
                                                       threats,
                                                       onClose,
                                                       onRemove,
                                                   }) => {
    const [selectedIds, setSelectedIds] = useState<number[]>(
        threats.map((t) => t.id)
    );

    if (!open) return null;

    const toggleId = (id: number) => {
        setSelectedIds((prev) =>
            prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
        );
    };

    const handleRemove = () => {
        if (!selectedIds.length) return;
        onRemove(selectedIds);
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
            <div className="w-[520px] max-h-[80vh] bg-white rounded-3xl shadow-[0_24px_80px_rgba(15,23,42,0.65)] flex flex-col">
                <div className="px-6 pt-5 pb-3 border-b border-[#E5E7EB]">
                    <h3 className="text-sm font-semibold text-[#111827]">
                        Threats found
                    </h3>
                    <p className="text-xs text-[#6B7280]">
                        Stellar Antivirus detected potentially harmful files. Choose what
                        to remove.
                    </p>
                </div>

                <div className="flex-1 overflow-y-auto px-6 py-3 space-y-2">
                    {threats.map((t) => {
                        const checked = selectedIds.includes(t.id);
                        return (
                            <div
                                key={t.id}
                                className="flex items-start gap-3 rounded-2xl border border-[#FCA5A5] bg-[#FEF2F2] px-3 py-2"
                            >
                                <input
                                    type="checkbox"
                                    className="mt-1 w-3 h-3 rounded border-[#FCA5A5]"
                                    checked={checked}
                                    onChange={() => toggleId(t.id)}
                                />
                                <div className="flex-1">
                                    <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-[#B91C1C]">
                      {t.fileName}
                    </span>
                                        <span className="text-[10px] text-[#B91C1C] uppercase tracking-wide">
                      {t.detection}
                    </span>
                                    </div>
                                    <p className="text-[11px] text-[#6B7280] break-all">
                                        {t.filePath}
                                    </p>
                                    <p className="text-[10px] text-[#9CA3AF] mt-1">
                                        Recommended action: {t.recommendedAction}
                                    </p>
                                </div>
                            </div>
                        );
                    })}

                    {!threats.length && (
                        <p className="text-xs text-[#9CA3AF]">
                            No threats are currently detected.
                        </p>
                    )}
                </div>

                <div className="px-6 py-4 border-t border-[#E5E7EB] flex justify-between items-center">
                    <button
                        onClick={onClose}
                        className="px-4 h-9 rounded-full text-xs font-medium border border-[#E5E7EB] text-[#111827] hover:bg-[#F3F4F6]"
                    >
                        Close
                    </button>
                    <button
                        onClick={handleRemove}
                        disabled={!selectedIds.length}
                        className={`px-4 h-9 rounded-full text-xs font-semibold text-white shadow-[0_10px_30px_rgba(220,38,38,0.6)] ${
                            selectedIds.length
                                ? "bg-[#DC2626] hover:bg-[#B91C1C]"
                                : "bg-[#FCA5A5] cursor-not-allowed"
                        }`}
                    >
                        Remove selected
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ThreatsModal;
