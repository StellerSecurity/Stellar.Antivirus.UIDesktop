import React, { useEffect, useState } from "react";

export interface Threat {
    id: number;
    fileName: string;
    filePath: string;
    detection: string;
    recommendedAction: "delete" | "quarantine";
}

interface Props {
    open: boolean;
    threats: Threat[];
    onClose: () => void;
    onRemove: (ids: number[]) => void;
}

const ThreatsModal: React.FC<Props> = ({
                                           open,
                                           threats,
                                           onClose,
                                           onRemove,
                                       }) => {
    const [selectedIds, setSelectedIds] = useState<number[]>([]);

    useEffect(() => {
        if (open) {
            // default: alle valgt
            setSelectedIds(threats.map((t) => t.id));
        }
    }, [open, threats]);

    if (!open) return null;

    const toggle = (id: number) => {
        setSelectedIds((prev) =>
            prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
        );
    };

    const allSelected = selectedIds.length === threats.length && threats.length > 0;

    const toggleAll = () => {
        if (allSelected) {
            setSelectedIds([]);
        } else {
            setSelectedIds(threats.map((t) => t.id));
        }
    };

    const handleRemove = () => {
        if (selectedIds.length === 0) {
            onClose();
            return;
        }
        onRemove(selectedIds);
    };

    return (
        <div className="absolute inset-0 bg-black/40 flex items-center justify-center z-50">
            <div className="w-[520px] max-h-[80vh] bg-white rounded-3xl shadow-[0_24px_80px_rgba(15,23,42,0.7)] px-6 py-6 flex flex-col">
                <h3 className="text-sm font-semibold text-[#111827] mb-1">
                    We found {threats.length} {threats.length === 1 ? "threat" : "threats"} on this device
                </h3>
                <p className="text-xs text-[#6B7280] mb-4">
                    These files look malicious or unsafe. Select what you want Stellar Antivirus to do.
                </p>

                <div className="flex items-center justify-between mb-2 text-[11px] text-[#6B7280]">
                    <button
                        onClick={toggleAll}
                        className="flex items-center gap-1 text-[11px] text-[#2563EB]"
                    >
            <span
                className={`w-3.5 h-3.5 rounded-[6px] border ${
                    allSelected
                        ? "bg-[#2563EB] border-[#2563EB]"
                        : "bg-white border-[#D1D5DB]"
                } flex items-center justify-center`}
            >
              {allSelected && (
                  <span className="w-2 h-2 bg-white rounded-[3px]" />
              )}
            </span>
                        <span>{allSelected ? "Deselect all" : "Select all"}</span>
                    </button>
                    <span>
            {selectedIds.length}/{threats.length} selected
          </span>
                </div>

                <div className="border border-[#E5E7EB] rounded-2xl overflow-hidden flex-1 min-h-[140px] max-h-[260px]">
                    {threats.map((t) => {
                        const checked = selectedIds.includes(t.id);
                        return (
                            <div
                                key={t.id}
                                className="flex items-start gap-3 px-4 py-3 text-xs border-b border-[#F3F4F6] last:border-b-0 hover:bg-[#F9FAFB]"
                            >
                                <button
                                    onClick={() => toggle(t.id)}
                                    className="mt-0.5 w-4 h-4 rounded-md border border-[#D1D5DB] flex items-center justify-center"
                                >
                                    {checked && (
                                        <span className="w-2.5 h-2.5 bg-[#2563EB] rounded-[4px]" />
                                    )}
                                </button>
                                <div className="flex-1">
                                    <div className="flex items-center justify-between mb-1">
                                        <div className="flex items-center gap-2">
                      <span className="font-medium text-[#111827]">
                        {t.fileName}
                      </span>
                                            <span className="px-2 py-0.5 rounded-full bg-[#FEF2F2] text-[10px] text-[#B91C1C]">
                        {t.detection}
                      </span>
                                        </div>
                                    </div>
                                    <div className="text-[11px] text-[#6B7280] mb-1">
                                        {t.filePath}
                                    </div>
                                    <div className="text-[11px] text-[#9CA3AF]">
                                        Recommended action:{" "}
                                        <span className="font-medium text-[#111827] capitalize">
                      {t.recommendedAction}
                    </span>
                                    </div>
                                </div>
                            </div>
                        );
                    })}

                    {threats.length === 0 && (
                        <div className="h-full flex items-center justify-center text-xs text-[#9CA3AF]">
                            No threats to show.
                        </div>
                    )}
                </div>

                <div className="flex justify-end gap-2 mt-4">
                    <button
                        onClick={onClose}
                        className="px-4 h-9 rounded-full text-xs font-medium border border-[#E5E7EB] text-[#111827] hover:bg-[#F3F4F6]"
                    >
                        Ignore for now
                    </button>
                    <button
                        onClick={handleRemove}
                        className="px-4 h-9 rounded-full text-xs font-semibold bg-[#DC2626] text-white shadow-[0_10px_30px_rgba(220,38,38,0.6)] disabled:opacity-60 disabled:cursor-not-allowed"
                        disabled={selectedIds.length === 0}
                    >
                        Remove selected threats
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ThreatsModal;
