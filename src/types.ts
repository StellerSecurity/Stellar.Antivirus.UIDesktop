export type ProtectionStatus = "protected" | "not_protected" | "scanning";

export type ScanType = "realtime" | "full_scan";

export type ScanResult = "clean" | "threats_found";

export interface ScanLogEntry {
    id: number;
    timestamp: string;
    scan_type: ScanType;
    result: ScanResult;
    details: string;
}

export type ThreatSource = "full_scan" | "realtime";
export type ThreatStatus = "active" | "quarantined" | "deleted";

export interface Threat {
    id: number;
    fileName: string;
    filePath: string;
    detection: string;
    recommendedAction: "delete" | "quarantine" | "ignore" | string;
    detectedAt?: string;
    source?: ThreatSource;
    status?: ThreatStatus;
}
