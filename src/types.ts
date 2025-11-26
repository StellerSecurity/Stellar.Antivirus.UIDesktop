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
a