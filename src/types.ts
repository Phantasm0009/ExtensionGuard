export type RiskLevel = "critical" | "elevated" | "low";
export type FindingSeverity = "critical" | "high" | "medium" | "low";
export type FindingType =
  | "network"
  | "process"
  | "filesystem"
  | "obfuscation"
  | "globalState"
  | "config"
  | "localhost"
  | "typosquat";

export interface ExtensionInfo {
  id: string;
  name: string;
  version: string;
  description: string;
  extensionPath: string;
  isBuiltin: boolean;
  activationEvents: string[];
  contributes: {
    commands?: Array<{ command: string; title?: string }>;
    configuration?: unknown;
    terminal?: unknown;
    debuggers?: unknown;
    taskDefinitions?: unknown;
  };
  main?: string;
  browser?: string;
}

export interface ThreatIntelMatch {
  type: "maliciousExtension" | "vulnerableExtension";
  severity: FindingSeverity;
  reason: string;
  referenceUrl: string;
  cve?: string;
}

export interface HeuristicFinding {
  ruleId: string;
  type: FindingType;
  severity: FindingSeverity;
  description: string;
  filePath: string;
  line?: number;
}

export interface PermissionProfile {
  runsOnStartup: boolean;
  hasTerminalAccess: boolean;
  hasDebugAccess: boolean;
  hasTaskProvider: boolean;
  commandCount: number;
}

export interface ScanResult {
  extension: ExtensionInfo;
  intelMatches: ThreatIntelMatch[];
  findings: HeuristicFinding[];
  riskLevel: RiskLevel;
  riskScore: number;
  riskExplanation: string;
  permissionProfile: PermissionProfile;
  isTrustedByUser: boolean;
  suppressedFindingsCount: number;
}

export interface ScanSummary {
  scanned: number;
  critical: number;
  elevated: number;
  low: number;
}

export interface FullScanReport {
  timestamp: string;
  overallRisk: RiskLevel;
  summary: ScanSummary;
  results: ScanResult[];
  intelSource: "bundled" | "remote" | "cached-remote";
  intelUpdatedAt: string;
}

export interface IntelData {
  maliciousExtensions: Array<{ id: string; reason: string; referenceUrl: string }>;
  vulnerableExtensions: Array<{
    id: string;
    versionRange: string;
    severity: FindingSeverity;
    reason: string;
    cve?: string;
    referenceUrl: string;
  }>;
  maliciousHosts: Array<{ hostOrIp: string; reason: string; referenceUrl: string }>;
}
