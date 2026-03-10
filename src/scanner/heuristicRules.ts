import { FindingType, IntelData } from "../types";

export interface RawRule {
  id: string;
  type: FindingType;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  regex: RegExp;
}

export const TRUSTED_PUBLISHERS = ["ms-vscode", "ms-python", "github", "redhat", "esbenp", "dbaeumer"];

export const RAW_RULES: RawRule[] = [
  {
    id: "H1",
    type: "network",
    severity: "medium",
    description: "Network client/API usage detected.",
    regex: /\b(fetch\(|axios\.|https?\.request\(|node-fetch|got\(|ws\(|net\.|dns\.)/g
  },
  {
    id: "H2",
    type: "network",
    severity: "high",
    description: "Hardcoded non-local IP address detected.",
    regex: /\b(?!(127\.0\.0\.1|0\.0\.0\.0))(?:\d{1,3}\.){3}\d{1,3}\b/g
  },
  {
    id: "H3",
    type: "network",
    severity: "medium",
    description: "Cleartext HTTP URL detected.",
    regex: /http:\/\/(?!localhost|127\.0\.0\.1)/g
  },
  {
    id: "H5",
    type: "network",
    severity: "critical",
    description: "Discord webhook URL detected; common data exfiltration vector.",
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g
  },
  {
    id: "H6",
    type: "process",
    severity: "high",
    description: "Process execution API usage detected.",
    regex: /\b(child_process|exec\(|spawn\(|execFile\(|execSync\()/g
  },
  {
    id: "H8",
    type: "filesystem",
    severity: "high",
    description: "Sensitive credential path pattern detected.",
    regex: /(\.ssh|\.aws\/credentials|id_rsa|\.env|credentials)/g
  },
  {
    id: "H9",
    type: "obfuscation",
    severity: "high",
    description: "Dynamic code execution pattern detected.",
    regex: /\b(eval\(|new Function\(|require\([^\)]*\+[^\)]*\))/g
  },
  {
    id: "H10",
    type: "filesystem",
    severity: "medium",
    description: "Sensitive OS path access pattern detected.",
    regex: /(process\.env\.HOME|os\.homedir\(\)|AppData|\.vscode|\/etc\/|\\Users\\)/g
  },
  {
    id: "H11",
    type: "globalState",
    severity: "medium",
    description: "Global state access with secret-like key detected.",
    regex: /globalState\.(get|update)\([^\)]*(token|secret|key|credential)/gi
  },
  {
    id: "H12",
    type: "config",
    severity: "high",
    description: "settings.json or executorMap modification pattern detected.",
    regex: /(settings\.json|executorMap|workspace\.getConfiguration\()/g
  },
  {
    id: "H13",
    type: "localhost",
    severity: "medium",
    description: "Local server creation detected.",
    regex: /(http\.createServer\(|createServer\(|express\()/g
  },
  {
    id: "H14",
    type: "network",
    severity: "critical",
    description: "Sensitive path and network pattern likely indicates exfiltration behavior.",
    regex: /(\.ssh|\.aws\/credentials|id_rsa|credentials).*(fetch\(|axios\.|https?\.request\()/g
  }
];

export function maliciousHostRegex(intel: IntelData): RegExp | null {
  if (!intel.maliciousHosts.length) {
    return null;
  }

  const escaped = intel.maliciousHosts
    .map((h) => h.hostOrIp.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("|");

  return new RegExp(`(${escaped})`, "gi");
}
