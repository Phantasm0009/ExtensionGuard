import * as fs from "node:fs/promises";
import * as path from "node:path";
import semver from "semver";
import { ExtensionInfo, IntelData, ThreatIntelMatch } from "../types";

let cachedIntel: IntelData | null = null;

export async function loadIntel(basePath: string): Promise<IntelData> {
  if (cachedIntel) {
    return cachedIntel;
  }

  const intelPath = path.join(basePath, "data", "intel.json");
  const raw = await fs.readFile(intelPath, "utf8");
  cachedIntel = JSON.parse(raw) as IntelData;
  return cachedIntel;
}

export function matchThreatIntel(ext: ExtensionInfo, intel: IntelData): ThreatIntelMatch[] {
  const matches: ThreatIntelMatch[] = [];

  for (const item of intel.maliciousExtensions) {
    if (item.id.toLowerCase() === ext.id.toLowerCase()) {
      matches.push({
        type: "maliciousExtension",
        severity: "critical",
        reason: item.reason,
        referenceUrl: item.referenceUrl
      });
    }
  }

  for (const vuln of intel.vulnerableExtensions) {
    if (vuln.id.toLowerCase() !== ext.id.toLowerCase()) {
      continue;
    }

    const safeVersion = semver.coerce(ext.version);
    if (safeVersion && semver.satisfies(safeVersion, vuln.versionRange)) {
      matches.push({
        type: "vulnerableExtension",
        severity: vuln.severity,
        reason: vuln.reason,
        cve: vuln.cve,
        referenceUrl: vuln.referenceUrl
      });
    }
  }

  return matches;
}
