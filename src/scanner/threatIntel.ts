import * as fs from "node:fs/promises";
import * as path from "node:path";
import semver from "semver";
import { ExtensionInfo, IntelData, ThreatIntelMatch } from "../types";

const INTEL_CACHE_KEY = "extensionShield.cachedIntel";
const INTEL_UPDATED_AT_KEY = "extensionShield.cachedIntelUpdatedAt";

export interface IntelLoadResult {
  intel: IntelData;
  source: "bundled" | "remote" | "cached-remote";
  updatedAt: string;
}

export interface IntelContext {
  extensionPath: string;
  globalState: {
    update(key: string, value: unknown): PromiseLike<void>;
    get<T>(key: string): T | undefined;
  };
}

async function loadBundledIntel(basePath: string): Promise<IntelData> {
  const intelPath = path.join(basePath, "data", "intel.json");
  const raw = await fs.readFile(intelPath, "utf8");
  return JSON.parse(raw) as IntelData;
}

async function fetchRemoteIntel(url: string): Promise<IntelData> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`Remote intel fetch failed: ${response.status}`);
    }
    return (await response.json()) as IntelData;
  } finally {
    clearTimeout(timeout);
  }
}

export async function loadIntel(
  context: IntelContext,
  configProvider: { get<T>(key: string, defaultValue?: T): T }
): Promise<IntelLoadResult> {
  const enableRemote = configProvider.get<boolean>("enableNetworkIntelUpdates", false);
  const remoteUrl = configProvider.get<string>(
    "intelUpdateUrl",
    "https://raw.githubusercontent.com/extension-shield/intel/main/intel.json"
  );

  if (enableRemote) {
    try {
      const remote = await fetchRemoteIntel(remoteUrl);
      const now = new Date().toISOString();
      await context.globalState.update(INTEL_CACHE_KEY, remote);
      await context.globalState.update(INTEL_UPDATED_AT_KEY, now);
      return { intel: remote, source: "remote", updatedAt: now };
    } catch {
      const cached = context.globalState.get<IntelData>(INTEL_CACHE_KEY);
      const cachedAt = context.globalState.get<string>(INTEL_UPDATED_AT_KEY);
      if (cached && cachedAt) {
        return { intel: cached, source: "cached-remote", updatedAt: cachedAt };
      }
    }
  }

  const bundled = await loadBundledIntel(context.extensionPath);
  return { intel: bundled, source: "bundled", updatedAt: new Date().toISOString() };
}

export async function refreshIntelNow(
  context: IntelContext,
  configProvider: { get<T>(key: string, defaultValue?: T): T }
): Promise<IntelLoadResult> {
  const remoteUrl = configProvider.get<string>(
    "intelUpdateUrl",
    "https://raw.githubusercontent.com/extension-shield/intel/main/intel.json"
  );

  const remote = await fetchRemoteIntel(remoteUrl);
  const now = new Date().toISOString();
  await context.globalState.update(INTEL_CACHE_KEY, remote);
  await context.globalState.update(INTEL_UPDATED_AT_KEY, now);
  return { intel: remote, source: "remote", updatedAt: now };
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
