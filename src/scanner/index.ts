import * as vscode from "vscode";
import { ExtensionInfo, FullScanReport, PermissionProfile, RiskLevel, ScanResult } from "../types";
import { getCachedResult, setCachedResult } from "./cache";
import { discoverExtensions } from "./discovery";
import { runHeuristics } from "./heuristics";
import { computeRisk } from "./scoring";
import { loadIntel, matchThreatIntel } from "./threatIntel";

function getWorstRisk(levels: RiskLevel[]): RiskLevel {
  if (levels.includes("critical")) {
    return "critical";
  }
  if (levels.includes("elevated")) {
    return "elevated";
  }
  return "low";
}

function buildPermissionProfile(ext: ExtensionInfo): PermissionProfile {
  const activation = ext.activationEvents ?? [];
  const contributes = ext.contributes ?? {};

  return {
    runsOnStartup: activation.includes("*") || activation.includes("onStartupFinished"),
    hasTerminalAccess: Boolean(contributes.terminal),
    hasDebugAccess: Array.isArray(contributes.debuggers) ? contributes.debuggers.length > 0 : Boolean(contributes.debuggers),
    hasTaskProvider: Array.isArray(contributes.taskDefinitions)
      ? contributes.taskDefinitions.length > 0
      : Boolean(contributes.taskDefinitions),
    commandCount: Array.isArray(contributes.commands) ? contributes.commands.length : 0
  };
}

function applyTrustBehavior(
  extId: string,
  findings: ScanResult["findings"],
  intelMatches: ScanResult["intelMatches"],
  trustedSet: Set<string>
): { effectiveFindings: ScanResult["findings"]; isTrustedByUser: boolean; suppressedFindingsCount: number } {
  const isTrusted = trustedSet.has(extId.toLowerCase());
  const hasMaliciousIntel = intelMatches.some((m) => m.type === "maliciousExtension");

  if (!isTrusted || hasMaliciousIntel) {
    return { effectiveFindings: findings, isTrustedByUser: isTrusted, suppressedFindingsCount: 0 };
  }

  return {
    effectiveFindings: [],
    isTrustedByUser: true,
    suppressedFindingsCount: findings.length
  };
}

export async function runFullScan(context: vscode.ExtensionContext): Promise<FullScanReport> {
  const config = vscode.workspace.getConfiguration("extensionShield");
  const ignore = config.get<string[]>("ignoreExtensions", []);
  const trusted = config.get<string[]>("trustedExtensions", []);
  const enableHeuristics = config.get<boolean>("enableHeuristics", true);
  const trustedSet = new Set(trusted.map((id) => id.toLowerCase()));

  const allExtensions = discoverExtensions(ignore).filter((ext) => !ext.isBuiltin);
  const intelLoad = await loadIntel(context, config);
  const intel = intelLoad.intel;
  const results: ScanResult[] = [];

  for (const ext of allExtensions) {
    const cached = getCachedResult(context, ext.id, ext.version);
    if (cached) {
      const trust = applyTrustBehavior(cached.extension.id, cached.findings, cached.intelMatches, trustedSet);
      const score = computeRisk(cached.intelMatches, trust.effectiveFindings);
      results.push({
        ...cached,
        findings: trust.effectiveFindings,
        riskLevel: score.level,
        riskScore: score.score,
        riskExplanation: trust.isTrustedByUser && !cached.intelMatches.length
          ? "Trusted by user; heuristic findings suppressed."
          : score.explanation,
        permissionProfile: cached.permissionProfile ?? buildPermissionProfile(cached.extension),
        isTrustedByUser: trust.isTrustedByUser,
        suppressedFindingsCount: trust.suppressedFindingsCount
      });
      continue;
    }

    const intelMatches = matchThreatIntel(ext, intel);
    const findings = enableHeuristics ? await runHeuristics(ext, intel) : [];
    const trust = applyTrustBehavior(ext.id, findings, intelMatches, trustedSet);
    const score = computeRisk(intelMatches, trust.effectiveFindings);

    const result: ScanResult = {
      extension: ext,
      intelMatches,
      findings: trust.effectiveFindings,
      riskLevel: score.level,
      riskScore: score.score,
      riskExplanation:
        trust.isTrustedByUser && !intelMatches.length
          ? "Trusted by user; heuristic findings suppressed."
          : score.explanation,
      permissionProfile: buildPermissionProfile(ext),
      isTrustedByUser: trust.isTrustedByUser,
      suppressedFindingsCount: trust.suppressedFindingsCount
    };

    const cachedResult: ScanResult = {
      ...result,
      findings,
      riskLevel: computeRisk(intelMatches, findings).level,
      riskScore: computeRisk(intelMatches, findings).score,
      riskExplanation: computeRisk(intelMatches, findings).explanation,
      isTrustedByUser: false,
      suppressedFindingsCount: 0
    };

    results.push(result);
    await setCachedResult(context, ext.id, ext.version, cachedResult);
  }

  results.sort((a, b) => {
    const order: Record<RiskLevel, number> = { critical: 0, elevated: 1, low: 2 };
    return order[a.riskLevel] - order[b.riskLevel];
  });

  const summary = {
    scanned: results.length,
    critical: results.filter((r) => r.riskLevel === "critical").length,
    elevated: results.filter((r) => r.riskLevel === "elevated").length,
    low: results.filter((r) => r.riskLevel === "low").length
  };

  return {
    timestamp: new Date().toISOString(),
    overallRisk: getWorstRisk(results.map((r) => r.riskLevel)),
    summary,
    results,
    intelSource: intelLoad.source,
    intelUpdatedAt: intelLoad.updatedAt
  };
}

export async function runSingleExtensionScan(
  context: vscode.ExtensionContext,
  extensionId: string
): Promise<ScanResult | undefined> {
  const all = discoverExtensions([]);
  const ext = all.find((item) => item.id.toLowerCase() === extensionId.toLowerCase());
  if (!ext) {
    return undefined;
  }

  const cfg = vscode.workspace.getConfiguration("extensionShield");
  const intelLoad = await loadIntel(context, cfg);
  const intel = intelLoad.intel;
  const trusted = cfg.get<string[]>("trustedExtensions", []);
  const trustedSet = new Set(trusted.map((id) => id.toLowerCase()));
  const intelMatches = matchThreatIntel(ext, intel);
  const rawFindings = await runHeuristics(ext, intel);
  const trust = applyTrustBehavior(ext.id, rawFindings, intelMatches, trustedSet);
  const score = computeRisk(intelMatches, trust.effectiveFindings);

  const result: ScanResult = {
    extension: ext,
    intelMatches,
    findings: trust.effectiveFindings,
    riskLevel: score.level,
    riskScore: score.score,
    riskExplanation:
      trust.isTrustedByUser && !intelMatches.length
        ? "Trusted by user; heuristic findings suppressed."
        : score.explanation,
    permissionProfile: buildPermissionProfile(ext),
    isTrustedByUser: trust.isTrustedByUser,
    suppressedFindingsCount: trust.suppressedFindingsCount
  };

  await setCachedResult(context, ext.id, ext.version, {
    ...result,
    findings: rawFindings,
    riskLevel: computeRisk(intelMatches, rawFindings).level,
    riskScore: computeRisk(intelMatches, rawFindings).score,
    riskExplanation: computeRisk(intelMatches, rawFindings).explanation,
    isTrustedByUser: false,
    suppressedFindingsCount: 0
  });
  return result;
}
