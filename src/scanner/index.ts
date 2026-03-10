import * as vscode from "vscode";
import { FullScanReport, RiskLevel, ScanResult } from "../types";
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

export async function runFullScan(context: vscode.ExtensionContext): Promise<FullScanReport> {
  const config = vscode.workspace.getConfiguration("extensionShield");
  const ignore = config.get<string[]>("ignoreExtensions", []);
  const enableHeuristics = config.get<boolean>("enableHeuristics", true);

  const allExtensions = discoverExtensions(ignore).filter((ext) => !ext.isBuiltin);
  const intel = await loadIntel(context.extensionPath);
  const results: ScanResult[] = [];

  for (const ext of allExtensions) {
    const cached = getCachedResult(context, ext.id, ext.version);
    if (cached) {
      results.push(cached);
      continue;
    }

    const intelMatches = matchThreatIntel(ext, intel);
    const findings = enableHeuristics ? await runHeuristics(ext, intel) : [];
    const score = computeRisk(intelMatches, findings);

    const result: ScanResult = {
      extension: ext,
      intelMatches,
      findings,
      riskLevel: score.level,
      riskExplanation: score.explanation
    };

    results.push(result);
    await setCachedResult(context, ext.id, ext.version, result);
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
    results
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

  const intel = await loadIntel(context.extensionPath);
  const intelMatches = matchThreatIntel(ext, intel);
  const findings = await runHeuristics(ext, intel);
  const score = computeRisk(intelMatches, findings);

  const result: ScanResult = {
    extension: ext,
    intelMatches,
    findings,
    riskLevel: score.level,
    riskExplanation: score.explanation
  };

  await setCachedResult(context, ext.id, ext.version, result);
  return result;
}
