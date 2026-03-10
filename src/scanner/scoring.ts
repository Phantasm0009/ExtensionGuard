import { HeuristicFinding, RiskLevel, ThreatIntelMatch } from "../types";

export function computeRisk(
  intelMatches: ThreatIntelMatch[],
  findings: HeuristicFinding[]
): { level: RiskLevel; explanation: string } {
  const hasKnownMalicious = intelMatches.some((m) => m.type === "maliciousExtension");
  const hasHighVuln = intelMatches.some((m) => m.type === "vulnerableExtension" && (m.severity === "critical" || m.severity === "high"));
  const criticalFindingCount = findings.filter((f) => f.severity === "critical").length;
  const highFindingCount = findings.filter((f) => f.severity === "high").length;

  if (hasKnownMalicious || hasHighVuln || criticalFindingCount > 0) {
    return {
      level: "critical",
      explanation: "Known malicious/vulnerable signal or critical behavioral pattern detected."
    };
  }

  if (highFindingCount > 0 || findings.length >= 3 || intelMatches.length > 0) {
    return {
      level: "elevated",
      explanation: "Suspicious behavioral patterns detected that deserve manual review."
    };
  }

  return {
    level: "low",
    explanation: "No known-bad match and only minimal suspicious behavior detected."
  };
}
