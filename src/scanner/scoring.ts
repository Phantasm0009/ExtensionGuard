import { HeuristicFinding, RiskLevel, ThreatIntelMatch } from "../types";

export function computeRisk(
  intelMatches: ThreatIntelMatch[],
  findings: HeuristicFinding[]
): { level: RiskLevel; explanation: string; score: number } {
  const hasKnownMalicious = intelMatches.some((m) => m.type === "maliciousExtension");
  const hasHighVuln = intelMatches.some(
    (m) => m.type === "vulnerableExtension" && (m.severity === "critical" || m.severity === "high")
  );
  const criticalFindingCount = findings.filter((f) => f.severity === "critical").length;
  const highFindingCount = findings.filter((f) => f.severity === "high").length;
  const highCategories = new Set(
    findings.filter((f) => f.severity === "high" || f.severity === "critical").map((f) => f.type)
  ).size;

  let score = 0;
  score += intelMatches.reduce((acc, m) => {
    if (m.type === "maliciousExtension") {
      return acc + 90;
    }
    if (m.severity === "critical") {
      return acc + 70;
    }
    if (m.severity === "high") {
      return acc + 55;
    }
    if (m.severity === "medium") {
      return acc + 35;
    }
    return acc + 20;
  }, 0);

  score += findings.reduce((acc, finding) => {
    if (finding.severity === "critical") {
      return acc + 30;
    }
    if (finding.severity === "high") {
      return acc + 18;
    }
    if (finding.severity === "medium") {
      return acc + 8;
    }
    return acc + 3;
  }, 0);
  score = Math.min(100, score);

  if (hasKnownMalicious) {
    return {
      level: "critical",
      explanation: "Known malicious extension match in threat intelligence.",
      score: Math.max(score, 95)
    };
  }

  if (criticalFindingCount > 0 || highCategories >= 2) {
    return {
      level: "critical",
      explanation: "Critical or multi-category high-severity behavioral signals detected.",
      score: Math.max(score, 75)
    };
  }

  if (hasHighVuln || highFindingCount > 0 || findings.length >= 3 || intelMatches.length > 0) {
    return {
      level: "elevated",
      explanation: "Suspicious behavioral patterns or known vulnerability match detected — manual review advised.",
      score: Math.max(score, 40)
    };
  }

  return {
    level: "low",
    explanation: "No known-bad match and only minimal suspicious behavior detected.",
    score
  };
}
