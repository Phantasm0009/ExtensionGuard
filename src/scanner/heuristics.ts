import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ExtensionInfo, HeuristicFinding, IntelData } from "../types";
import { RAW_RULES, TRUSTED_PUBLISHERS, maliciousHostRegex } from "./heuristicRules";

const MAX_FILES = 60;
const MAX_DEPTH = 3;

function getLineFromIndex(content: string, index: number): number {
  return content.slice(0, index).split(/\r\n|\r|\n/).length;
}

function getSnippet(content: string, index: number): string {
  const lineIdx = getLineFromIndex(content, index) - 1;
  const line = content.split(/\r\n|\r|\n/)[lineIdx] ?? "";
  return line.trim().slice(0, 120);
}

async function collectFiles(dirPath: string, depth = 0, output: string[] = []): Promise<string[]> {
  if (depth > MAX_DEPTH || output.length >= MAX_FILES) {
    return output;
  }

  let entries;
  try {
    entries = await fs.readdir(dirPath, { withFileTypes: true });
  } catch {
    return output;
  }

  for (const entry of entries) {
    if (output.length >= MAX_FILES) {
      break;
    }

    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      if (["node_modules", ".git", "test", "tests"].includes(entry.name)) {
        continue;
      }
      await collectFiles(fullPath, depth + 1, output);
      continue;
    }

    if (/\.(js|cjs|mjs|ts)$/i.test(entry.name)) {
      output.push(fullPath);
    }
  }

  return output;
}

function addFinding(findings: HeuristicFinding[], finding: HeuristicFinding): void {
  const alreadyExists = findings.some(
    (f) => f.ruleId === finding.ruleId && f.filePath === finding.filePath && f.line === finding.line
  );

  if (!alreadyExists) {
    findings.push(finding);
  }
}

function cloneRegex(regex: RegExp): RegExp {
  return new RegExp(regex.source, regex.flags);
}

function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, () => Array<number>(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i += 1) {
    dp[i][0] = i;
  }
  for (let j = 0; j <= b.length; j += 1) {
    dp[0][j] = j;
  }

  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }

  return dp[a.length][b.length];
}

function typosquatFinding(ext: ExtensionInfo): HeuristicFinding | null {
  const publisher = ext.id.split(".")[0]?.toLowerCase() ?? "";
  const extensionName = ext.name.toLowerCase();
  const canonicalNames = ["python", "prettier", "eslint", "live server", "jupyter", "github copilot"];
  if (!publisher) {
    return null;
  }

  for (const trusted of TRUSTED_PUBLISHERS) {
    const distance = levenshtein(publisher, trusted.toLowerCase());
    if (distance > 0 && distance <= 2) {
      return {
        ruleId: "H15",
        type: "typosquat",
        severity: "high",
        description: `Publisher '${publisher}' is very similar to trusted publisher '${trusted}'. Possible impersonation.`,
        filePath: ext.extensionPath
      };
    }
  }

  for (const canonical of canonicalNames) {
    const distance = levenshtein(extensionName, canonical.toLowerCase());
    if (distance > 0 && distance <= 2) {
      return {
        ruleId: "H15",
        type: "typosquat",
        severity: "high",
        description: `Extension name '${extensionName}' is very similar to popular extension '${canonical}'. Possible impersonation.`,
        filePath: ext.extensionPath
      };
    }
  }

  return null;
}

export async function runHeuristics(ext: ExtensionInfo, intel: IntelData): Promise<HeuristicFinding[]> {
  const findings: HeuristicFinding[] = [];
  const filesToScan: string[] = [];
  let hasNetworkSignal = false;
  let hasSensitivePathSignal = false;
  let hasProcessSignal = false;

  if (ext.main) {
    filesToScan.push(path.join(ext.extensionPath, ext.main));
  }
  if (ext.browser) {
    filesToScan.push(path.join(ext.extensionPath, ext.browser));
  }

  const scannedDirs = ["src", "dist", "out"];
  for (const dir of scannedDirs) {
    const fullDir = path.join(ext.extensionPath, dir);
    const collected = await collectFiles(fullDir);
    filesToScan.push(...collected);
  }

  const uniqueFiles = [...new Set(filesToScan)].slice(0, MAX_FILES);

  for (const file of uniqueFiles) {
    let content = "";
    try {
      content = await fs.readFile(file, "utf8");
    } catch {
      continue;
    }

    for (const rule of RAW_RULES) {
      const regex = cloneRegex(rule.regex);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        if (match.index === undefined) {
          break;
        }

        addFinding(findings, {
          ruleId: rule.id,
          type: rule.type,
          severity: rule.severity,
          description: rule.description,
          filePath: file,
          line: getLineFromIndex(content, match.index),
          snippet: getSnippet(content, match.index)
        });

        if (rule.type === "network") {
          hasNetworkSignal = true;
        }
        if (rule.id === "H8" || rule.id === "H10") {
          hasSensitivePathSignal = true;
        }
        if (rule.id === "H6") {
          hasProcessSignal = true;
        }

        if (!regex.global) {
          break;
        }
      }
    }

    const hostRegex = maliciousHostRegex(intel);
    if (hostRegex) {
      let hostMatch: RegExpExecArray | null;
      while ((hostMatch = hostRegex.exec(content)) !== null) {
        if (hostMatch.index === undefined) {
          break;
        }

        addFinding(findings, {
          ruleId: "H4",
          type: "network",
          severity: "critical",
          description: `Known malicious host matched: ${hostMatch[0]}`,
          filePath: file,
          line: getLineFromIndex(content, hostMatch.index),
          snippet: getSnippet(content, hostMatch.index)
        });
        hasNetworkSignal = true;

        if (!hostRegex.global) {
          break;
        }
      }
    }

    const longLine = content.split(/\r\n|\r|\n/).findIndex((line) => line.length > 10000);
    if (longLine >= 0 && !file.includes("dist") && !file.includes("min")) {
      addFinding(findings, {
        ruleId: "H16",
        type: "obfuscation",
        severity: "medium",
        description: "Large potentially minified line detected in non-dist source file.",
        filePath: file,
        line: longLine + 1
      });
    }
  }

  if (hasProcessSignal && hasNetworkSignal) {
    addFinding(findings, {
      ruleId: "H7",
      type: "process",
      severity: "high",
      description: "Process execution and network usage both present (potential remote command workflow).",
      filePath: ext.extensionPath
    });
  }

  if (hasSensitivePathSignal && hasNetworkSignal) {
    addFinding(findings, {
      ruleId: "H14",
      type: "network",
      severity: "critical",
      description: "Sensitive path indicators combined with network usage (possible exfiltration path).",
      filePath: ext.extensionPath
    });
  }

  const typo = typosquatFinding(ext);
  if (typo) {
    addFinding(findings, typo);
  }

  return findings;
}
