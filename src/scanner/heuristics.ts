import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ExtensionInfo, HeuristicFinding, IntelData } from "../types";
import { RAW_RULES, maliciousHostRegex } from "./heuristicRules";

const MAX_FILES = 60;
const MAX_DEPTH = 3;

function getLineFromIndex(content: string, index: number): number {
  return content.slice(0, index).split(/\r\n|\r|\n/).length;
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

export async function runHeuristics(ext: ExtensionInfo, intel: IntelData): Promise<HeuristicFinding[]> {
  const findings: HeuristicFinding[] = [];
  const filesToScan: string[] = [];

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
      rule.regex.lastIndex = 0;
      const match = rule.regex.exec(content);
      if (!match || match.index === undefined) {
        continue;
      }

      addFinding(findings, {
        ruleId: rule.id,
        type: rule.type,
        severity: rule.severity,
        description: rule.description,
        filePath: file,
        line: getLineFromIndex(content, match.index)
      });
    }

    const hostRegex = maliciousHostRegex(intel);
    if (hostRegex) {
      hostRegex.lastIndex = 0;
      const hostMatch = hostRegex.exec(content);
      if (hostMatch && hostMatch.index !== undefined) {
        addFinding(findings, {
          ruleId: "H4",
          type: "network",
          severity: "critical",
          description: `Known malicious host matched: ${hostMatch[0]}`,
          filePath: file,
          line: getLineFromIndex(content, hostMatch.index)
        });
      }
    }
  }

  return findings;
}
