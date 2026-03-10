import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runHeuristics } from "../scanner/heuristics";
import { ExtensionInfo, IntelData } from "../types";

const tempDirs: string[] = [];

async function makeTempExtension(source: string): Promise<ExtensionInfo> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "extensionshield-test-"));
  tempDirs.push(dir);
  await fs.writeFile(path.join(dir, "index.js"), source, "utf8");

  return {
    id: "test.publisher",
    name: "test",
    version: "1.0.0",
    description: "",
    extensionPath: dir,
    isBuiltin: false,
    activationEvents: [],
    contributes: {},
    main: "index.js"
  };
}

afterEach(async () => {
  for (const dir of tempDirs.splice(0, tempDirs.length)) {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

const intel: IntelData = {
  maliciousExtensions: [],
  vulnerableExtensions: [],
  maliciousHosts: [{ hostOrIp: "203.0.113.7", reason: "bad host", referenceUrl: "https://example.com/host" }]
};

describe("runHeuristics", () => {
  it("captures multiple matches per rule in the same file", async () => {
    const ext = await makeTempExtension(`
      const cp = require('child_process');
      cp.exec('whoami');
      cp.exec('hostname');
    `);

    const findings = await runHeuristics(ext, intel);
    const processFindings = findings.filter((f) => f.ruleId === "H6");
    expect(processFindings.length).toBeGreaterThanOrEqual(2);
  });

  it("detects process and network indicators", async () => {
    const ext = await makeTempExtension(`
      const cp = require('child_process');
      fetch('http://evil.test');
      cp.exec('whoami');
    `);

    const findings = await runHeuristics(ext, intel);
    const ids = findings.map((f) => f.ruleId);

    expect(ids).toContain("H1");
    expect(ids).toContain("H3");
    expect(ids).toContain("H6");
  });

  it("detects known malicious hosts", async () => {
    const ext = await makeTempExtension(`
      const axios = { get() {} };
      const x = '203.0.113.7';
      axios.get('https://' + x);
    `);

    const findings = await runHeuristics(ext, intel);
    expect(findings.some((f) => f.ruleId === "H4")).toBe(true);
  });
});
