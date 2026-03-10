import { describe, expect, it } from "vitest";
import { matchThreatIntel } from "../scanner/threatIntel";
import { ExtensionInfo, IntelData } from "../types";

const intel: IntelData = {
  maliciousExtensions: [
    { id: "bad.publisher", reason: "Known bad", referenceUrl: "https://example.com/bad" }
  ],
  vulnerableExtensions: [
    {
      id: "vuln.publisher",
      versionRange: "<=1.2.3",
      severity: "high",
      reason: "Known vuln",
      cve: "CVE-2025-0001",
      referenceUrl: "https://example.com/cve"
    }
  ],
  maliciousHosts: []
};

function makeExt(id: string, version: string): ExtensionInfo {
  return {
    id,
    name: id,
    version,
    description: "",
    extensionPath: "C:/tmp/ext",
    isBuiltin: false,
    activationEvents: [],
    contributes: {}
  };
}

describe("matchThreatIntel", () => {
  it("matches malicious extension by id", () => {
    const matches = matchThreatIntel(makeExt("bad.publisher", "1.0.0"), intel);
    expect(matches).toHaveLength(1);
    expect(matches[0].type).toBe("maliciousExtension");
    expect(matches[0].severity).toBe("critical");
  });

  it("matches vulnerable extension by version range", () => {
    const matches = matchThreatIntel(makeExt("vuln.publisher", "1.2.3"), intel);
    expect(matches).toHaveLength(1);
    expect(matches[0].type).toBe("vulnerableExtension");
    expect(matches[0].cve).toBe("CVE-2025-0001");
  });

  it("does not match vulnerable extension outside range", () => {
    const matches = matchThreatIntel(makeExt("vuln.publisher", "2.0.0"), intel);
    expect(matches).toHaveLength(0);
  });
});
