import { describe, expect, it } from "vitest";
import { computeRisk } from "../scanner/scoring";

describe("computeRisk", () => {
  it("returns critical for known malicious intel match", () => {
    const result = computeRisk(
      [
        {
          type: "maliciousExtension",
          severity: "critical",
          reason: "known bad",
          referenceUrl: "https://example.com"
        }
      ],
      []
    );

    expect(result.level).toBe("critical");
  });

  it("returns elevated for high heuristic findings", () => {
    const result = computeRisk([], [
      {
        ruleId: "H5",
        type: "process",
        severity: "high",
        description: "exec",
        filePath: "x.js",
        line: 1
      }
    ]);

    expect(result.level).toBe("elevated");
  });

  it("returns low for no intel and no findings", () => {
    const result = computeRisk([], []);
    expect(result.level).toBe("low");
  });
});
