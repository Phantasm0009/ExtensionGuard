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
    expect(result.score).toBeGreaterThanOrEqual(90);
  });

  it("returns elevated for high heuristic findings", () => {
    const result = computeRisk([], [
      {
        ruleId: "H6",
        type: "process",
        severity: "high",
        description: "exec",
        filePath: "x.js",
        line: 1
      }
    ]);

    expect(result.level).toBe("elevated");
    expect(result.score).toBeGreaterThan(0);
  });

  it("returns low for no intel and no findings", () => {
    const result = computeRisk([], []);
    expect(result.level).toBe("low");
  });
});
