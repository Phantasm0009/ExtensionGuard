import * as path from "node:path";
import * as vscode from "vscode";
import { FullScanReport, HeuristicFinding, ScanResult } from "../types";

type TreeNode = SummaryNode | RiskGroupNode | ScanNode | FindingTypeNode | FindingNode | InfoNode;

class InfoNode extends vscode.TreeItem {
  constructor(label: string) {
    super(label, vscode.TreeItemCollapsibleState.None);
  }
}

class SummaryNode extends vscode.TreeItem {
  constructor(report: FullScanReport) {
    super("Scan Summary", vscode.TreeItemCollapsibleState.None);
    this.description =
      `Total ${report.summary.scanned} | Critical ${report.summary.critical} | Elevated ${report.summary.elevated} | Low ${report.summary.low}`;
    this.iconPath = new vscode.ThemeIcon(
      report.overallRisk === "critical" ? "error" : report.overallRisk === "elevated" ? "warning" : "pass"
    );
    this.tooltip = `Last scan: ${new Date(report.timestamp).toLocaleString()}`;
  }
}

class RiskGroupNode extends vscode.TreeItem {
  constructor(
    public readonly level: "critical" | "elevated" | "low",
    public readonly items: ScanResult[]
  ) {
    super(
      `${level[0].toUpperCase()}${level.slice(1)} (${items.length})`,
      items.length ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.None
    );

    this.iconPath = new vscode.ThemeIcon(level === "critical" ? "error" : level === "elevated" ? "warning" : "pass");
    this.tooltip = `${items.length} extension(s) in ${level} risk bucket`;
    if (!items.length) {
      this.description = "none";
    }
  }
}

class ScanNode extends vscode.TreeItem {
  constructor(public readonly result: ScanResult) {
    super(
      result.extension.name,
      vscode.TreeItemCollapsibleState.Collapsed
    );

    const findingCount = result.findings.length;
    const intelCount = result.intelMatches.length;
    this.description = `${result.extension.id} | findings ${findingCount} | intel ${intelCount}`;
    this.iconPath = new vscode.ThemeIcon(
      result.riskLevel === "critical"
        ? "error"
        : result.riskLevel === "elevated"
          ? "warning"
          : "pass"
    );
    this.tooltip = `${result.riskExplanation}\nPath: ${result.extension.extensionPath}`;
    this.contextValue = "extensionShield.scanNode";
    this.command = {
      title: "Show Extension Details",
      command: "extensionShield.showExtensionSummary",
      arguments: [result]
    };
  }
}

class FindingTypeNode extends vscode.TreeItem {
  constructor(public readonly findingType: HeuristicFinding["type"], public readonly findings: HeuristicFinding[]) {
    super(`${findingType} (${findings.length})`, vscode.TreeItemCollapsibleState.Collapsed);
    this.iconPath = new vscode.ThemeIcon("list-tree");
    this.description = findings.some((f) => f.severity === "critical" || f.severity === "high")
      ? "review"
      : "info";
  }
}

class FindingNode extends vscode.TreeItem {
  constructor(public readonly finding: HeuristicFinding) {
    super(`${finding.ruleId}: ${finding.description}`, vscode.TreeItemCollapsibleState.None);
    this.description = `${finding.severity.toUpperCase()} | ${path.basename(finding.filePath)}${finding.line ? `:${finding.line}` : ""}`;
    this.iconPath = new vscode.ThemeIcon("circle-filled");
    this.tooltip = finding.filePath;
  }
}

export class ExtensionTreeProvider implements vscode.TreeDataProvider<TreeNode> {
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<TreeNode | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private report: FullScanReport | null = null;

  public setReport(report: FullScanReport): void {
    this.report = report;
    this._onDidChangeTreeData.fire(undefined);
  }

  public getReport(): FullScanReport | null {
    return this.report;
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeNode): Thenable<TreeNode[]> {
    if (!this.report) {
      return Promise.resolve([new InfoNode("Run ExtensionShield scan to view results")]);
    }

    if (!element) {
      const critical = this.report.results.filter((r) => r.riskLevel === "critical");
      const elevated = this.report.results.filter((r) => r.riskLevel === "elevated");
      const low = this.report.results.filter((r) => r.riskLevel === "low");

      return Promise.resolve([
        new SummaryNode(this.report),
        new RiskGroupNode("critical", critical),
        new RiskGroupNode("elevated", elevated),
        new RiskGroupNode("low", low)
      ]);
    }

    if (element instanceof RiskGroupNode) {
      if (!element.items.length) {
        return Promise.resolve([new InfoNode("No extensions in this risk group")]);
      }
      return Promise.resolve(element.items.map((result) => new ScanNode(result)));
    }

    if (element instanceof ScanNode) {
      if (!element.result.findings.length) {
        const intelInfo = element.result.intelMatches.length
          ? new InfoNode(`Threat intel matches: ${element.result.intelMatches.length}`)
          : new InfoNode("No heuristic findings");
        return Promise.resolve([intelInfo]);
      }

      const byType = new Map<HeuristicFinding["type"], HeuristicFinding[]>();
      for (const finding of element.result.findings) {
        const existing = byType.get(finding.type) ?? [];
        existing.push(finding);
        byType.set(finding.type, existing);
      }

      const typeNodes = Array.from(byType.entries()).map(
        ([findingType, findings]) => new FindingTypeNode(findingType, findings)
      );

      return Promise.resolve(typeNodes);
    }

    if (element instanceof FindingTypeNode) {
      return Promise.resolve(element.findings.map((finding) => new FindingNode(finding)));
    }

    return Promise.resolve([]);
  }
}
