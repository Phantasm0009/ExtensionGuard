import * as vscode from "vscode";
import { FullScanReport } from "../types";

export class RiskStatusBar {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.item.command = "extensionShield.scan";
    this.item.tooltip = "Run ExtensionShield scan";
    this.item.text = "$(shield) ExtensionShield";
    this.item.show();
  }

  update(report: FullScanReport): void {
    const risks = report.summary.critical + report.summary.elevated;

    if (report.overallRisk === "critical") {
      this.item.text = `$(shield) ExtensionShield: ${risks} risk(s)`;
      this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
      return;
    }

    if (report.overallRisk === "elevated") {
      this.item.text = `$(shield) ExtensionShield: ${risks} warning(s)`;
      this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
      return;
    }

    this.item.text = "$(shield) ExtensionShield: all clear";
    this.item.backgroundColor = undefined;
  }

  dispose(): void {
    this.item.dispose();
  }
}
