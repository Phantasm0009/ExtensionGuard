import * as vscode from "vscode";
import { runFullScan, runSingleExtensionScan } from "./scanner";
import { ScanResult } from "./types";
import { DashboardFilterMode, ExtensionTreeProvider } from "./ui/extensionTreeProvider";
import { DetailPanel } from "./ui/detailPanel";
import { RiskStatusBar } from "./ui/statusBar";

let treeProvider: ExtensionTreeProvider;
let statusBar: RiskStatusBar;

async function ensureReport(context: vscode.ExtensionContext): Promise<void> {
  if (!treeProvider.getReport()) {
    await executeFullScan(context);
  }
}

async function pickExtensionFromReport(): Promise<ScanResult | undefined> {
  const report = treeProvider.getReport();
  if (!report || report.results.length === 0) {
    return undefined;
  }

  const sorted = [...report.results].sort((a, b) => {
    const order: Record<string, number> = { critical: 0, elevated: 1, low: 2 };
    return order[a.riskLevel] - order[b.riskLevel];
  });

  const pick = await vscode.window.showQuickPick(
    sorted.map((item) => ({
      label: item.extension.name,
      description: `${item.extension.id} - ${item.riskLevel}`,
      detail: `${item.findings.length} heuristic finding(s), ${item.intelMatches.length} intel match(es)`,
      result: item
    })),
    {
      title: "Select an extension",
      placeHolder: "Choose an extension to inspect or re-scan"
    }
  );

  return pick?.result;
}

async function executeFullScan(context: vscode.ExtensionContext): Promise<void> {
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "ExtensionShield scanning installed extensions",
      cancellable: false
    },
    async () => {
      const report = await runFullScan(context);
      treeProvider.setReport(report);
      statusBar.update(report);

      const message = `Scanned ${report.summary.scanned} extension(s). Critical: ${report.summary.critical}, Elevated: ${report.summary.elevated}, Low: ${report.summary.low}.`;
      if (report.summary.critical > 0) {
        const action = await vscode.window.showWarningMessage(message, "Open Dashboard");
        if (action === "Open Dashboard") {
          await vscode.commands.executeCommand("workbench.view.extension.extensionShield");
        }
      } else {
        void vscode.window.showInformationMessage(message);
      }
    }
  );
}

async function rescanExtension(context: vscode.ExtensionContext, extensionId?: string): Promise<void> {
  if (!extensionId) {
    await ensureReport(context);
    const selected = await pickExtensionFromReport();
    extensionId = selected?.extension.id;
  }

  if (!extensionId) {
    void vscode.window.showWarningMessage("No extension selected. Run a full scan first.");
    return;
  }

  const result = await runSingleExtensionScan(context, extensionId);
  if (!result) {
    void vscode.window.showWarningMessage(`Extension not found: ${extensionId}`);
    return;
  }

  void vscode.window.showInformationMessage(
    `Re-scanned ${result.extension.id}. Risk: ${result.riskLevel}.`
  );

  await executeFullScan(context);
}

function showExtensionSummary(context: vscode.ExtensionContext, result: ScanResult): void {
  DetailPanel.show(context, result);
}

export function activate(context: vscode.ExtensionContext): void {
  treeProvider = new ExtensionTreeProvider();
  statusBar = new RiskStatusBar();

  const treeView = vscode.window.createTreeView("extensionShield.results", {
    treeDataProvider: treeProvider,
    showCollapseAll: true
  });

  context.subscriptions.push(treeView, statusBar);

  context.subscriptions.push(
    vscode.commands.registerCommand("extensionShield.scan", async () => {
      await executeFullScan(context);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("extensionShield.setFilter", async () => {
      const current = treeProvider.getFilterMode();
      const selected = await vscode.window.showQuickPick(
        [
          { label: "All", description: "Show all scanned extensions", mode: "all" as DashboardFilterMode },
          {
            label: "Critical only",
            description: "Show only critical-risk extensions",
            mode: "criticalOnly" as DashboardFilterMode
          },
          {
            label: "Intel matches only",
            description: "Show extensions with threat intel matches",
            mode: "intelOnly" as DashboardFilterMode
          }
        ],
        {
          title: "Set ExtensionShield Dashboard Filter",
          placeHolder: `Current: ${
            current === "all" ? "All" : current === "criticalOnly" ? "Critical only" : "Intel matches only"
          }`
        }
      );

      if (!selected) {
        return;
      }

      treeProvider.setFilterMode(selected.mode);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("extensionShield.rescanExtension", async (item?: { result?: ScanResult }) => {
      const id = item?.result?.extension.id;
      await rescanExtension(context, id);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("extensionShield.openSettings", async () => {
      await vscode.commands.executeCommand("workbench.action.openSettings", "@ext:extensionshield.extensionshield");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("extensionShield.showExtensionSummary", async (item?: ScanResult | { result?: ScanResult }) => {
      let result: ScanResult | undefined;

      if (item && "extension" in item) {
        result = item;
      } else {
        result = item?.result;
      }

      if (!result) {
        await ensureReport(context);
        result = await pickExtensionFromReport();
      }

      if (!result) {
        void vscode.window.showWarningMessage("No scan result available. Run a scan first.");
        return;
      }

      showExtensionSummary(context, result);
    })
  );

  const config = vscode.workspace.getConfiguration("extensionShield");
  if (config.get<boolean>("scanOnStartup", false)) {
    void executeFullScan(context);
  }

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("extensionShield.showLowRiskBucket")) {
        treeProvider.setFilterMode(treeProvider.getFilterMode());
      }
    })
  );
}

export function deactivate(): void {
  statusBar?.dispose();
}
