import * as vscode from "vscode";
import * as fs from "node:fs/promises";
import { runFullScan, runSingleExtensionScan } from "./scanner";
import { refreshIntelNow } from "./scanner/threatIntel";
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
  const report = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "ExtensionShield scanning installed extensions",
      cancellable: false
    },
    async () => {
      return runFullScan(context);
    }
  );

  treeProvider.setReport(report);
  statusBar.update(report);

  const message = `Scanned ${report.summary.scanned} extension(s). Critical: ${report.summary.critical}, Elevated: ${report.summary.elevated}, Low: ${report.summary.low}.`;
  if (report.summary.critical > 0) {
    void vscode.window
      .showWarningMessage(message, "Open Dashboard")
      .then(async (action) => {
        if (action === "Open Dashboard") {
          await vscode.commands.executeCommand("workbench.view.extension.extensionShield");
        }
      });
  } else {
    void vscode.window.showInformationMessage(message);
  }
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
  treeProvider.upsertResult(result);
  const report = treeProvider.getReport();
  if (report) {
    statusBar.update(report);
  }
}

async function toggleTrustedExtension(target: ScanResult): Promise<void> {
  const config = vscode.workspace.getConfiguration("extensionShield");
  const trusted = new Set(config.get<string[]>("trustedExtensions", []).map((id) => id.toLowerCase()));
  const id = target.extension.id.toLowerCase();

  let message = "";
  if (trusted.has(id)) {
    trusted.delete(id);
    message = `Removed ${target.extension.id} from trusted extensions.`;
  } else {
    trusted.add(id);
    message = `Added ${target.extension.id} to trusted extensions.`;
  }

  await config.update("trustedExtensions", [...trusted], vscode.ConfigurationTarget.Global);
  void vscode.window.showInformationMessage(message);
}

async function exportReport(): Promise<void> {
  const report = treeProvider.getReport();
  if (!report) {
    void vscode.window.showWarningMessage("No report available. Run a scan first.");
    return;
  }

  const defaultUri = vscode.workspace.workspaceFolders?.[0]
    ? vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, "extensionShield-report.json")
    : undefined;

  const targetUri = await vscode.window.showSaveDialog({
    defaultUri,
    filters: {
      JSON: ["json"],
      Markdown: ["md"]
    }
  });

  if (!targetUri) {
    return;
  }

  const metadata = {
    generatedAt: new Date().toISOString(),
    platform: process.platform,
    vscodeVersion: vscode.version,
    extensionVersion: vscode.extensions.getExtension("extensionshield.extensionshield")?.packageJSON.version
  };

  const isMarkdown = targetUri.fsPath.toLowerCase().endsWith(".md");
  if (isMarkdown) {
    const lines = [
      "# ExtensionShield Report",
      "",
      `Generated: ${metadata.generatedAt}`,
      `Platform: ${metadata.platform}`,
      `VS Code: ${metadata.vscodeVersion}`,
      `ExtensionShield: ${metadata.extensionVersion ?? "unknown"}`,
      `Intel Source: ${report.intelSource}`,
      `Intel Updated At: ${report.intelUpdatedAt}`,
      "",
      `Summary: scanned ${report.summary.scanned}, critical ${report.summary.critical}, elevated ${report.summary.elevated}, low ${report.summary.low}`,
      ""
    ];

    for (const result of report.results) {
      lines.push(`## ${result.extension.name} (${result.extension.id})`);
      lines.push(`- Risk: ${result.riskLevel} (${result.riskScore})`);
      lines.push(`- Explanation: ${result.riskExplanation}`);
      lines.push(`- Trusted: ${result.isTrustedByUser ? "yes" : "no"}`);
      lines.push(`- Intel matches: ${result.intelMatches.length}`);
      lines.push(`- Findings: ${result.findings.length}`);
      lines.push("");
    }

    await fs.writeFile(targetUri.fsPath, lines.join("\n"), "utf8");
  } else {
    await fs.writeFile(
      targetUri.fsPath,
      JSON.stringify({ metadata, report }, null, 2),
      "utf8"
    );
  }

  void vscode.window.showInformationMessage(`Report exported to ${targetUri.fsPath}`);
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
    vscode.commands.registerCommand("extensionShield.refreshIntel", async () => {
      const cfg = vscode.workspace.getConfiguration("extensionShield");
      const enabled = cfg.get<boolean>("enableNetworkIntelUpdates", false);

      if (!enabled) {
        const action = await vscode.window.showWarningMessage(
          "Network intel updates are disabled. Enable them to refresh intel now.",
          "Open Settings"
        );
        if (action === "Open Settings") {
          await vscode.commands.executeCommand("workbench.action.openSettings", "extensionShield.enableNetworkIntelUpdates");
        }
        return;
      }

      try {
        const intel = await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: "ExtensionShield refreshing threat intel",
            cancellable: false
          },
          async () => refreshIntelNow(context, cfg)
        );

        void vscode.window.showInformationMessage(
          `Threat intel refreshed from ${intel.source} (${new Date(intel.updatedAt).toLocaleString()}).`
        );
        await executeFullScan(context);
      } catch (error) {
        const reason = error instanceof Error ? error.message : "Unknown error";
        void vscode.window.showErrorMessage(`Failed to refresh threat intel: ${reason}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("extensionShield.setFilter", async () => {
      const current = treeProvider.getFilterMode();
      const filterLabels: Record<DashboardFilterMode, string> = {
        all: "All",
        criticalOnly: "Critical only",
        intelOnly: "Intel matches only",
        heuristicOnly: "Heuristic findings only"
      };

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
          },
          {
            label: "Heuristic findings only",
            description: "Show extensions with heuristic behavior findings (excludes intel-only results)",
            mode: "heuristicOnly" as DashboardFilterMode
          }
        ],
        {
          title: "Set ExtensionShield Dashboard Filter",
          placeHolder: `Current: ${filterLabels[current]}`
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
    vscode.commands.registerCommand("extensionShield.markTrusted", async (item?: { result?: ScanResult }) => {
      const target = item?.result;
      if (!target) {
        const selected = await pickExtensionFromReport();
        if (!selected) {
          return;
        }
        await toggleTrustedExtension(selected);
      } else {
        await toggleTrustedExtension(target);
      }
      await executeFullScan(context);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("extensionShield.exportReport", async () => {
      await exportReport();
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
      if (
        event.affectsConfiguration("extensionShield.showLowRiskBucket") ||
        event.affectsConfiguration("extensionShield.trustedExtensions")
      ) {
        treeProvider.setFilterMode(treeProvider.getFilterMode());
      }
    })
  );

  context.subscriptions.push(
    vscode.extensions.onDidChange(async () => {
      const cfg = vscode.workspace.getConfiguration("extensionShield");
      if (cfg.get<boolean>("scanOnExtensionChange", true)) {
        await executeFullScan(context);
      }
    })
  );
}

export function deactivate(): void {
  statusBar?.dispose();
}
