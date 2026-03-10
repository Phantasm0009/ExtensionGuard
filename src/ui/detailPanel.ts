import * as vscode from "vscode";
import * as path from "node:path";
import { ScanResult } from "../types";

export class DetailPanel {
  private static panel: vscode.WebviewPanel | undefined;
  private static currentResult: ScanResult | undefined;

  public static show(context: vscode.ExtensionContext, result: ScanResult): void {
    const column = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;

    if (DetailPanel.panel) {
      DetailPanel.panel.reveal(column);
      DetailPanel.panel.title = `ExtensionShield: ${result.extension.name}`;
      DetailPanel.panel.webview.html = DetailPanel.getHtml(result);
      DetailPanel.currentResult = result;
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      "extensionShield.details",
      `ExtensionShield: ${result.extension.name}`,
      column,
      {
        enableScripts: true,
        retainContextWhenHidden: true
      }
    );

    panel.onDidDispose(() => {
      DetailPanel.panel = undefined;
      DetailPanel.currentResult = undefined;
    });

    panel.webview.html = DetailPanel.getHtml(result);
    DetailPanel.currentResult = result;
    DetailPanel.attachMessageHandlers(panel);
    DetailPanel.panel = panel;
  }

  private static attachMessageHandlers(panel: vscode.WebviewPanel): void {
    panel.webview.onDidReceiveMessage(async (message) => {
      const result = DetailPanel.currentResult;
      if (!result) {
        return;
      }

      if (!message || typeof message !== "object") {
        return;
      }

      if (message.command === "openUrl" && typeof message.url === "string") {
        await vscode.env.openExternal(vscode.Uri.parse(message.url));
        return;
      }

      if (
        message.command === "openFindingLocation" &&
        typeof message.filePath === "string" &&
        (typeof message.line === "number" || typeof message.line === "undefined")
      ) {
        const uri = vscode.Uri.file(message.filePath);
        const document = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(document, { preview: false });
        const line = Math.max(0, (message.line ?? 1) - 1);
        const position = new vscode.Position(line, 0);
        editor.selection = new vscode.Selection(position, position);
        editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
        return;
      }

      if (message.command === "copyFindingJson" && typeof message.finding === "object") {
        const payload = JSON.stringify(message.finding, null, 2);
        await vscode.env.clipboard.writeText(payload);
        void vscode.window.showInformationMessage("Finding JSON copied to clipboard.");
        return;
      }

      if (message.command === "manageExtension") {
        await vscode.commands.executeCommand("workbench.extensions.search", `@installed ${result.extension.id}`);
        return;
      }

      if (message.command === "disableExtension") {
        await vscode.commands.executeCommand("workbench.extensions.search", `@installed ${result.extension.id}`);
        void vscode.window.showInformationMessage(
          `Open the extension card for ${result.extension.id} and click Disable.`
        );
      }
    });
  }

  private static getRiskClass(level: string): string {
    if (level === "critical") {
      return "critical";
    }
    if (level === "elevated") {
      return "elevated";
    }
    return "low";
  }

  private static getHtml(result: ScanResult): string {
    const riskClass = DetailPanel.getRiskClass(result.riskLevel);
    const intelRows = result.intelMatches.length
      ? result.intelMatches
          .map(
            (m) => `
              <tr>
                <td>${m.type}</td>
                <td>${m.severity}</td>
                <td>${escapeHtml(m.reason)}${m.cve ? ` (${escapeHtml(m.cve)})` : ""}</td>
                <td><a href="#" data-url="${escapeHtml(m.referenceUrl)}" class="open-link">Open</a></td>
              </tr>
            `
          )
          .join("")
      : `<tr><td colspan="4">No threat intel matches.</td></tr>`;

    const findingRows = result.findings.length
      ? result.findings
          .map(
            (f) => `
              <tr>
                <td>${f.ruleId}</td>
                <td>${f.type}</td>
                <td>${f.severity}</td>
                <td>${escapeHtml(f.description)}</td>
                <td>${escapeHtml(path.basename(f.filePath))}${f.line ? `:${f.line}` : ""}</td>
                <td>
                  <button
                    class="secondary finding-open"
                    data-file="${escapeHtmlAttr(f.filePath)}"
                    data-line="${f.line ?? 1}"
                  >Open</button>
                  <button
                    class="secondary finding-copy"
                    data-rule-id="${escapeHtmlAttr(f.ruleId)}"
                    data-type="${escapeHtmlAttr(f.type)}"
                    data-severity="${escapeHtmlAttr(f.severity)}"
                    data-description="${escapeHtmlAttr(f.description)}"
                    data-file="${escapeHtmlAttr(f.filePath)}"
                    data-line="${f.line ?? 1}"
                  >Copy JSON</button>
                </td>
              </tr>
            `
          )
          .join("")
      : `<tr><td colspan="6">No heuristic findings.</td></tr>`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ExtensionShield Details</title>
  <style>
    :root {
      --bg: var(--vscode-editor-background);
      --fg: var(--vscode-editor-foreground);
      --border: var(--vscode-editorWidget-border);
      --muted: var(--vscode-descriptionForeground);
      --critical: #c62828;
      --elevated: #ef6c00;
      --low: #2e7d32;
    }
    body {
      background: radial-gradient(circle at top right, rgba(56, 142, 60, 0.12), transparent 40%), var(--bg);
      color: var(--fg);
      font-family: Consolas, "Courier New", monospace;
      margin: 0;
      padding: 16px;
    }
    .risk-card {
      border: 1px solid var(--border);
      border-left: 6px solid;
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 16px;
      background: color-mix(in srgb, var(--bg) 90%, white 10%);
    }
    .risk-card.critical { border-left-color: var(--critical); }
    .risk-card.elevated { border-left-color: var(--elevated); }
    .risk-card.low { border-left-color: var(--low); }
    h1, h2 {
      margin: 0 0 8px 0;
      font-size: 16px;
    }
    .meta {
      color: var(--muted);
      margin-bottom: 10px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .actions {
      display: flex;
      gap: 8px;
      margin: 12px 0 18px 0;
    }
    button {
      border: 1px solid var(--border);
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border-radius: 6px;
      padding: 6px 10px;
      cursor: pointer;
    }
    button.secondary {
      background: transparent;
      color: var(--fg);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 16px;
      table-layout: fixed;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 6px;
      text-align: left;
      vertical-align: top;
      word-wrap: break-word;
      overflow-wrap: anywhere;
      font-size: 12px;
    }
    th {
      background: color-mix(in srgb, var(--bg) 80%, white 20%);
    }
  </style>
</head>
<body>
  <div class="risk-card ${riskClass}">
    <h1>${escapeHtml(result.extension.name)} (${escapeHtml(result.extension.id)})</h1>
    <div class="meta">Version: ${escapeHtml(result.extension.version)}
Risk: ${escapeHtml(result.riskLevel.toUpperCase())}
${escapeHtml(result.riskExplanation)}</div>
  </div>

  <div class="actions">
    <button id="manage-btn">Open Extension in Marketplace View</button>
    <button id="disable-btn" class="secondary">Guide: Disable Extension</button>
  </div>

  <h2>Threat Intel Matches</h2>
  <table>
    <thead>
      <tr><th>Type</th><th>Severity</th><th>Reason</th><th>Reference</th></tr>
    </thead>
    <tbody>${intelRows}</tbody>
  </table>

  <h2>Heuristic Findings</h2>
  <table>
    <thead>
      <tr><th>Rule</th><th>Category</th><th>Severity</th><th>Description</th><th>File</th><th>Action</th></tr>
    </thead>
    <tbody>${findingRows}</tbody>
  </table>

  <script>
    const vscode = acquireVsCodeApi();

    document.querySelectorAll('.open-link').forEach((link) => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const url = e.target.getAttribute('data-url');
        vscode.postMessage({ command: 'openUrl', url });
      });
    });

    document.getElementById('manage-btn').addEventListener('click', () => {
      vscode.postMessage({ command: 'manageExtension' });
    });

    document.getElementById('disable-btn').addEventListener('click', () => {
      vscode.postMessage({ command: 'disableExtension' });
    });

    document.querySelectorAll('.finding-open').forEach((btn) => {
      btn.addEventListener('click', () => {
        vscode.postMessage({
          command: 'openFindingLocation',
          filePath: btn.getAttribute('data-file'),
          line: Number(btn.getAttribute('data-line') || '1')
        });
      });
    });

    document.querySelectorAll('.finding-copy').forEach((btn) => {
      btn.addEventListener('click', () => {
        const finding = {
          ruleId: btn.getAttribute('data-rule-id') || '',
          type: btn.getAttribute('data-type') || '',
          severity: btn.getAttribute('data-severity') || '',
          description: btn.getAttribute('data-description') || '',
          filePath: btn.getAttribute('data-file') || '',
          line: Number(btn.getAttribute('data-line') || '1')
        };

        vscode.postMessage({ command: 'copyFindingJson', finding });
      });
    });
  </script>
</body>
</html>`;
  }
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeHtmlAttr(value: string): string {
  return escapeHtml(value).replace(/`/g, "&#96;");
}
