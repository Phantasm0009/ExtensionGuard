import * as vscode from "vscode";
import { ExtensionInfo } from "../types";

export function discoverExtensions(ignoreList: string[] = []): ExtensionInfo[] {
  const ignoreSet = new Set(ignoreList.map((id) => id.toLowerCase()));

  return vscode.extensions.all
    .map((ext) => {
      const pkg = ext.packageJSON as Record<string, unknown>;
      const contributes = (pkg?.contributes ?? {}) as Record<string, unknown>;

      return {
        id: ext.id,
        name: ext.packageJSON.displayName ?? ext.packageJSON.name ?? ext.id,
        version: ext.packageJSON.version ?? "0.0.0",
        description: ext.packageJSON.description ?? "",
        extensionPath: ext.extensionPath,
        isBuiltin: ext.id.startsWith("vscode."),
        activationEvents: (pkg?.activationEvents as string[]) ?? [],
        contributes: {
          commands: (contributes.commands as Array<{ command: string; title?: string }>) ?? [],
          configuration: contributes.configuration
        },
        main: typeof pkg?.main === "string" ? pkg.main : undefined,
        browser: typeof pkg?.browser === "string" ? pkg.browser : undefined
      } as ExtensionInfo;
    })
    .filter((ext) => !ignoreSet.has(ext.id.toLowerCase()));
}
