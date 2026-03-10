import * as vscode from "vscode";
import { ScanResult } from "../types";

const CACHE_KEY = "extensionShield.scanCache";

type CacheStore = Record<string, ScanResult>;

export function getCachedResult(context: vscode.ExtensionContext, extensionId: string, version: string): ScanResult | null {
  const store = context.globalState.get<CacheStore>(CACHE_KEY, {});
  const key = `${extensionId}@${version}`;
  return store[key] ?? null;
}

export async function setCachedResult(
  context: vscode.ExtensionContext,
  extensionId: string,
  version: string,
  result: ScanResult
): Promise<void> {
  const store = context.globalState.get<CacheStore>(CACHE_KEY, {});
  store[`${extensionId}@${version}`] = result;
  await context.globalState.update(CACHE_KEY, store);
}
