import * as vscode from 'vscode';
import { SlopguardClient } from '../services/slopguardClient';
import { ScanManager } from '../services/scanManager';
import { EvaluatedDependency, PolicyAction, RegistryStatus } from '../types/slopguard';
import { WebviewDetailProvider } from '../views/webviewDetailProvider';
import { DependencyTreeItem } from '../providers/dependencyTreeProvider';

export function registerEvidenceCommands(
    context: vscode.ExtensionContext,
    restClient: SlopguardClient,
    scanManager: ScanManager
): void {
    // 1. Show Evidence
    context.subscriptions.push(
        vscode.commands.registerCommand('slopguard.showEvidence', async (itemOrDep?: DependencyTreeItem | EvaluatedDependency) => {
            let dep: EvaluatedDependency | undefined;

            if (itemOrDep && 'depData' in itemOrDep && itemOrDep.depData) {
                dep = itemOrDep.depData;
            } else if (itemOrDep && 'decision' in itemOrDep) {
                dep = itemOrDep as EvaluatedDependency;
            } else {
                // Prompt user to choose from scanned dependencies
                const all = scanManager.getAllEvaluatedDependencies();
                if (all.length === 0) {
                    vscode.window.showInformationMessage('No dependencies scanned yet. Run a workspace or file scan first.');
                    return;
                }

                const pick = await vscode.window.showQuickPick(
                    all.map(d => ({
                        label: `${d.decision.action === PolicyAction.BLOCK ? '🚫' : d.decision.action === PolicyAction.ALLOW ? '✅' : '⚠️'} ${d.extracted.name}`,
                        description: `[${d.decision.action}] Canonical: ${d.identity.resolved_package}`,
                        dep: d
                    })),
                    { placeHolder: 'Select dependency to view SLOPGUARD evidence dossier' }
                );

                if (pick) {
                    dep = pick.dep;
                }
            }

            if (dep) {
                WebviewDetailProvider.show(context.extensionUri, dep);
            }
        })
    );

    // 2. Show Dependency History
    context.subscriptions.push(
        vscode.commands.registerCommand('slopguard.showDependencyHistory', async (itemOrDep?: DependencyTreeItem | EvaluatedDependency) => {
            await vscode.commands.executeCommand('slopguard.showEvidence', itemOrDep);
        })
    );

    // 3. Verify Single Dependency
    context.subscriptions.push(
        vscode.commands.registerCommand('slopguard.verifyDependency', async () => {
            const pkgName = await vscode.window.showInputBox({
                prompt: 'Enter package name to verify through SLOPGUARD control plane',
                placeHolder: 'e.g. requests, tensorflow, phantom_pkg'
            });

            if (!pkgName || pkgName.trim() === '') {
                return;
            }

            const ecoPick = await vscode.window.showQuickPick(
                ['pypi', 'npm'],
                { placeHolder: 'Select registry ecosystem' }
            );

            const ecosystem = ecoPick || 'pypi';

            vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: `SLOPGUARD: Verifying ${pkgName} against ${ecosystem}...`,
                    cancellable: false
                },
                async () => {
                    try {
                        const verified = await restClient.verifyPackage(pkgName.trim(), ecosystem);
                        const isFound = verified.status === RegistryStatus.FOUND;
                        const statusMsg = isFound
                            ? `Package '${pkgName}' verified exists on ${ecosystem} (latest: ${verified.latest_version || 'N/A'}).`
                            : `Package '${pkgName}' status: ${verified.status} on ${ecosystem}.`;

                        if (isFound) {
                            vscode.window.showInformationMessage(statusMsg);
                        } else {
                            vscode.window.showWarningMessage(statusMsg);
                        }
                    } catch (err: any) {
                        vscode.window.showErrorMessage(`Verification failed: ${err.message}`);
                    }
                }
            );
        })
    );
}
