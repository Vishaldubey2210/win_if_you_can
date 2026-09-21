import * as vscode from 'vscode';
import { ScanManager } from '../services/scanManager';
import { EvaluatedDependency, PolicyAction, extractSuggestedTarget } from '../types/slopguard';
import { WebviewDetailProvider } from '../views/webviewDetailProvider';
import { DependencyTreeItem } from '../providers/dependencyTreeProvider';

export function registerRepairCommands(
    context: vscode.ExtensionContext,
    scanManager: ScanManager
): void {
    context.subscriptions.push(
        vscode.commands.registerCommand('slopguard.findRepair', async (itemOrDep?: DependencyTreeItem | EvaluatedDependency) => {
            let dep: EvaluatedDependency | undefined;

            if (itemOrDep && 'depData' in itemOrDep && itemOrDep.depData) {
                dep = itemOrDep.depData;
            } else if (itemOrDep && 'decision' in itemOrDep) {
                dep = itemOrDep as EvaluatedDependency;
            } else {
                // Find all scanned dependencies with repairs or typosquat candidates
                const candidates = scanManager.getAllEvaluatedDependencies().filter(d => 
                    extractSuggestedTarget(d) !== undefined
                );
                if (candidates.length === 0) {
                    vscode.window.showInformationMessage('No active dependencies have pending repair suggestions.');
                    return;
                }

                const pick = await vscode.window.showQuickPick(
                    candidates.map(d => {
                        const repairInfo = extractSuggestedTarget(d)!;
                        return {
                            label: `Replace ${d.extracted.name} → ${repairInfo.target}`,
                            description: `[${d.decision.action}] Confidence: ${(d.decision.confidence * 100).toFixed(0)}% (${repairInfo.reason})`,
                            dep: d,
                            target: repairInfo.target
                        };
                    }),
                    { placeHolder: 'Select dependency to repair' }
                );

                if (pick) {
                    dep = pick.dep;
                }
            }

            if (dep) {
                const repairInfo = extractSuggestedTarget(dep);
                const target = repairInfo?.target;

                if (target) {
                    const choice = await vscode.window.showInformationMessage(
                        `SLOPGUARD Repair: Replace '${dep.extracted.name}' with verified package '${target}'?`,
                        'Apply & Rescan',
                        'Open Evidence Dossier',
                        'Cancel'
                    );

                    if (choice === 'Apply & Rescan') {
                        const editor = vscode.window.activeTextEditor;
                        if (editor) {
                            const oldName = dep.extracted.name;
                            const text = editor.document.getText();
                            const index = text.indexOf(oldName);
                            if (index !== -1) {
                                const posStart = editor.document.positionAt(index);
                                const posEnd = editor.document.positionAt(index + oldName.length);
                                await editor.edit(builder => builder.replace(new vscode.Range(posStart, posEnd), target));
                                await vscode.commands.executeCommand('slopguard.scanCurrentFile');
                                vscode.window.showInformationMessage(`Applied repair '${target}' and triggered rescan.`);
                                return;
                            }
                        }
                        vscode.window.showWarningMessage(`Could not locate '${dep.extracted.name}' in active editor.`);
                    } else if (choice === 'Open Evidence Dossier') {
                        WebviewDetailProvider.show(context.extensionUri, dep);
                    }
                } else {
                    vscode.window.showInformationMessage(`No automatic repair suggestions available for '${dep.extracted.name}'.`);
                    WebviewDetailProvider.show(context.extensionUri, dep);
                }
            }
        })
    );
}
