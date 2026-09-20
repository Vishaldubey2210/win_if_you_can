import * as vscode from 'vscode';
import { ScanManager } from '../services/scanManager';
import { StatusBarProvider } from '../providers/statusBarProvider';
import { DependencyTreeProvider } from '../providers/dependencyTreeProvider';
import { PhantomsTreeProvider } from '../providers/phantomsTreeProvider';

export function registerScanCommands(
    context: vscode.ExtensionContext,
    scanManager: ScanManager,
    statusBar: StatusBarProvider,
    depTree: DependencyTreeProvider,
    phantomTree: PhantomsTreeProvider
): void {
    // 1. Scan Workspace
    context.subscriptions.push(
        vscode.commands.registerCommand('slopguard.scanWorkspace', async () => {
            statusBar.setScanning();
            vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: 'SLOPGUARD: Scanning workspace dependencies...',
                    cancellable: false
                },
                async (progress) => {
                    try {
                        const summary = await scanManager.scanWorkspace();
                        depTree.refresh();
                        phantomTree.refresh();
                        statusBar.updateWithSummary(summary);

                        const reviewCount = summary.hold_count + summary.alert_count;
                        if (summary.blocked_count > 0) {
                            vscode.window.showErrorMessage(
                                `SLOPGUARD: Scan completed. ${summary.blocked_count} blocked, ${reviewCount} review required, ${summary.allowed_count} verified safe.`
                            );
                        } else if (reviewCount > 0) {
                            vscode.window.showWarningMessage(
                                `SLOPGUARD: Scan completed. ${reviewCount} review required, ${summary.allowed_count} verified safe.`
                            );
                        } else {
                            vscode.window.showInformationMessage(
                                `SLOPGUARD: Scan completed. All ${summary.allowed_count} dependencies verified safe.`
                            );
                        }
                    } catch (error: any) {
                        vscode.window.showErrorMessage(`SLOPGUARD scan failed: ${error.message}`);
                    }
                }
            );
        })
    );

    // 2. Scan Current File
    context.subscriptions.push(
        vscode.commands.registerCommand('slopguard.scanCurrentFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showInformationMessage('No active source file open to scan.');
                return;
            }

            statusBar.setScanning();
            try {
                const result = await scanManager.scanDocument(editor.document);
                if (result) {
                    depTree.refresh();
                    phantomTree.refresh();
                    const summary = scanManager.getWorkspaceSummary();
                    statusBar.updateWithSummary(summary);

                    if (result.summary.blocked_count > 0) {
                        vscode.window.showErrorMessage(
                            `SLOPGUARD: ${result.summary.blocked_count} blocked dependencies detected in ${vscode.workspace.asRelativePath(editor.document.uri)}`
                        );
                    }
                } else {
                    vscode.window.showInformationMessage('Current file type is not supported for SLOPGUARD dependency scanning.');
                }
            } catch (error: any) {
                vscode.window.showErrorMessage(`SLOPGUARD file scan failed: ${error.message}`);
            }
        })
    );

    // 3. Rescan
    context.subscriptions.push(
        vscode.commands.registerCommand('slopguard.rescan', async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor && scanManager.detectLanguage(editor.document.uri.fsPath)) {
                await vscode.commands.executeCommand('slopguard.scanCurrentFile');
            } else {
                await vscode.commands.executeCommand('slopguard.scanWorkspace');
            }
        })
    );

    // 4. Refresh Views
    context.subscriptions.push(
        vscode.commands.registerCommand('slopguard.refresh', () => {
            depTree.refresh();
            phantomTree.refresh();
            vscode.window.showInformationMessage('SLOPGUARD views refreshed.');
        })
    );
}
