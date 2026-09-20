import * as vscode from 'vscode';
import { SlopguardClient } from './services/slopguardClient';
import { CliClient } from './services/cliClient';
import { ScanManager } from './services/scanManager';
import { DiagnosticsProvider } from './providers/diagnosticsProvider';
import { DependencyTreeProvider } from './providers/dependencyTreeProvider';
import { PhantomsTreeProvider } from './providers/phantomsTreeProvider';
import { StatusBarProvider } from './providers/statusBarProvider';
import { QuickFixProvider } from './providers/quickFixProvider';
import { registerScanCommands } from './commands/scanCommands';
import { registerEvidenceCommands } from './commands/evidenceCommands';
import { registerRepairCommands } from './commands/repairCommands';
import { registerDashboardCommands } from './commands/dashboardCommands';

let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext): void {
    outputChannel = vscode.window.createOutputChannel('SLOPGUARD');
    outputChannel.appendLine('[SLOPGUARD] Activating AI Dependency Firewall extension v0.1.0...');

    // 1. Initialize Clients & Services
    const config = vscode.workspace.getConfiguration('slopguard');
    const serverUrl = config.get<string>('server.url', 'http://localhost:8000');
    const cliPath = config.get<string>('cli.path', 'slopguard');

    const restClient = new SlopguardClient(serverUrl);
    const cliClient = new CliClient(cliPath);
    const scanManager = new ScanManager(restClient, cliClient);

    // 2. Providers
    const diagnosticsProvider = new DiagnosticsProvider(scanManager);
    const depTreeProvider = new DependencyTreeProvider(scanManager);
    const phantomsTreeProvider = new PhantomsTreeProvider(restClient);
    const statusBarProvider = new StatusBarProvider(scanManager);

    context.subscriptions.push(
        diagnosticsProvider,
        statusBarProvider,
        vscode.window.registerTreeDataProvider('slopguard.dependenciesView', depTreeProvider),
        vscode.window.registerTreeDataProvider('slopguard.phantomsView', phantomsTreeProvider)
    );

    // 3. Quick Fixes / Code Actions
    const supportedLanguages = [
        'python',
        'javascript',
        'typescript',
        'javascriptreact',
        'typescriptreact'
    ];
    for (const lang of supportedLanguages) {
        context.subscriptions.push(
            vscode.languages.registerCodeActionsProvider(
                { language: lang },
                new QuickFixProvider(),
                {
                    providedCodeActionKinds: QuickFixProvider.providedCodeActionKinds
                }
            )
        );
    }

    // 4. Register Commands
    registerScanCommands(context, scanManager, statusBarProvider, depTreeProvider, phantomsTreeProvider);
    registerEvidenceCommands(context, restClient, scanManager);
    registerRepairCommands(context, scanManager);
    registerDashboardCommands(context);

    // 5. File Watchers / Auto-scan hooks
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc) => {
            const currentConfig = vscode.workspace.getConfiguration('slopguard');
            if (currentConfig.get<boolean>('scanOnSave', true)) {
                if (scanManager.detectLanguage(doc.uri.fsPath)) {
                    outputChannel.appendLine(`[SLOPGUARD] Auto-scanning saved document: ${doc.uri.fsPath}`);
                    try {
                        await scanManager.scanDocument(doc);
                    } catch (err: any) {
                        outputChannel.appendLine(`[SLOPGUARD] Auto-scan error: ${err.message}`);
                    }
                }
            }
        })
    );

    // Auto-scan current active editor on startup if available
    if (config.get<boolean>('autoScan', true)) {
        if (vscode.window.activeTextEditor) {
            const activeDoc = vscode.window.activeTextEditor.document;
            if (scanManager.detectLanguage(activeDoc.uri.fsPath)) {
                outputChannel.appendLine(`[SLOPGUARD] Initial active file auto-scan: ${activeDoc.uri.fsPath}`);
                scanManager.scanDocument(activeDoc).catch(err => {
                    outputChannel.appendLine(`[SLOPGUARD] Initial auto-scan warning: ${err.message}`);
                });
            }
        }
    }

    outputChannel.appendLine('[SLOPGUARD] Extension activated successfully.');
}

export function deactivate(): void {
    if (outputChannel) {
        outputChannel.appendLine('[SLOPGUARD] Extension deactivating.');
        outputChannel.dispose();
    }
}
