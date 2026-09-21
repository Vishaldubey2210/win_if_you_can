import * as vscode from 'vscode';
import { SlopguardClient } from './services/slopguardClient';
import { CliClient } from './services/cliClient';
import { ScanManager } from './services/scanManager';
import { ScanCoordinator } from './services/scanCoordinator';
import { ScanCache } from './services/scanCache';
import { EngineManager } from './services/engineManager';
import { WatcherService } from './services/watcherService';
import { NotificationService } from './services/notificationService';
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
let engineManager: EngineManager;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    outputChannel = vscode.window.createOutputChannel('SLOPGUARD');
    const version = context.extension?.packageJSON?.version || '0.1.2';
    outputChannel.appendLine(`[SLOPGUARD] Activating Always-On AI Dependency Firewall v${version}...`);

    // 1. Initialize Engine Manager & Clients
    const config = vscode.workspace.getConfiguration('slopguard');
    const serverUrl = config.get<string>('serverUrl') || config.get<string>('server.url', 'http://localhost:8000');
    const cliPath = config.get<string>('cliPath') || config.get<string>('cli.path', 'slopguard');

    engineManager = new EngineManager(outputChannel);
    context.subscriptions.push(engineManager);

    const restClient = new SlopguardClient(serverUrl);
    const cliClient = new CliClient(cliPath, outputChannel);
    const scanCache = new ScanCache(15);
    const scanManager = new ScanManager(restClient, cliClient, scanCache, outputChannel);
    const scanCoordinator = new ScanCoordinator(engineManager, scanManager, outputChannel);

    context.subscriptions.push(scanCoordinator);

    const notificationService = new NotificationService(context);

    // 2. Providers & UI Surfaces
    const diagnosticsProvider = new DiagnosticsProvider(scanManager);
    const depTreeProvider = new DependencyTreeProvider(scanManager);
    const phantomsTreeProvider = new PhantomsTreeProvider(restClient);
    const statusBarProvider = new StatusBarProvider(scanManager, engineManager);

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

    // 5. Connect Security Notifications
    context.subscriptions.push(
        scanManager.onScanCompleted(({ result }) => {
            notificationService.handleScanResult(result);
        })
    );

    // 6. Initialize File Watchers (manifests, saves, new files, periodic reverification)
    const watcherService = new WatcherService(scanManager, scanCoordinator, outputChannel);
    context.subscriptions.push(watcherService);

    // 7. Watch Configuration Changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration('slopguard')) {
                const updatedConfig = vscode.workspace.getConfiguration('slopguard');
                const newCliPath = updatedConfig.get<string>('cliPath') || updatedConfig.get<string>('cli.path', 'slopguard');
                cliClient.updateCliPath(newCliPath);
                engineManager.reloadConfiguration();
            }
        })
    );

    // 8. Non-blocking Background Engine Auto-Start & Startup Workspace Scan
    statusBarProvider.setStarting();

    (async () => {
        try {
            const engineReady = await engineManager.ensureRunning();
            if (engineReady) {
                outputChannel.appendLine('[SLOPGUARD] Engine connection established.');
                notificationService.checkFirstRun();

                // Flush pending scans accumulated during startup
                await scanCoordinator.flushPendingScans();

                const autoScanConfig = vscode.workspace.getConfiguration('slopguard');
                const onStartup = autoScanConfig.get<boolean>('autoScan.onStartup', true) &&
                                  autoScanConfig.get<boolean>('autoScan.enabled', true);

                if (onStartup && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
                    outputChannel.appendLine('[SLOPGUARD] Starting automated background workspace scan...');
                    statusBarProvider.setScanning();
                    await scanManager.scanWorkspace();
                } else if (vscode.window.activeTextEditor) {
                    const activeDoc = vscode.window.activeTextEditor.document;
                    if (scanManager.detectLanguage(activeDoc.uri.fsPath)) {
                        await scanCoordinator.requestScan(activeDoc);
                    }
                }
            } else {
                outputChannel.appendLine('[SLOPGUARD] Warning: Engine could not be started automatically.');
                statusBarProvider.setEngineError();
            }
        } catch (err: any) {
            outputChannel.appendLine(`[SLOPGUARD ERROR] Startup initialization error: ${err.message}`);
            statusBarProvider.setEngineError();
        }
    })();

    outputChannel.appendLine('[SLOPGUARD] Always-On AI Dependency Firewall activated successfully.');
}

export function deactivate(): void {
    if (engineManager) {
        engineManager.stopEngine();
    }
    if (outputChannel) {
        outputChannel.appendLine('[SLOPGUARD] Extension deactivated.');
        outputChannel.dispose();
    }
}
