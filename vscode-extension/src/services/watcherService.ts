import * as vscode from 'vscode';
import * as path from 'path';
import { ScanManager } from './scanManager';
import { ScanCoordinator } from './scanCoordinator';

export class WatcherService implements vscode.Disposable {
    private scanManager: ScanManager;
    private scanCoordinator: ScanCoordinator;
    private outputChannel: vscode.OutputChannel;
    private disposables: vscode.Disposable[] = [];
    private debounceTimers: Map<string, NodeJS.Timeout> = new Map();
    private periodicTimer?: NodeJS.Timeout;

    constructor(
        scanManager: ScanManager,
        scanCoordinator: ScanCoordinator,
        outputChannel: vscode.OutputChannel
    ) {
        this.scanManager = scanManager;
        this.scanCoordinator = scanCoordinator;
        this.outputChannel = outputChannel;
        this.setupWatchers();
        this.setupPeriodicScanner();
    }

    private debounce(key: string, delayMs: number): Promise<void> {
        if (this.debounceTimers.has(key)) {
            clearTimeout(this.debounceTimers.get(key)!);
            this.debounceTimers.delete(key);
        }

        return new Promise<void>((resolve) => {
            const timer = setTimeout(() => {
                this.debounceTimers.delete(key);
                resolve();
            }, delayMs);
            this.debounceTimers.set(key, timer);
        });
    }

    private isExcluded(filePath: string): boolean {
        const config = vscode.workspace.getConfiguration('slopguard');
        const defaultExcludes = [
            'node_modules',
            '.venv',
            'venv',
            '.git',
            'dist',
            'build',
            '__pycache__',
            'coverage',
            '.pytest_cache'
        ];
        const normalized = filePath.replace(/\\/g, '/');
        return defaultExcludes.some(ex => normalized.includes(`/${ex}/`) || normalized.startsWith(`${ex}/`));
    }

    private setupWatchers(): void {
        const config = vscode.workspace.getConfiguration('slopguard');
        const masterEnabled = config.get<boolean>('autoScan.enabled', true);
        if (!masterEnabled) {
            return;
        }

        // 1. Dependency Manifest Watchers
        const watchManifests = config.get<boolean>('autoScan.watchManifests', true);
        if (watchManifests) {
            const manifestPatterns = [
                '**/requirements.txt',
                '**/requirements-*.txt',
                '**/pyproject.toml',
                '**/package.json',
                '**/package-lock.json',
                '**/yarn.lock',
                '**/pnpm-lock.yaml',
                '**/Pipfile',
                '**/Pipfile.lock'
            ];

            for (const pattern of manifestPatterns) {
                const watcher = vscode.workspace.createFileSystemWatcher(pattern);
                
                const handleManifestEvent = async (uri: vscode.Uri) => {
                    if (this.isExcluded(uri.fsPath)) {
                        return;
                    }
                    this.outputChannel.appendLine(`[SLOPGUARD Watcher] Manifest updated: ${uri.fsPath}. Rescanning...`);
                    try {
                        await this.scanCoordinator.requestScan(uri.fsPath);
                    } catch (err: any) {
                        this.outputChannel.appendLine(`[SLOPGUARD ERROR] Manifest scan error: ${err.message}`);
                    }
                };

                watcher.onDidChange(handleManifestEvent, null, this.disposables);
                watcher.onDidCreate(handleManifestEvent, null, this.disposables);
                this.disposables.push(watcher);
            }
        }

        // 2. New Source File Monitoring
        const watchNewFiles = config.get<boolean>('autoScan.watchNewFiles', true);
        if (watchNewFiles) {
            this.disposables.push(
                vscode.workspace.onDidCreateFiles(async (e) => {
                    for (const file of e.files) {
                        if (this.isExcluded(file.fsPath)) {
                            continue;
                        }
                        const lang = this.scanManager.detectLanguage(file.fsPath);
                        if (lang) {
                            this.outputChannel.appendLine(`[SLOPGUARD Watcher] New source file detected: ${file.fsPath}. Scanning...`);
                            try {
                                await this.scanCoordinator.requestScan(file.fsPath);
                            } catch (err: any) {
                                this.outputChannel.appendLine(`[SLOPGUARD ERROR] New file scan error: ${err.message}`);
                            }
                        }
                    }
                })
            );
        }

        // 3. Scan on File Save
        const scanOnSave = config.get<boolean>('autoScan.onSave', true) && config.get<boolean>('scanOnSave', true);
        if (scanOnSave) {
            this.disposables.push(
                vscode.workspace.onDidSaveTextDocument(async (doc) => {
                    if (this.isExcluded(doc.uri.fsPath)) {
                        return;
                    }
                    if (this.scanManager.detectLanguage(doc.uri.fsPath)) {
                        this.outputChannel.appendLine(`[SLOPGUARD] Document saved: ${doc.uri.fsPath}`);
                        this.outputChannel.appendLine(`[SLOPGUARD Watcher] Debouncing scan...`);
                        try {
                            await this.debounce(doc.uri.fsPath, 300);
                            await this.scanCoordinator.requestScan(doc, true);
                        } catch (err: any) {
                            this.outputChannel.appendLine(`[SLOPGUARD ERROR] Save scan error: ${err.message}`);
                        }
                    }
                })
            );
        }
    }

    private setupPeriodicScanner(): void {
        const config = vscode.workspace.getConfiguration('slopguard');
        const periodicEnabled = config.get<boolean>('autoScan.periodic', true);
        const intervalMinutes = config.get<number>('autoScan.intervalMinutes', 30);

        if (periodicEnabled && intervalMinutes > 0) {
            const intervalMs = Math.max(1, intervalMinutes) * 60 * 1000;
            this.outputChannel.appendLine(`[SLOPGUARD Watcher] Periodic reverification active every ${intervalMinutes} minutes.`);

            this.periodicTimer = setInterval(async () => {
                this.outputChannel.appendLine('[SLOPGUARD Watcher] Executing periodic background reverification...');
                try {
                    await this.scanManager.scanWorkspace();
                } catch (err: any) {
                    this.outputChannel.appendLine(`[SLOPGUARD Watcher] Periodic scan warning: ${err.message}`);
                }
            }, intervalMs);
        }
    }

    public dispose(): void {
        if (this.periodicTimer) {
            clearInterval(this.periodicTimer);
            this.periodicTimer = undefined;
        }
        while (this.disposables.length) {
            const d = this.disposables.pop();
            if (d) {
                d.dispose();
            }
        }
    }
}
