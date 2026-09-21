import * as vscode from 'vscode';
import * as path from 'path';
import { SlopguardClient } from './slopguardClient';
import { CliClient } from './cliClient';
import { ScanCache } from './scanCache';
import { EvaluatedDependency, ScanResult, ScanSummary } from '../types/slopguard';

export class ScanManager {
    private restClient: SlopguardClient;
    private cliClient: CliClient;
    private scanCache: ScanCache;
    private outputChannel?: vscode.OutputChannel;
    private fileResults: Map<string, ScanResult> = new Map();
    private isScanning: boolean = false;
    private debounceTimers: Map<string, NodeJS.Timeout> = new Map();
    private activeScansCount: number = 0;
    private readonly maxConcurrency: number = 2;
    private scanQueue: Array<() => Promise<void>> = [];

    private onScanCompletedEmitter = new vscode.EventEmitter<{ filePath: string; result: ScanResult }>();
    private onWorkspaceScanCompletedEmitter = new vscode.EventEmitter<ScanSummary>();

    public readonly onScanCompleted = this.onScanCompletedEmitter.event;
    public readonly onWorkspaceScanCompleted = this.onWorkspaceScanCompletedEmitter.event;

    constructor(
        restClient: SlopguardClient,
        cliClient: CliClient,
        scanCache?: ScanCache,
        outputChannel?: vscode.OutputChannel
    ) {
        this.restClient = restClient;
        this.cliClient = cliClient;
        this.scanCache = scanCache || new ScanCache(10);
        this.outputChannel = outputChannel;
    }

    public setOutputChannel(channel: vscode.OutputChannel): void {
        this.outputChannel = channel;
    }

    public getCache(): ScanCache {
        return this.scanCache;
    }

    public getResultForFile(filePath: string): ScanResult | undefined {
        return this.fileResults.get(path.normalize(filePath));
    }

    public getAllResults(): Map<string, ScanResult> {
        return this.fileResults;
    }

    public getAllEvaluatedDependencies(): EvaluatedDependency[] {
        const all: EvaluatedDependency[] = [];
        for (const res of this.fileResults.values()) {
            all.push(...res.dependencies);
        }
        return all;
    }

    public getWorkspaceSummary(): ScanSummary {
        let total = 0;
        let stdlib = 0;
        let allowed = 0;
        let hold = 0;
        let blocked = 0;
        let alert = 0;

        for (const res of this.fileResults.values()) {
            total += res.summary.total_extracted;
            stdlib += res.summary.stdlib_count;
            allowed += res.summary.allowed_count;
            hold += res.summary.hold_count;
            blocked += res.summary.blocked_count;
            alert += res.summary.alert_count;
        }

        return {
            total_extracted: total,
            stdlib_count: stdlib,
            allowed_count: allowed,
            hold_count: hold,
            blocked_count: blocked,
            alert_count: alert
        };
    }

    public detectLanguage(filePath: string): string | null {
        const base = path.basename(filePath).toLowerCase();
        const ext = path.extname(filePath).toLowerCase();

        if (base === 'requirements.txt' || base.startsWith('requirements-') || base.endsWith('.requirements.txt') || base === 'pipfile') {
            return 'requirements';
        }
        if (base === 'pyproject.toml') {
            return 'pyproject';
        }
        if (base === 'package.json' || base === 'package-lock.json' || base === 'yarn.lock' || base === 'pnpm-lock.yaml') {
            return 'package_json';
        }
        if (ext === '.py') {
            return 'python';
        }
        if (ext === '.js' || ext === '.jsx' || ext === '.mjs' || ext === '.cjs') {
            return 'javascript';
        }
        if (ext === '.ts' || ext === '.tsx' || ext === '.mts' || ext === '.cts') {
            return 'typescript';
        }
        return null;
    }

    /**
     * Debounced scan for document edits or file saves.
     */
    public debounceScan(document: vscode.TextDocument, delayMs: number = 300): Promise<ScanResult | null> {
        const filePath = path.normalize(document.uri.fsPath);

        // Cancel previous pending timer for this file
        if (this.debounceTimers.has(filePath)) {
            clearTimeout(this.debounceTimers.get(filePath)!);
            this.debounceTimers.delete(filePath);
        }

        return new Promise<ScanResult | null>((resolve, reject) => {
            const timer = setTimeout(async () => {
                this.debounceTimers.delete(filePath);
                try {
                    const res = await this.scanDocument(document);
                    resolve(res);
                } catch (err: any) {
                    this.outputChannel?.appendLine(`[SLOPGUARD ERROR] Debounced scan failed for ${filePath}: ${err.message}`);
                    reject(err);
                }
            }, delayMs);

            this.debounceTimers.set(filePath, timer);
        });
    }

    public async scanDocument(document: vscode.TextDocument): Promise<ScanResult | null> {
        const filePath = document.uri.fsPath;
        const lang = this.detectLanguage(filePath);
        if (!lang) {
            return null;
        }

        const content = document.getText();
        if (content.length > 10 * 1024 * 1024) {
            throw new Error('File exceeds maximum SLOPGUARD scan size limit (10MB)');
        }

        return this.enqueueScan(() => this.executeScan(content, lang, filePath));
    }

    public async scanFileByPath(filePath: string): Promise<ScanResult | null> {
        const lang = this.detectLanguage(filePath);
        if (!lang) {
            return null;
        }

        try {
            const uri = vscode.Uri.file(filePath);
            const rawBytes = await vscode.workspace.fs.readFile(uri);
            const content = Buffer.from(rawBytes).toString('utf-8');
            if (content.length > 10 * 1024 * 1024) {
                return null;
            }
            return this.enqueueScan(() => this.executeScan(content, lang, filePath));
        } catch (error: any) {
            this.outputChannel?.appendLine(`[SLOPGUARD ERROR] Failed to read file ${filePath}: ${error.message}`);
            throw new Error(`Failed to read file ${filePath}: ${error.message}`);
        }
    }

    private enqueueScan(scanFn: () => Promise<ScanResult>): Promise<ScanResult> {
        return new Promise<ScanResult>((resolve, reject) => {
            const task = async () => {
                this.activeScansCount++;
                try {
                    const result = await scanFn();
                    resolve(result);
                } catch (err) {
                    reject(err);
                } finally {
                    this.activeScansCount--;
                    this.processQueue();
                }
            };

            if (this.activeScansCount < this.maxConcurrency) {
                task();
            } else {
                this.scanQueue.push(task);
            }
        });
    }

    private processQueue(): void {
        while (this.activeScansCount < this.maxConcurrency && this.scanQueue.length > 0) {
            const nextTask = this.scanQueue.shift();
            if (nextTask) {
                nextTask();
            }
        }
    }

    private async executeScan(content: string, language: string, filePath: string): Promise<ScanResult> {
        const normalized = path.normalize(filePath);
        this.outputChannel?.appendLine(`[SLOPGUARD] Scanning: ${normalized}`);

        // 1. Intelligent Cache Check
        const cached = this.scanCache.get(normalized, content);
        if (cached) {
            this.fileResults.set(normalized, cached);
            this.outputChannel?.appendLine(`[SLOPGUARD] Parsed dependency results: ${cached.dependencies.length} dependencies (cached).`);
            this.outputChannel?.appendLine(`[SLOPGUARD] Publishing diagnostics: ${normalized}`);
            this.onScanCompletedEmitter.fire({ filePath: normalized, result: cached });
            this.outputChannel?.appendLine('[SLOPGUARD] Scan completed.');
            return cached;
        }

        let result: ScanResult;

        try {
            // 2. Try REST API first
            const isRestHealthy = await this.restClient.isHealthy();
            if (isRestHealthy) {
                result = await this.restClient.scanCode(content, language, normalized);
            } else {
                // 3. Fallback to CLI
                const isCliAvailable = await this.cliClient.isAvailable();
                if (isCliAvailable) {
                    const config = vscode.workspace.getConfiguration('slopguard');
                    const profile = config.get<string>('policyProfile', 'STRICT_CI');
                    result = await this.cliClient.scanFile(normalized, profile);
                } else {
                    throw new Error(
                        'SLOPGUARD service is unavailable. Neither the REST API (http://localhost:8000) nor the CLI executable (slopguard) could be reached.'
                    );
                }
            }

            result.file_path = normalized;
            result.language = language;

            // Store in scan cache and file results
            this.scanCache.set(normalized, content, result);
            this.fileResults.set(normalized, result);
            this.outputChannel?.appendLine(`[SLOPGUARD] Parsed dependency results: ${result.dependencies.length} dependencies.`);
            this.outputChannel?.appendLine(`[SLOPGUARD] Publishing diagnostics: ${normalized}`);
            this.onScanCompletedEmitter.fire({ filePath: normalized, result });
            this.outputChannel?.appendLine('[SLOPGUARD] Scan completed.');
            return result;
        } catch (err: any) {
            this.outputChannel?.appendLine(`[SLOPGUARD ERROR] Scan execution failed for ${normalized}: ${err.message}`);
            throw err;
        }
    }

    public async scanWorkspace(): Promise<ScanSummary> {
        if (this.isScanning) {
            return this.getWorkspaceSummary();
        }

        this.isScanning = true;
        this.fileResults.clear();
        this.outputChannel?.appendLine('[SLOPGUARD] Workspace scan started.');

        try {
            const config = vscode.workspace.getConfiguration('slopguard');
            const defaultExcludes = [
                '**/.git/**',
                '**/node_modules/**',
                '**/.venv/**',
                '**/venv/**',
                '**/dist/**',
                '**/build/**',
                '**/__pycache__/**',
                '**/coverage/**',
                '**/.pytest_cache/**'
            ];
            const excludes = config.get<string[]>('autoScan.excludePatterns', defaultExcludes);
            const excludePattern = `{${excludes.join(',')}}`;

            const files = await vscode.workspace.findFiles(
                '**/*.{py,js,ts,jsx,tsx,json,toml,txt,Pipfile}',
                excludePattern,
                150
            );

            for (const fileUri of files) {
                const lang = this.detectLanguage(fileUri.fsPath);
                if (lang) {
                    try {
                        this.outputChannel?.appendLine(`[SLOPGUARD] Scanning ${path.basename(fileUri.fsPath)}.`);
                        await this.scanFileByPath(fileUri.fsPath);
                    } catch (err: any) {
                        this.outputChannel?.appendLine(`[SLOPGUARD ERROR] Failed scanning ${fileUri.fsPath}: ${err.message}`);
                    }
                }
            }

            const summary = this.getWorkspaceSummary();
            this.outputChannel?.appendLine(`[SLOPGUARD] Workspace scan completed. Scanned ${files.length} files. Total extracted: ${summary.total_extracted}, Blocked: ${summary.blocked_count}, Hold: ${summary.hold_count}, Allowed: ${summary.allowed_count}.`);
            this.onWorkspaceScanCompletedEmitter.fire(summary);
            return summary;
        } finally {
            this.isScanning = false;
        }
    }

    public clear(): void {
        this.fileResults.clear();
        this.scanCache.clear();
        for (const timer of this.debounceTimers.values()) {
            clearTimeout(timer);
        }
        this.debounceTimers.clear();
    }
}
