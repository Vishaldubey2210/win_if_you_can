import * as vscode from 'vscode';
import * as path from 'path';
import { SlopguardClient } from './slopguardClient';
import { CliClient } from './cliClient';
import { EvaluatedDependency, ScanResult, ScanSummary } from '../types/slopguard';

export class ScanManager {
    private restClient: SlopguardClient;
    private cliClient: CliClient;
    private fileResults: Map<string, ScanResult> = new Map();
    private isScanning: boolean = false;
    private onScanCompletedEmitter = new vscode.EventEmitter<{ filePath: string; result: ScanResult }>();
    private onWorkspaceScanCompletedEmitter = new vscode.EventEmitter<ScanSummary>();

    public readonly onScanCompleted = this.onScanCompletedEmitter.event;
    public readonly onWorkspaceScanCompleted = this.onWorkspaceScanCompletedEmitter.event;

    constructor(restClient: SlopguardClient, cliClient: CliClient) {
        this.restClient = restClient;
        this.cliClient = cliClient;
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

        if (base === 'requirements.txt' || base.startsWith('requirements-') || base.endsWith('.requirements.txt')) {
            return 'requirements';
        }
        if (base === 'pyproject.toml') {
            return 'pyproject';
        }
        if (base === 'package.json') {
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

        return this.executeScan(content, lang, filePath);
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
            return this.executeScan(content, lang, filePath);
        } catch (error: any) {
            throw new Error(`Failed to read file ${filePath}: ${error.message}`);
        }
    }

    private async executeScan(content: string, language: string, filePath: string): Promise<ScanResult> {
        const normalized = path.normalize(filePath);
        let result: ScanResult;

        // Try REST API first
        const isRestHealthy = await this.restClient.isHealthy();
        if (isRestHealthy) {
            result = await this.restClient.scanCode(content, language, normalized);
        } else {
            // Fallback to CLI
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
        this.fileResults.set(normalized, result);
        this.onScanCompletedEmitter.fire({ filePath: normalized, result });
        return result;
    }

    public async scanWorkspace(): Promise<ScanSummary> {
        if (this.isScanning) {
            return this.getWorkspaceSummary();
        }

        this.isScanning = true;
        this.fileResults.clear();

        try {
            const config = vscode.workspace.getConfiguration('slopguard');
            const excludes = config.get<string[]>('exclude', [
                '**/node_modules/**',
                '**/.venv/**',
                '**/dist/**',
                '**/build/**',
                '**/__pycache__/**'
            ]);
            const excludePattern = `{${excludes.join(',')}}`;

            const files = await vscode.workspace.findFiles(
                '**/*.{py,js,ts,jsx,tsx,json,toml,txt}',
                excludePattern,
                100
            );

            for (const fileUri of files) {
                const lang = this.detectLanguage(fileUri.fsPath);
                if (lang) {
                    try {
                        await this.scanFileByPath(fileUri.fsPath);
                    } catch {
                        // Continue scanning remaining files
                    }
                }
            }

            const summary = this.getWorkspaceSummary();
            this.onWorkspaceScanCompletedEmitter.fire(summary);
            return summary;
        } finally {
            this.isScanning = false;
        }
    }

    public clear(): void {
        this.fileResults.clear();
    }
}
