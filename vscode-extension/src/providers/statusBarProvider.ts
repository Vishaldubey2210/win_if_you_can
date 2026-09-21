import * as vscode from 'vscode';
import { ScanManager } from '../services/scanManager';
import { EngineManager, EngineConnectionStatus } from '../services/engineManager';
import { ScanSummary } from '../types/slopguard';

export class StatusBarProvider implements vscode.Disposable {
    private statusBarItem: vscode.StatusBarItem;
    private scanManager: ScanManager;
    private engineManager?: EngineManager;
    private hasScanned: boolean = false;
    private currentSummary?: ScanSummary;

    constructor(scanManager: ScanManager, engineManager?: EngineManager) {
        this.scanManager = scanManager;
        this.engineManager = engineManager;
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            100
        );
        this.statusBarItem.command = 'slopguard.openDashboard';
        this.setStarting();
        this.statusBarItem.show();

        // Bind scan events
        this.scanManager.onScanCompleted(() => {
            this.updateWithSummary(this.scanManager.getWorkspaceSummary());
        });

        this.scanManager.onWorkspaceScanCompleted((summary) => {
            this.updateWithSummary(summary);
        });

        // Bind engine status events
        if (this.engineManager) {
            this.engineManager.onDidChangeStatus((status) => {
                if (status === EngineConnectionStatus.STARTING || status === EngineConnectionStatus.INITIALIZING) {
                    this.setStarting();
                } else if (status === EngineConnectionStatus.ERROR || status === EngineConnectionStatus.UNAVAILABLE) {
                    this.setEngineError();
                } else if (
                    status === EngineConnectionStatus.READY ||
                    status === EngineConnectionStatus.RUNNING_REST ||
                    status === EngineConnectionStatus.CLI_FALLBACK
                ) {
                    if (this.currentSummary) {
                        this.updateWithSummary(this.currentSummary);
                    } else {
                        this.setProtected(status === EngineConnectionStatus.CLI_FALLBACK);
                    }
                }
            });
        }
    }

    public setStarting(): void {
        this.statusBarItem.text = '$(sync~spin) SLOPGUARD: Starting';
        this.statusBarItem.tooltip = 'SLOPGUARD AI Firewall engine is starting up in the background.';
        this.statusBarItem.backgroundColor = undefined;
    }

    public setScanning(): void {
        this.statusBarItem.text = '$(sync~spin) SLOPGUARD: Scanning';
        this.statusBarItem.tooltip = 'SLOPGUARD is evaluating workspace dependency trust and policy gates.';
        this.statusBarItem.backgroundColor = undefined;
    }

    public setProtected(isCliFallback: boolean = false): void {
        const mode = isCliFallback ? ' (CLI)' : '';
        this.statusBarItem.text = `$(shield) SLOPGUARD: Protected${mode}`;
        this.statusBarItem.tooltip = `SLOPGUARD AI Dependency Firewall is active and monitoring workspace dependencies.`;
        this.statusBarItem.backgroundColor = undefined;
    }

    public setEngineError(): void {
        this.statusBarItem.text = '$(alert) SLOPGUARD: Error';
        this.statusBarItem.tooltip = 'SLOPGUARD could not connect to REST API or CLI executable. Click to configure.';
        this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    }

    public updateWithSummary(summary: ScanSummary): void {
        this.hasScanned = true;
        this.currentSummary = summary;
        const reviewCount = summary.hold_count + summary.alert_count;

        if (summary.blocked_count > 0) {
            this.statusBarItem.text = `$(error) SLOPGUARD: Blocked (${summary.blocked_count})`;
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        } else if (reviewCount > 0) {
            this.statusBarItem.text = `$(warning) SLOPGUARD: Review (${reviewCount})`;
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        } else {
            this.setProtected();
        }

        this.statusBarItem.tooltip = new vscode.MarkdownString(
            `### SLOPGUARD Security Status\n\n` +
            `- **Verified Safe**: ${summary.allowed_count}\n` +
            `- **Review Required**: ${reviewCount}\n` +
            `- **Blocked (Untrusted / Phantom)**: ${summary.blocked_count}\n` +
            `- **Total Extracted**: ${summary.total_extracted}\n\n` +
            `*Click to open SLOPGUARD Control Center.*`
        );
    }

    public reset(): void {
        this.hasScanned = false;
        this.currentSummary = undefined;
        this.setStarting();
    }

    public dispose(): void {
        this.statusBarItem.dispose();
    }
}
