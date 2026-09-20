import * as vscode from 'vscode';
import { ScanManager } from '../services/scanManager';
import { ScanSummary } from '../types/slopguard';

export class StatusBarProvider implements vscode.Disposable {
    private statusBarItem: vscode.StatusBarItem;
    private scanManager: ScanManager;
    private hasScanned: boolean = false;

    constructor(scanManager: ScanManager) {
        this.scanManager = scanManager;
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            100
        );
        this.statusBarItem.command = 'slopguard.openDashboard';
        this.reset();
        this.statusBarItem.show();

        // Event bindings
        this.scanManager.onScanCompleted(() => {
            this.updateWithSummary(this.scanManager.getWorkspaceSummary());
        });

        this.scanManager.onWorkspaceScanCompleted((summary) => {
            this.updateWithSummary(summary);
        });
    }

    public setScanning(): void {
        this.statusBarItem.text = '$(sync~spin) SLOPGUARD: Scanning...';
        this.statusBarItem.tooltip = 'SLOPGUARD is evaluating dependency trust and policy gates.';
    }

    public updateWithSummary(summary: ScanSummary): void {
        this.hasScanned = true;
        const reviewCount = summary.hold_count + summary.alert_count;
        this.statusBarItem.text = `$(shield) SLOPGUARD: ${summary.allowed_count} ✓ | ${reviewCount} ⚠ | ${summary.blocked_count} 🚫`;

        if (summary.blocked_count > 0) {
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        } else if (reviewCount > 0) {
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        } else {
            this.statusBarItem.backgroundColor = undefined;
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
        this.statusBarItem.text = '$(shield) SLOPGUARD: Not scanned';
        this.statusBarItem.tooltip = 'Click to open SLOPGUARD Control Center or run a scan.';
        this.statusBarItem.backgroundColor = undefined;
    }

    public dispose(): void {
        this.statusBarItem.dispose();
    }
}
