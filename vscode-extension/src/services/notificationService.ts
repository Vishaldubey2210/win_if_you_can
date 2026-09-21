import * as vscode from 'vscode';
import { EvaluatedDependency, PhantomState, PolicyAction, ScanResult } from '../types/slopguard';

export class NotificationService {
    private context: vscode.ExtensionContext;
    private lastBlockNotifyTime: number = 0;
    private notifiedPhantoms: Set<string> = new Set();

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    /**
     * Shows a single, elegant first-run notification on initial install.
     */
    public checkFirstRun(): void {
        const hasShown = this.context.globalState.get<boolean>('slopguard.hasShownFirstRunNotice', false);
        if (!hasShown) {
            vscode.window.showInformationMessage(
                'SLOPGUARD is active. Your workspace will now be scanned automatically for AI-generated dependency risks.',
                'Open Control Center'
            ).then(selection => {
                if (selection === 'Open Control Center') {
                    vscode.commands.executeCommand('slopguard.openDashboard');
                }
            });
            this.context.globalState.update('slopguard.hasShownFirstRunNotice', true);
        }
    }

    /**
     * Inspects scan results and alerts user strictly on security-relevant events.
     */
    public handleScanResult(scanResult: ScanResult): void {
        const blockedCount = scanResult.summary.blocked_count;
        const now = Date.now();

        // 1. Notify on Blocked dependencies (debounced by 10s cooldown to prevent notification fatigue)
        if (blockedCount > 0 && now - this.lastBlockNotifyTime > 10000) {
            this.lastBlockNotifyTime = now;
            vscode.window.showErrorMessage(
                `SLOPGUARD: Blocked ${blockedCount} unverified / high-risk dependency(ies).`,
                'View Problems',
                'Inspect Evidence'
            ).then(choice => {
                if (choice === 'View Problems') {
                    vscode.commands.executeCommand('workbench.actions.view.problems');
                } else if (choice === 'Inspect Evidence') {
                    vscode.commands.executeCommand('slopguard.showEvidence');
                }
            });
        }

        // 2. Check for Critical Advisories & Phantom State Changes
        for (const dep of scanResult.dependencies) {
            // Phantom Appeared
            if (dep.phantom_state === PhantomState.APPEARED && !this.notifiedPhantoms.has(dep.extracted.name)) {
                this.notifiedPhantoms.add(dep.extracted.name);
                vscode.window.showWarningMessage(
                    `SLOPGUARD Alert: Dependency '${dep.extracted.name}' was previously an unresolvable phantom and has recently appeared on the registry. Review required.`,
                    'Inspect Dossier'
                ).then(choice => {
                    if (choice === 'Inspect Dossier') {
                        vscode.commands.executeCommand('slopguard.showEvidence');
                    }
                });
            }

            // Critical Security Advisories
            const highestAdv = dep.trust?.signals?.release_signals?.highest_advisory_severity;
            if (highestAdv === 'CRITICAL' && dep.decision.action === PolicyAction.BLOCK) {
                vscode.window.showErrorMessage(
                    `SLOPGUARD: Critical security advisory match for '${dep.extracted.name}'. Policy blocked installation.`,
                    'Find Repair'
                ).then(choice => {
                    if (choice === 'Find Repair') {
                        vscode.commands.executeCommand('slopguard.findRepair');
                    }
                });
            }
        }
    }
}
