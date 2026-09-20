import * as vscode from 'vscode';
import { ScanManager } from '../services/scanManager';
import { EvaluatedDependency, PolicyAction, IdentityStatus, ScanSummary } from '../types/slopguard';

export class DependencyTreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly depData?: EvaluatedDependency,
        public readonly categoryType?: 'overview' | 'blocked' | 'hold' | 'allowed',
        public readonly summaryData?: ScanSummary
    ) {
        super(label, collapsibleState);
        this.setupItem();
    }

    private setupItem(): void {
        if (this.depData) {
            this.contextValue = 'slopguardDependency';
            const dep = this.depData;
            const isAlias = dep.identity.status === IdentityStatus.ALIASED;
            const aliasInfo = isAlias ? ` → ${dep.identity.resolved_package}` : '';
            this.description = `${dep.decision.action} (${(dep.decision.confidence * 100).toFixed(0)}%)${aliasInfo}`;
            
            // Build rich tooltip
            const md = new vscode.MarkdownString();
            md.appendMarkdown(`### SLOPGUARD: **${dep.extracted.name}**\n\n`);
            md.appendMarkdown(`- **Policy Action**: \`${dep.decision.action}\`\n`);
            md.appendMarkdown(`- **Resolved Package**: \`${dep.identity.resolved_package}\`\n`);
            md.appendMarkdown(`- **Ecosystem**: \`${dep.extracted.ecosystem}\`\n`);
            md.appendMarkdown(`- **Confidence**: \`${(dep.decision.confidence * 100).toFixed(1)}%\`\n`);
            if (dep.decision.reasons.length > 0) {
                md.appendMarkdown(`\n**Reasons**:\n`);
                for (const r of dep.decision.reasons) {
                    md.appendMarkdown(`- ${r}\n`);
                }
            }
            if (dep.trust.typosquat_details) {
                const td = dep.trust.typosquat_details;
                md.appendMarkdown(`\n**Typosquat Candidate**:\n`);
                md.appendMarkdown(`- Similar to \`${td.similar_package}\` (${td.reason})\n`);
            }
            if (dep.decision.suggested_fix) {
                md.appendMarkdown(`\n**Suggested Fix**:\n`);
                md.appendMarkdown(`- ${dep.decision.suggested_fix}\n`);
            }
            this.tooltip = md;

            // Icons
            switch (dep.decision.action) {
                case PolicyAction.BLOCK:
                    this.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
                    break;
                case PolicyAction.HOLD:
                case PolicyAction.ALERT:
                    this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
                    break;
                case PolicyAction.ALLOW:
                default:
                    this.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));
                    break;
            }

            // Command on click
            this.command = {
                command: 'slopguard.showEvidence',
                title: 'Show Evidence',
                arguments: [dep]
            };
        } else if (this.categoryType === 'overview') {
            this.iconPath = new vscode.ThemeIcon('shield');
            if (this.summaryData) {
                this.description = `${this.summaryData.allowed_count} ✓ | ${this.summaryData.hold_count + this.summaryData.alert_count} ⚠ | ${this.summaryData.blocked_count} 🚫`;
            }
        } else if (this.categoryType === 'blocked') {
            this.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
        } else if (this.categoryType === 'hold') {
            this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
        } else if (this.categoryType === 'allowed') {
            this.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));
        }
    }
}

export class DependencyTreeProvider implements vscode.TreeDataProvider<DependencyTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<DependencyTreeItem | undefined | null | void> = new vscode.EventEmitter<DependencyTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<DependencyTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private scanManager: ScanManager;

    constructor(scanManager: ScanManager) {
        this.scanManager = scanManager;

        this.scanManager.onScanCompleted(() => this.refresh());
        this.scanManager.onWorkspaceScanCompleted(() => this.refresh());
    }

    public refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    public getTreeItem(element: DependencyTreeItem): vscode.TreeItem {
        return element;
    }

    public async getChildren(element?: DependencyTreeItem): Promise<DependencyTreeItem[]> {
        const allDeps = this.scanManager.getAllEvaluatedDependencies();
        const summary = this.scanManager.getWorkspaceSummary();

        if (!element) {
            // Root categories
            if (allDeps.length === 0) {
                const emptyItem = new DependencyTreeItem(
                    'No scan results yet. Run a scan.',
                    vscode.TreeItemCollapsibleState.None
                );
                emptyItem.iconPath = new vscode.ThemeIcon('info');
                emptyItem.command = {
                    command: 'slopguard.scanWorkspace',
                    title: 'Scan Workspace'
                };
                return [emptyItem];
            }

            const blockedCount = allDeps.filter(d => d.decision.action === PolicyAction.BLOCK).length;
            const holdCount = allDeps.filter(d => d.decision.action === PolicyAction.HOLD || d.decision.action === PolicyAction.ALERT).length;
            const allowCount = allDeps.filter(d => d.decision.action === PolicyAction.ALLOW).length;

            const items: DependencyTreeItem[] = [
                new DependencyTreeItem(
                    `Overview: ${summary.total_extracted} Dependencies`,
                    vscode.TreeItemCollapsibleState.None,
                    undefined,
                    'overview',
                    summary
                )
            ];

            if (blockedCount > 0) {
                items.push(new DependencyTreeItem(
                    `Blocked Dependencies (${blockedCount})`,
                    vscode.TreeItemCollapsibleState.Expanded,
                    undefined,
                    'blocked'
                ));
            }

            if (holdCount > 0) {
                items.push(new DependencyTreeItem(
                    `Review Required (${holdCount})`,
                    vscode.TreeItemCollapsibleState.Expanded,
                    undefined,
                    'hold'
                ));
            }

            if (allowCount > 0) {
                items.push(new DependencyTreeItem(
                    `Verified Safe (${allowCount})`,
                    vscode.TreeItemCollapsibleState.Collapsed,
                    undefined,
                    'allowed'
                ));
            }

            return items;
        }

        // Children of category
        if (element.categoryType === 'blocked') {
            return allDeps
                .filter(d => d.decision.action === PolicyAction.BLOCK)
                .map(d => new DependencyTreeItem(d.extracted.name, vscode.TreeItemCollapsibleState.None, d));
        }

        if (element.categoryType === 'hold') {
            return allDeps
                .filter(d => d.decision.action === PolicyAction.HOLD || d.decision.action === PolicyAction.ALERT)
                .map(d => new DependencyTreeItem(d.extracted.name, vscode.TreeItemCollapsibleState.None, d));
        }

        if (element.categoryType === 'allowed') {
            return allDeps
                .filter(d => d.decision.action === PolicyAction.ALLOW)
                .map(d => new DependencyTreeItem(d.extracted.name, vscode.TreeItemCollapsibleState.None, d));
        }

        return [];
    }
}
