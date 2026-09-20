import * as vscode from 'vscode';
import { SlopguardClient } from '../services/slopguardClient';
import { PhantomRecord, PhantomState } from '../types/slopguard';

export class PhantomTreeItem extends vscode.TreeItem {
    constructor(public readonly phantom: PhantomRecord) {
        super(phantom.package_name, vscode.TreeItemCollapsibleState.None);
        this.setupItem();
    }

    private setupItem(): void {
        this.contextValue = 'slopguardPhantom';
        this.description = `${this.phantom.current_state} (${this.phantom.occurrence_count}x)`;

        const md = new vscode.MarkdownString();
        md.appendMarkdown(`### Phantom: **${this.phantom.package_name}**\n\n`);
        md.appendMarkdown(`- **Current State**: \`${this.phantom.current_state}\`\n`);
        md.appendMarkdown(`- **Ecosystem**: \`${this.phantom.ecosystem}\`\n`);
        md.appendMarkdown(`- **Observations**: ${this.phantom.occurrence_count}\n`);
        md.appendMarkdown(`- **First Observed**: ${this.phantom.first_seen}\n`);
        md.appendMarkdown(`- **Last Observed**: ${this.phantom.last_seen}\n`);
        if (this.phantom.notes && this.phantom.notes.length > 0) {
            md.appendMarkdown(`- **Notes**: ${this.phantom.notes.join('; ')}\n`);
        }
        if (this.phantom.current_state === PhantomState.APPEARED) {
            md.appendMarkdown(`\n⚠️ **STATE CHANGE**: This package previously did not exist, but has recently appeared on the registry. Review is required before use.\n`);
        }
        this.tooltip = md;

        switch (this.phantom.current_state) {
            case PhantomState.APPEARED:
                this.iconPath = new vscode.ThemeIcon('bell-dot', new vscode.ThemeColor('editorWarning.foreground'));
                break;
            case PhantomState.WATCH:
                this.iconPath = new vscode.ThemeIcon('eye', new vscode.ThemeColor('charts.blue'));
                break;
            case PhantomState.RESOLVED:
                this.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));
                break;
            case PhantomState.NOT_FOUND:
            default:
                this.iconPath = new vscode.ThemeIcon('circle-slash', new vscode.ThemeColor('errorForeground'));
                break;
        }
    }
}

export class PhantomsTreeProvider implements vscode.TreeDataProvider<PhantomTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<PhantomTreeItem | undefined | null | void> = new vscode.EventEmitter<PhantomTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<PhantomTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private restClient: SlopguardClient;

    constructor(restClient: SlopguardClient) {
        this.restClient = restClient;
    }

    public refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    public getTreeItem(element: PhantomTreeItem): vscode.TreeItem {
        return element;
    }

    public async getChildren(element?: PhantomTreeItem): Promise<PhantomTreeItem[]> {
        if (element) {
            return [];
        }

        try {
            const phantoms = await this.restClient.getPhantoms();
            if (!phantoms || phantoms.length === 0) {
                const emptyItem = new vscode.TreeItem('No phantoms on watchlist', vscode.TreeItemCollapsibleState.None);
                emptyItem.iconPath = new vscode.ThemeIcon('check');
                return [emptyItem as PhantomTreeItem];
            }

            return phantoms.map(p => new PhantomTreeItem(p));
        } catch {
            const unavailableItem = new vscode.TreeItem('Phantom memory service offline', vscode.TreeItemCollapsibleState.None);
            unavailableItem.iconPath = new vscode.ThemeIcon('cloud-offline');
            return [unavailableItem as PhantomTreeItem];
        }
    }
}
