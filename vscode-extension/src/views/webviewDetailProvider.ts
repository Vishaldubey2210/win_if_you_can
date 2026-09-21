import * as vscode from 'vscode';
import { EvaluatedDependency, PolicyAction, IdentityStatus, RegistryStatus, extractSuggestedTarget } from '../types/slopguard';

export class WebviewDetailProvider {
    public static currentPanel: WebviewDetailProvider | undefined;
    private readonly panel: vscode.WebviewPanel;
    private readonly extensionUri: vscode.Uri;
    private disposables: vscode.Disposable[] = [];
    private currentDep?: EvaluatedDependency;

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri, dep: EvaluatedDependency) {
        this.panel = panel;
        this.extensionUri = extensionUri;
        this.currentDep = dep;

        this.updateContent();

        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);

        // Handle messages from the webview
        this.panel.webview.onDidReceiveMessage(
            async (message) => {
                switch (message.command) {
                    case 'applyRepair':
                        if (message.suggestedPackage) {
                            await this.applyRepair(message.suggestedPackage);
                        }
                        return;
                    case 'rescan':
                        await vscode.commands.executeCommand('slopguard.scanCurrentFile');
                        return;
                    case 'openUrl':
                        if (message.url) {
                            vscode.env.openExternal(vscode.Uri.parse(message.url));
                        }
                        return;
                }
            },
            null,
            this.disposables
        );
    }

    public static show(extensionUri: vscode.Uri, dep: EvaluatedDependency): void {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (WebviewDetailProvider.currentPanel) {
            WebviewDetailProvider.currentPanel.currentDep = dep;
            WebviewDetailProvider.currentPanel.updateContent();
            WebviewDetailProvider.currentPanel.panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'slopguardEvidence',
            `SLOPGUARD: ${dep.extracted.name}`,
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media')]
            }
        );

        WebviewDetailProvider.currentPanel = new WebviewDetailProvider(panel, extensionUri, dep);
    }

    private async applyRepair(suggestedPackage: string): Promise<void> {
        const editor = vscode.window.activeTextEditor;
        if (!editor || !this.currentDep) {
            vscode.window.showWarningMessage('No active editor found to apply repair.');
            return;
        }

        const oldName = this.currentDep.extracted.name;
        const text = editor.document.getText();
        const index = text.indexOf(oldName);

        if (index === -1) {
            vscode.window.showInformationMessage(`Could not find token '${oldName}' in current active document.`);
            return;
        }

        const posStart = editor.document.positionAt(index);
        const posEnd = editor.document.positionAt(index + oldName.length);
        const range = new vscode.Range(posStart, posEnd);

        const success = await editor.edit((editBuilder) => {
            editBuilder.replace(range, suggestedPackage);
        });

        if (success) {
            vscode.window.showInformationMessage(`Applied repair: replaced '${oldName}' with '${suggestedPackage}'. Rescanning...`);
            await vscode.commands.executeCommand('slopguard.scanCurrentFile');
        }
    }

    private updateContent(): void {
        if (!this.currentDep) {
            return;
        }
        this.panel.title = `Evidence: ${this.currentDep.extracted.name}`;
        this.panel.webview.html = this.getHtmlForWebview(this.currentDep);
    }

    private escapeHtml(unsafe: string): string {
        return unsafe
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    private getHtmlForWebview(dep: EvaluatedDependency): string {
        const action = dep.decision.action;
        const actionClass = action === PolicyAction.BLOCK
            ? 'badge-blocked'
            : action === PolicyAction.HOLD || action === PolicyAction.ALERT
            ? 'badge-hold'
            : 'badge-allow';

        const reasonsHtml = dep.decision.reasons.length > 0
            ? dep.decision.reasons.map((r: string) => `<li>${this.escapeHtml(r)}</li>`).join('')
            : '<li>Policy verification passed with no violations.</li>';

        // Repair proposals
        const repairInfo = extractSuggestedTarget(dep);
        let repairsHtml = '';
        if (repairInfo) {
            repairsHtml += `
                <div class="repair-card">
                    <div class="repair-header">
                        <strong>${this.escapeHtml(repairInfo.target)}</strong>
                        <span class="badge badge-confidence">Recommended Alternative</span>
                    </div>
                    <div class="repair-reason">${this.escapeHtml(repairInfo.reason)}</div>
                    <div class="repair-actions">
                        <button class="btn btn-primary" onclick="applyRepair('${this.escapeHtml(repairInfo.target)}')">Apply &amp; Rescan</button>
                    </div>
                </div>
            `;
        } else {
            repairsHtml = '<p class="text-muted">No repair candidates required for this dependency.</p>';
        }

        const isFound = dep.registry?.status === RegistryStatus.FOUND;
        const registryStatus = isFound
            ? `<span class="badge badge-allow">EXISTS (HTTP 200)</span>`
            : `<span class="badge badge-blocked">${dep.registry?.status || 'NOT FOUND (HTTP 404)'}</span>`;

        const registryVersions = dep.registry?.release_count || (dep.registry?.all_versions?.length || 0);
        const latestVersion = dep.registry?.latest_version || 'N/A';
        const repositoryUrl = dep.registry?.repository_url || 'None verified';
        const isAlias = dep.identity.status === IdentityStatus.ALIASED;

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${this.panel.webview.cspSource} https: data:; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SLOPGUARD Evidence Dossier</title>
    <style>
        :root {
            --bg-color: var(--vscode-editor-background, #1e1e1e);
            --card-bg: var(--vscode-sideBar-background, #252526);
            --border-color: var(--vscode-panel-border, #3c3c3c);
            --text-color: var(--vscode-editor-foreground, #cccccc);
            --text-muted: var(--vscode-descriptionForeground, #888888);
            --btn-primary-bg: var(--vscode-button-background, #0e639c);
            --btn-primary-fg: var(--vscode-button-foreground, #ffffff);
            --color-allow: #4caf50;
            --color-hold: #ff9800;
            --color-blocked: #f44336;
        }
        body {
            font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif);
            background-color: var(--bg-color);
            color: var(--text-color);
            padding: 24px;
            margin: 0;
            line-height: 1.6;
        }
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }
        .header h1 {
            margin: 0;
            font-size: 22px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge-allow { background-color: rgba(76, 175, 80, 0.2); color: var(--color-allow); border: 1px solid var(--color-allow); }
        .badge-hold { background-color: rgba(255, 152, 0, 0.2); color: var(--color-hold); border: 1px solid var(--color-hold); }
        .badge-blocked { background-color: rgba(244, 67, 54, 0.2); color: var(--color-blocked); border: 1px solid var(--color-blocked); }
        .badge-confidence { background-color: rgba(14, 99, 156, 0.2); color: #4fc1ff; border: 1px solid #4fc1ff; }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
        }
        .card h2 {
            margin-top: 0;
            font-size: 15px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 8px;
            color: var(--text-color);
        }
        .field {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 13px;
        }
        .field-label { color: var(--text-muted); }
        .field-value { font-weight: 500; }
        
        /* Evidence Graph Visual */
        .graph-container {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 20px 10px;
            background: rgba(0,0,0,0.15);
            border-radius: 6px;
            margin-bottom: 24px;
            overflow-x: auto;
        }
        .node {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 10px 14px;
            text-align: center;
            min-width: 90px;
            font-size: 12px;
        }
        .node-title { font-weight: bold; margin-bottom: 4px; font-size: 11px; color: var(--text-muted); text-transform: uppercase; }
        .edge { flex-grow: 1; height: 2px; background: var(--border-color); margin: 0 10px; position: relative; }
        .edge::after {
            content: '▶';
            position: absolute;
            right: -6px;
            top: -7px;
            font-size: 10px;
            color: var(--border-color);
        }

        .repair-card {
            background: rgba(14, 99, 156, 0.1);
            border: 1px solid rgba(14, 99, 156, 0.3);
            border-radius: 6px;
            padding: 14px;
            margin-top: 10px;
        }
        .repair-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }
        .repair-reason {
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 12px;
        }
        .btn {
            border: none;
            padding: 6px 14px;
            border-radius: 4px;
            font-size: 12px;
            cursor: pointer;
            font-weight: 500;
        }
        .btn-primary {
            background-color: var(--btn-primary-bg);
            color: var(--btn-primary-fg);
        }
        .btn-primary:hover { opacity: 0.9; }
        .text-muted { color: var(--text-muted); }
        ul { margin: 0; padding-left: 20px; }
        li { margin-bottom: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>
                <span>🛡 ${this.escapeHtml(dep.extracted.name)}</span>
                <span class="badge ${actionClass}">${action}</span>
            </h1>
            <div class="text-muted" style="margin-top: 4px;">
                Ecosystem: <strong>${this.escapeHtml(dep.extracted.ecosystem)}</strong> |
                Resolved: <strong>${this.escapeHtml(dep.identity.resolved_package)}</strong>
                ${isAlias ? '<em>(Resolved Alias)</em>' : ''}
            </div>
        </div>
        <button class="btn btn-primary" onclick="rescan()">Rescan Current File</button>
    </div>

    <!-- Evidence Graph -->
    <div class="card" style="margin-bottom: 24px;">
        <h2>Evidence Graph</h2>
        <div class="graph-container">
            <div class="node">
                <div class="node-title">Import</div>
                <div>${this.escapeHtml(dep.extracted.name)}</div>
            </div>
            <div class="edge"></div>
            <div class="node">
                <div class="node-title">Canonical</div>
                <div>${this.escapeHtml(dep.identity.resolved_package)}</div>
            </div>
            <div class="edge"></div>
            <div class="node">
                <div class="node-title">Registry</div>
                <div>${isFound ? 'Verified' : '404'}</div>
            </div>
            <div class="edge"></div>
            <div class="node">
                <div class="node-title">Trust Gate</div>
                <div>${(dep.decision.confidence * 100).toFixed(0)}%</div>
            </div>
            <div class="edge"></div>
            <div class="node" style="border-color: ${action === PolicyAction.BLOCK ? 'var(--color-blocked)' : action === PolicyAction.ALLOW ? 'var(--color-allow)' : 'var(--color-hold)'}">
                <div class="node-title">Policy</div>
                <div style="font-weight: bold;">${action}</div>
            </div>
        </div>
    </div>

    <div class="grid">
        <!-- Identity & Status -->
        <div class="card">
            <h2>Identity Resolution</h2>
            <div class="field">
                <span class="field-label">Import Name</span>
                <span class="field-value">${this.escapeHtml(dep.extracted.name)}</span>
            </div>
            <div class="field">
                <span class="field-label">Resolved Package</span>
                <span class="field-value">${this.escapeHtml(dep.identity.resolved_package)}</span>
            </div>
            <div class="field">
                <span class="field-label">Is Alias</span>
                <span class="field-value">${isAlias ? 'Yes' : 'No'}</span>
            </div>
            <div class="field">
                <span class="field-label">Confidence</span>
                <span class="field-value">${(dep.decision.confidence * 100).toFixed(1)}%</span>
            </div>
            <div class="field">
                <span class="field-label">Policy Action</span>
                <span class="field-value badge ${actionClass}">${action}</span>
            </div>
        </div>

        <!-- Registry Evidence -->
        <div class="card">
            <h2>Registry Evidence</h2>
            <div class="field">
                <span class="field-label">Status</span>
                <span class="field-value">${registryStatus}</span>
            </div>
            <div class="field">
                <span class="field-label">Latest Version</span>
                <span class="field-value">${this.escapeHtml(latestVersion)}</span>
            </div>
            <div class="field">
                <span class="field-label">Releases Available</span>
                <span class="field-value">${registryVersions}</span>
            </div>
            <div class="field">
                <span class="field-label">Repository</span>
                <span class="field-value">${this.escapeHtml(repositoryUrl)}</span>
            </div>
        </div>
    </div>

    <!-- Policy Reasons -->
    <div class="card" style="margin-bottom: 24px;">
        <h2>Policy Decision Reasons</h2>
        <ul>${reasonsHtml}</ul>
    </div>

    <!-- Repair Center -->
    <div class="card">
        <h2>Repair Center</h2>
        ${repairsHtml}
    </div>

    <script>
        const vscode = acquireVsCodeApi();

        function applyRepair(suggestedPackage) {
            vscode.postMessage({
                command: 'applyRepair',
                suggestedPackage: suggestedPackage
            });
        }

        function rescan() {
            vscode.postMessage({
                command: 'rescan'
            });
        }
    </script>
</body>
</html>`;
    }

    public dispose(): void {
        WebviewDetailProvider.currentPanel = undefined;
        this.panel.dispose();
        while (this.disposables.length) {
            const x = this.disposables.pop();
            if (x) {
                x.dispose();
            }
        }
    }
}
