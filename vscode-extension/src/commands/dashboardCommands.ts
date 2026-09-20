import * as vscode from 'vscode';

export function registerDashboardCommands(context: vscode.ExtensionContext): void {
    // 1. Open Dashboard
    context.subscriptions.push(
        vscode.commands.registerCommand('slopguard.openDashboard', async () => {
            const config = vscode.workspace.getConfiguration('slopguard');
            const baseUrl = config.get<string>('server.url', 'http://localhost:8000');
            const dashboardUrl = `${baseUrl.replace(/\/$/, '')}/dashboard`;

            const choice = await vscode.window.showInformationMessage(
                `Open SLOPGUARD Web Dashboard?`,
                'Open in Browser',
                'Open Embedded Tab'
            );

            if (choice === 'Open in Browser') {
                vscode.env.openExternal(vscode.Uri.parse(dashboardUrl));
            } else if (choice === 'Open Embedded Tab') {
                const panel = vscode.window.createWebviewPanel(
                    'slopguardWebDashboard',
                    'SLOPGUARD Dashboard',
                    vscode.ViewColumn.One,
                    {
                        enableScripts: true,
                        retainContextWhenHidden: true
                    }
                );

                panel.webview.html = `<!DOCTYPE html>
<html>
<head>
    <style>
        body, html { margin: 0; padding: 0; height: 100%; overflow: hidden; background: #1e1e1e; }
        iframe { width: 100%; height: 100%; border: none; }
    </style>
</head>
<body>
    <iframe src="${dashboardUrl}"></iframe>
</body>
</html>`;
            }
        })
    );

    // 2. Configure Settings
    context.subscriptions.push(
        vscode.commands.registerCommand('slopguard.configure', () => {
            vscode.commands.executeCommand('workbench.action.openSettings', 'slopguard');
        })
    );
}
