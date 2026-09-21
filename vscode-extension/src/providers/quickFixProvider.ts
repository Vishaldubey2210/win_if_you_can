import * as vscode from 'vscode';
import { EvaluatedDependency, extractSuggestedTarget } from '../types/slopguard';

export class QuickFixProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    public provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'SLOPGUARD') {
                continue;
            }

            const dep: EvaluatedDependency | undefined = (diagnostic as any).dependencyData;
            if (!dep) {
                continue;
            }

            // 1. Action: Apply suggested fix if available
            const repairInfo = extractSuggestedTarget(dep);
            const suggestedTarget = repairInfo?.target;

            if (suggestedTarget) {
                const action = new vscode.CodeAction(
                    `SLOPGUARD: Replace '${dep.extracted.name}' with verified '${suggestedTarget}' (Policy rescan required)`,
                    vscode.CodeActionKind.QuickFix
                );
                action.diagnostics = [diagnostic];
                action.isPreferred = true;

                // Edit replacing the bad package name with the verified package name
                const edit = new vscode.WorkspaceEdit();
                edit.replace(document.uri, diagnostic.range, suggestedTarget);
                action.edit = edit;

                // Trigger rescan command after applying fix
                action.command = {
                    command: 'slopguard.scanCurrentFile',
                    title: 'Rescan with SLOPGUARD'
                };

                actions.push(action);
            }

            // 2. Action: Inspect Evidence Dossier
            const evidenceAction = new vscode.CodeAction(
                `SLOPGUARD: Inspect Evidence Dossier for '${dep.extracted.name}'`,
                vscode.CodeActionKind.Empty
            );
            evidenceAction.command = {
                command: 'slopguard.showEvidence',
                title: 'Show Evidence',
                arguments: [dep]
            };
            actions.push(evidenceAction);

            // 3. Action: Rescan
            const rescanAction = new vscode.CodeAction(
                `SLOPGUARD: Rescan Current File`,
                vscode.CodeActionKind.Empty
            );
            rescanAction.command = {
                command: 'slopguard.scanCurrentFile',
                title: 'Rescan File'
            };
            actions.push(rescanAction);
        }

        return actions;
    }
}
