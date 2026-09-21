import * as vscode from 'vscode';
import { ScanManager } from '../services/scanManager';
import { EvaluatedDependency, PolicyAction, IdentityStatus, ScanResult } from '../types/slopguard';

export class DiagnosticsProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private scanManager: ScanManager;

    constructor(scanManager: ScanManager) {
        this.scanManager = scanManager;
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('slopguard');

        // Subscribe to scan completions
        this.scanManager.onScanCompleted(({ filePath, result }) => {
            this.updateDiagnostics(filePath, result);
        });
    }

    public updateDiagnostics(filePath: string, scanResult: ScanResult): void {
        const uri = vscode.Uri.file(filePath);
        const diagnostics: vscode.Diagnostic[] = [];

        // Open text document if available to locate lines accurately
        const document = vscode.workspace.textDocuments.find(d => d.uri.fsPath.toLowerCase() === uri.fsPath.toLowerCase());
        const documentText = document ? document.getText() : null;

        for (const dep of scanResult.dependencies) {
            // Only flag blocked, held, or alerted dependencies (ALLOW dependencies are verified clean)
            if (dep.decision.action === PolicyAction.ALLOW) {
                continue;
            }

            const range = this.findDependencyRange(dep, documentText);
            const severity = this.mapSeverity(dep.decision.action);
            const message = this.formatDiagnosticMessage(dep);

            const diagnostic = new vscode.Diagnostic(range, message, severity);
            diagnostic.source = 'SLOPGUARD';
            diagnostic.code = `slopguard-${dep.decision.action.toLowerCase()}`;
            
            // Attach custom metadata to the diagnostic for CodeAction consumption
            (diagnostic as any).dependencyData = dep;

            diagnostics.push(diagnostic);
        }

        this.diagnosticCollection.set(uri, diagnostics);
    }

    public clearForFile(filePath: string): void {
        const uri = vscode.Uri.file(filePath);
        this.diagnosticCollection.delete(uri);
    }

    public clearAll(): void {
        this.diagnosticCollection.clear();
    }

    public dispose(): void {
        this.diagnosticCollection.dispose();
    }

    private mapSeverity(action: PolicyAction): vscode.DiagnosticSeverity {
        switch (action) {
            case PolicyAction.BLOCK:
                return vscode.DiagnosticSeverity.Error;
            case PolicyAction.HOLD:
            case PolicyAction.ALERT:
                return vscode.DiagnosticSeverity.Warning;
            case PolicyAction.ALLOW:
            default:
                return vscode.DiagnosticSeverity.Information;
        }
    }

    private formatDiagnosticMessage(dep: EvaluatedDependency): string {
        const importName = dep.extracted.name;
        const registryStatus = dep.registry?.status || 'UNKNOWN';
        const riskLevel = dep.decision.risk_level || 'HIGH';
        const policyAction = dep.decision.action;
        const canonical = dep.identity.resolved_package;
        const isAlias = dep.identity.status === IdentityStatus.ALIASED;

        let msg = `SLOPGUARD:\nDependency "${importName}" could not be verified.`;
        if (isAlias) {
            msg = `SLOPGUARD:\nDependency "${importName}" resolves to canonical package: ${canonical}.`;
        } else if (policyAction === PolicyAction.ALLOW) {
            msg = `SLOPGUARD:\nDependency "${importName}" verified.`;
        }

        msg += `\nRegistry: ${registryStatus}`;
        msg += `\nRisk: ${riskLevel}`;
        msg += `\nPolicy: ${policyAction}`;

        let suggestedFix = dep.decision.suggested_fix;
        if (!suggestedFix && dep.trust?.typosquat_details?.similar_package) {
            suggestedFix = dep.trust.typosquat_details.similar_package;
        } else if (suggestedFix && suggestedFix.startsWith("Did you mean '") && suggestedFix.endsWith("'?")) {
            const match = suggestedFix.match(/Did you mean '([^']+)'\?/);
            if (match) {
                suggestedFix = match[1];
            }
        }

        if (suggestedFix) {
            msg += `\nSuggested fix: ${suggestedFix}`;
        }

        if (dep.decision.reasons && dep.decision.reasons.length > 0) {
            msg += `\nReasons: ${dep.decision.reasons.join('; ')}`;
        }

        return msg;
    }

    private findDependencyRange(dep: EvaluatedDependency, documentText: string | null): vscode.Range {
        if (!documentText) {
            if (dep.extracted.line_number && dep.extracted.line_number > 0) {
                const line = dep.extracted.line_number - 1;
                return new vscode.Range(line, 0, line, dep.extracted.name.length);
            }
            return new vscode.Range(0, 0, 0, 0);
        }

        const lines = documentText.split(/\r?\n/);
        const name = dep.extracted.name;
        const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

        // Regex patterns for imports in Python, JS, TS, and manifest lines
        const patterns = [
            new RegExp(`\\bimport\\s+${escapedName}\\b`),
            new RegExp(`\\bfrom\\s+${escapedName}\\b`),
            new RegExp(`\\brequire\\s*\\(\\s*['"]${escapedName}['"]\\s*\\)`),
            new RegExp(`\\bimport\\s*\\(\\s*['"]${escapedName}['"]\\s*\\)`),
            new RegExp(`['"]${escapedName}['"]`),
            new RegExp(`^\\s*${escapedName}\\b`)
        ];

        // Check explicit line number first if available
        if (dep.extracted.line_number && dep.extracted.line_number <= lines.length) {
            const explicitLineIdx = dep.extracted.line_number - 1;
            const line = lines[explicitLineIdx];
            const col = line.indexOf(name);
            if (col >= 0) {
                return new vscode.Range(explicitLineIdx, col, explicitLineIdx, col + name.length);
            }
        }

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            for (const pattern of patterns) {
                const match = pattern.exec(line);
                if (match) {
                    const colIndex = line.indexOf(name, match.index);
                    const startCol = colIndex >= 0 ? colIndex : match.index;
                    const endCol = startCol + name.length;
                    return new vscode.Range(lineIndex, startCol, lineIndex, endCol);
                }
            }
        }

        // Default fallback to first line
        return new vscode.Range(0, 0, 0, 0);
    }
}
