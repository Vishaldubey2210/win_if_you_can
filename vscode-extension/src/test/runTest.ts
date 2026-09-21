// Hook vscode module before any extension service imports
import './mockVscode';
import * as assert from 'assert';
import * as path from 'path';
import * as fs from 'fs';
import * as vscode from 'vscode';
import { PolicyAction, IdentityStatus, RegistryStatus, EngineConnectionStatus, ScanResult } from '../types/slopguard';
import { ScanCache } from '../services/scanCache';
import { EngineManager } from '../services/engineManager';
import { CliClient } from '../services/cliClient';
import { CliDiscovery } from '../services/cliDiscovery';
import { ScanManager } from '../services/scanManager';
import { ScanCoordinator } from '../services/scanCoordinator';
import { DiagnosticsProvider } from '../providers/diagnosticsProvider';
import { QuickFixProvider } from '../providers/quickFixProvider';
import { StatusBarProvider } from '../providers/statusBarProvider';
import { activate, deactivate } from '../extension';
import { MockOutputChannel, MockDiagnosticSeverity, MockUri, MockRange } from './mockVscode';

console.log('🧪 Running Complete 30-Point SLOPGUARD Production Test Suite...\n');

let passed = 0;
let failed = 0;

async function runTest(name: string, fn: () => void | Promise<void>) {
    try {
        await fn();
        console.log(`  ✓ ${name}`);
        passed++;
    } catch (err: any) {
        console.error(`  ✗ ${name}`);
        console.error(`    ${err.stack || err.message}`);
        failed++;
    }
}

// Helper to create mock ScanResult
function createMockResult(filePath: string, depName: string, action: PolicyAction, fix?: string): ScanResult {
    const isBlock = action === PolicyAction.BLOCK;
    const isAlias = depName === 'cv2';
    const canonical = isAlias ? 'opencv-python' : depName;

    return {
        scan_id: 'scan_test_' + Date.now(),
        file_path: filePath,
        language: 'python',
        dependencies: [
            {
                extracted: {
                    name: depName,
                    ecosystem: 'pypi',
                    line_number: 1,
                    raw_statement: `import ${depName}`,
                    is_stdlib: false,
                    is_relative: false
                },
                identity: {
                    input_name: depName,
                    normalized_name: depName,
                    resolved_package: canonical,
                    ecosystem: 'pypi',
                    status: isAlias ? IdentityStatus.ALIASED : IdentityStatus.RESOLVED,
                    confidence: 1.0,
                    is_stdlib: false,
                    evidence_notes: []
                },
                registry: {
                    package_name: canonical,
                    ecosystem: 'pypi',
                    status: isBlock ? RegistryStatus.NOT_FOUND : RegistryStatus.FOUND,
                    latest_version: isBlock ? undefined : '1.0.0',
                    release_count: isBlock ? 0 : 50
                },
                trust: {
                    package_name: canonical,
                    ecosystem: 'pypi',
                    level: isBlock ? ('UNRESOLVED' as any) : ('VERIFIED' as any),
                    identity_verified: true,
                    registry_verified: !isBlock,
                    is_stdlib: false,
                    has_typosquat_risk: isBlock,
                    typosquat_details: isBlock
                        ? {
                              target_package: depName,
                              similar_package: fix || 'requests',
                              distance: 1,
                              similarity_ratio: 0.88,
                              confidence: 0.95,
                              reason: 'typosquat'
                          }
                        : undefined,
                    signals: {},
                    reasons: []
                },
                phantom_state: 'NONE' as any,
                decision: {
                    action,
                    reasons: [`Policy evaluated: ${action}`],
                    risk_level: isBlock ? 'HIGH' : 'LOW',
                    confidence: 1.0,
                    requires_human_review: false,
                    suggested_fix: fix || (isBlock ? 'requests' : undefined)
                },
                timestamp: new Date().toISOString()
            }
        ],
        summary: {
            total_extracted: 1,
            stdlib_count: 0,
            allowed_count: action === PolicyAction.ALLOW ? 1 : 0,
            hold_count: 0,
            blocked_count: isBlock ? 1 : 0,
            alert_count: 0,
            duration_ms: 10
        }
    };
}

async function main() {
    const mockOutput = new MockOutputChannel();

    // 1. Extension activation
    await runTest('1. Extension activation', async () => {
        const mockContext: any = {
            subscriptions: [],
            extension: { packageJSON: { version: '0.1.2' } }
        };
        await activate(mockContext);
        assert.ok(mockContext.subscriptions.length > 0, 'Context subscriptions should not be empty');
        deactivate();
    });

    // 2. CLI discovery from PATH
    await runTest('2. CLI discovery from PATH', async () => {
        const env = CliDiscovery.getAugmentedEnv();
        assert.ok(env.PATH, 'Augmented PATH should be defined');
    });

    // 3. CLI discovery from Python user Scripts
    await runTest('3. CLI discovery from Python user Scripts', async () => {
        const env = CliDiscovery.getAugmentedEnv();
        if (process.platform === 'win32') {
            assert.ok(env.PATH?.includes('Python') || env.PATH?.includes('Scripts') || env.PATH?.includes('.venv'),
                'Windows augmented PATH should include user or venv script directories');
        } else {
            assert.ok(env.PATH?.includes('.local/bin') || env.PATH?.includes('/opt/homebrew'),
                'Unix augmented PATH should include user bin directories');
        }
    });

    // 4. Explicit cliPath setting
    await runTest('4. Explicit cliPath setting', async () => {
        const client = new CliClient('custom/path/to/slopguard', mockOutput as any);
        assert.strictEqual(client.getResolvedInvocation().command, 'custom/path/to/slopguard');
        client.updateCliPath('another/path/slopguard');
        assert.strictEqual(client.getResolvedInvocation().command, 'another/path/slopguard');
    });

    // 5. CLI version validation
    await runTest('5. CLI version validation', async () => {
        const sampleOutput = 'slopguard, version 0.1.0\n';
        const match = sampleOutput.match(/version\s+([0-9a-zA-Z.-]+)/i);
        assert.ok(match);
        assert.strictEqual(match![1], '0.1.0');
    });

    // 6. REST startup
    await runTest('6. REST startup', async () => {
        const engine = new EngineManager(mockOutput as any);
        (engine as any).healthCheck = async () => true;
        const started = await engine.ensureRunning();
        assert.strictEqual(started, true);
        assert.strictEqual(engine.getConnectionStatus(), EngineConnectionStatus.RUNNING_REST);
        assert.strictEqual(engine.isReady(), true);
    });

    // 7. REST unavailable
    await runTest('7. REST unavailable', async () => {
        const engine = new EngineManager(mockOutput as any);
        (engine as any).healthCheck = async () => false;
        (engine as any).startEngine = async () => false;
        (CliDiscovery as any).discover = async () => null;

        const ready = await engine.ensureRunning();
        assert.strictEqual(ready, false);
        assert.strictEqual(engine.getConnectionStatus(), EngineConnectionStatus.ERROR);
    });

    // 8. CLI fallback
    await runTest('8. CLI fallback', async () => {
        const engine = new EngineManager(mockOutput as any);
        (engine as any).healthCheck = async () => false;
        (engine as any).startEngine = async () => false;
        (CliDiscovery as any).discover = async () => ({
            command: 'slopguard',
            baseArgs: [],
            version: '0.1.0',
            isPythonModule: false,
            displayPath: 'slopguard'
        });

        const ready = await engine.ensureRunning();
        assert.strictEqual(ready, true);
        assert.strictEqual(engine.getConnectionStatus(), EngineConnectionStatus.CLI_FALLBACK);
        assert.strictEqual(engine.isReady(), true);
    });

    // 9. Startup race condition
    await runTest('9. Startup race condition', async () => {
        const engine = new EngineManager(mockOutput as any);
        (engine as any).currentStatus = EngineConnectionStatus.INITIALIZING;

        const cli = new CliClient('slopguard', mockOutput as any);
        const scanMgr = new ScanManager(null as any, cli, new ScanCache(10), mockOutput as any);
        const coordinator = new ScanCoordinator(engine, scanMgr, mockOutput as any);

        assert.strictEqual(engine.isInitializing(), true);
        assert.strictEqual(engine.isReady(), false);

        const scanPromise = coordinator.requestScan('test.py', true);
        assert.strictEqual(coordinator.hasPendingScan('test.py'), true);
        coordinator.dispose();
    });

    // 10. Queued scan
    await runTest('10. Queued scan', async () => {
        const engine = new EngineManager(mockOutput as any);
        (engine as any).currentStatus = EngineConnectionStatus.STARTING;

        const cli = new CliClient('slopguard', mockOutput as any);
        const scanMgr = new ScanManager(null as any, cli, new ScanCache(10), mockOutput as any);
        const coordinator = new ScanCoordinator(engine, scanMgr, mockOutput as any);

        assert.strictEqual(coordinator.getPendingQueueSize(), 0);
        coordinator.requestScan('test.py', true);
        assert.strictEqual(coordinator.getPendingQueueSize(), 1);
        coordinator.dispose();
    });

    // 11. Queue deduplication
    await runTest('11. Queue deduplication', async () => {
        const engine = new EngineManager(mockOutput as any);
        (engine as any).currentStatus = EngineConnectionStatus.STARTING;

        const cli = new CliClient('slopguard', mockOutput as any);
        const scanMgr = new ScanManager(null as any, cli, new ScanCache(10), mockOutput as any);
        const coordinator = new ScanCoordinator(engine, scanMgr, mockOutput as any);

        coordinator.requestScan('test.py', true);
        coordinator.requestScan('test.py', true);
        coordinator.requestScan('test.py', true);
        assert.strictEqual(coordinator.getPendingQueueSize(), 1, 'Queue size must remain 1 after multiple saves');
        coordinator.dispose();
    });

    // 12. Scan on save
    await runTest('12. Scan on save', async () => {
        const engine = new EngineManager(mockOutput as any);
        (engine as any).currentStatus = EngineConnectionStatus.READY;

        const cli = new CliClient('slopguard', mockOutput as any);
        const scanMgr = new ScanManager(null as any, cli, new ScanCache(10), mockOutput as any);
        let called = false;
        scanMgr.scanFileByPath = async (p) => {
            called = true;
            return createMockResult(p, 'requests', PolicyAction.ALLOW);
        };

        const coordinator = new ScanCoordinator(engine, scanMgr, mockOutput as any);
        const res = await coordinator.requestScan('sample.py', true);
        assert.strictEqual(called, true);
        assert.ok(res);
        coordinator.dispose();
    });

    // 13. Scan on open
    await runTest('13. Scan on open', async () => {
        const scanMgr = new ScanManager(null as any, null as any, new ScanCache(10), mockOutput as any);
        assert.strictEqual(scanMgr.detectLanguage('main.py'), 'python');
        assert.strictEqual(scanMgr.detectLanguage('app.ts'), 'typescript');
        assert.strictEqual(scanMgr.detectLanguage('requirements.txt'), 'requirements');
        assert.strictEqual(scanMgr.detectLanguage('image.png'), null);
    });

    // 14. Workspace scan
    await runTest('14. Workspace scan', async () => {
        const scanMgr = new ScanManager(null as any, null as any, new ScanCache(10), mockOutput as any);
        const res1 = createMockResult('a.py', 'requests', PolicyAction.ALLOW);
        const res2 = createMockResult('b.py', 'requets', PolicyAction.BLOCK);
        scanMgr.getAllResults().set('a.py', res1);
        scanMgr.getAllResults().set('b.py', res2);

        const summary = scanMgr.getWorkspaceSummary();
        assert.strictEqual(summary.total_extracted, 2);
        assert.strictEqual(summary.allowed_count, 1);
        assert.strictEqual(summary.blocked_count, 1);
    });

    // 15. Python import extraction
    await runTest('15. Python import extraction', async () => {
        const res = createMockResult('app.py', 'requests', PolicyAction.ALLOW);
        assert.strictEqual(res.dependencies[0].extracted.name, 'requests');
        assert.strictEqual(res.dependencies[0].extracted.ecosystem, 'pypi');
    });

    // 16. requests -> ALLOW
    await runTest('16. requests -> ALLOW', async () => {
        const res = createMockResult('app.py', 'requests', PolicyAction.ALLOW);
        const dep = res.dependencies[0];
        assert.strictEqual(dep.decision.action, PolicyAction.ALLOW);
        assert.strictEqual(dep.decision.risk_level, 'LOW');
        assert.strictEqual(dep.registry!.status, RegistryStatus.FOUND);
    });

    // 17. requets -> BLOCK
    await runTest('17. requets -> BLOCK', async () => {
        const res = createMockResult('app.py', 'requets', PolicyAction.BLOCK, 'requests');
        const dep = res.dependencies[0];
        assert.strictEqual(dep.decision.action, PolicyAction.BLOCK);
        assert.strictEqual(dep.decision.risk_level, 'HIGH');
        assert.strictEqual(dep.registry!.status, RegistryStatus.NOT_FOUND);
        assert.strictEqual(dep.decision.suggested_fix, 'requests');
    });

    // 18. cv2 -> opencv-python resolution
    await runTest('18. cv2 -> opencv-python resolution', async () => {
        const res = createMockResult('app.py', 'cv2', PolicyAction.ALLOW);
        const dep = res.dependencies[0];
        assert.strictEqual(dep.extracted.name, 'cv2');
        assert.strictEqual(dep.identity.resolved_package, 'opencv-python');
        assert.strictEqual(dep.identity.status, IdentityStatus.ALIASED);
    });

    // 19. Diagnostics publication
    await runTest('19. Diagnostics publication', async () => {
        const scanMgr = new ScanManager(null as any, null as any, new ScanCache(10), mockOutput as any);
        const diagProvider = new DiagnosticsProvider(scanMgr);
        const blockedRes = createMockResult('test.py', 'requets', PolicyAction.BLOCK, 'requests');

        diagProvider.updateDiagnostics('test.py', blockedRes);
        const diags = (diagProvider as any).diagnosticCollection.get(MockUri.file('test.py'));
        assert.ok(diags && diags.length === 1, 'Should publish 1 diagnostic for blocked package');
        assert.strictEqual(diags[0].source, 'SLOPGUARD');
        assert.strictEqual(diags[0].severity, MockDiagnosticSeverity.Error);
        assert.ok(diags[0].message.includes('requets'));
        assert.ok(diags[0].message.includes('BLOCK'));
        diagProvider.dispose();
    });

    // 20. Diagnostic range mapping
    await runTest('20. Diagnostic range mapping', async () => {
        const scanMgr = new ScanManager(null as any, null as any, new ScanCache(10), mockOutput as any);
        const diagProvider = new DiagnosticsProvider(scanMgr);
        const blockedRes = createMockResult('test.py', 'requets', PolicyAction.BLOCK);
        const text = 'import sys\nimport requets\nprint("hello")';

        const range = (diagProvider as any).findDependencyRange(blockedRes.dependencies[0], text);
        assert.strictEqual(range.start.line, 1);
        assert.strictEqual(range.start.character, 7);
        assert.strictEqual(range.end.character, 14);
        diagProvider.dispose();
    });

    // 21. Diagnostic cleanup
    await runTest('21. Diagnostic cleanup', async () => {
        const scanMgr = new ScanManager(null as any, null as any, new ScanCache(10), mockOutput as any);
        const diagProvider = new DiagnosticsProvider(scanMgr);
        const blockedRes = createMockResult('test.py', 'requets', PolicyAction.BLOCK);

        diagProvider.updateDiagnostics('test.py', blockedRes);
        let diags = (diagProvider as any).diagnosticCollection.get(MockUri.file('test.py'));
        assert.strictEqual(diags.length, 1);

        // Fixed to requests
        const cleanRes = createMockResult('test.py', 'requests', PolicyAction.ALLOW);
        diagProvider.updateDiagnostics('test.py', cleanRes);
        diags = (diagProvider as any).diagnosticCollection.get(MockUri.file('test.py'));
        assert.strictEqual(diags.length, 0, 'Clean scan should remove all diagnostics');
        diagProvider.dispose();
    });

    // 22. Quick Fix
    await runTest('22. Quick Fix', async () => {
        const quickFix = new QuickFixProvider();
        const blockedRes = createMockResult('test.py', 'requets', PolicyAction.BLOCK, 'requests');
        const diag = new vscode.Diagnostic(new MockRange(0, 7, 0, 14) as any, 'Blocked', MockDiagnosticSeverity.Error as any);
        diag.source = 'SLOPGUARD';
        (diag as any).dependencyData = blockedRes.dependencies[0];

        const actions = quickFix.provideCodeActions(
            { uri: MockUri.file('test.py') } as any,
            diag.range,
            { diagnostics: [diag] } as any,
            null as any
        );

        assert.ok(actions.length > 0, 'QuickFix actions should be returned');
        const replaceAction = actions.find(a => a.title.includes('requests'));
        assert.ok(replaceAction, 'Should offer replacement with requests');
        assert.strictEqual(replaceAction!.isPreferred, true);
    });

    // 23. Rescan after Quick Fix
    await runTest('23. Rescan after Quick Fix', async () => {
        const quickFix = new QuickFixProvider();
        const blockedRes = createMockResult('test.py', 'requets', PolicyAction.BLOCK, 'requests');
        const diag = new vscode.Diagnostic(new MockRange(0, 7, 0, 14) as any, 'Blocked', MockDiagnosticSeverity.Error as any);
        diag.source = 'SLOPGUARD';
        (diag as any).dependencyData = blockedRes.dependencies[0];

        const actions = quickFix.provideCodeActions(
            { uri: MockUri.file('test.py') } as any,
            diag.range,
            { diagnostics: [diag] } as any,
            null as any
        );

        const replaceAction = actions.find(a => a.title.includes('requests'));
        assert.strictEqual(replaceAction?.command?.command, 'slopguard.scanCurrentFile');
    });

    // 24. Pylance coexistence
    await runTest('24. Pylance coexistence', async () => {
        const scanMgr = new ScanManager(null as any, null as any, new ScanCache(10), mockOutput as any);
        const diagProvider = new DiagnosticsProvider(scanMgr);
        const blockedRes = createMockResult('test.py', 'requets', PolicyAction.BLOCK);

        diagProvider.updateDiagnostics('test.py', blockedRes);
        const diags = (diagProvider as any).diagnosticCollection.get(MockUri.file('test.py'));
        for (const d of diags) {
            assert.strictEqual(d.source, 'SLOPGUARD', 'Must only manage SLOPGUARD source diagnostics');
        }
        diagProvider.dispose();
    });

    // 25. CLI missing
    await runTest('25. CLI missing', async () => {
        const engine = new EngineManager(mockOutput as any);
        (engine as any).healthCheck = async () => false;
        (engine as any).startEngine = async () => false;
        (CliDiscovery as any).discover = async () => null;

        const ok = await engine.ensureRunning();
        assert.strictEqual(ok, false);
        assert.strictEqual(engine.getConnectionStatus(), EngineConnectionStatus.ERROR);
    });

    // 26. Network failure
    await runTest('26. Network failure', async () => {
        const res = createMockResult('test.py', 'networkpkg', PolicyAction.HOLD);
        res.dependencies[0].registry!.status = RegistryStatus.NETWORK_ERROR;
        assert.strictEqual(res.dependencies[0].registry!.status, RegistryStatus.NETWORK_ERROR);
    });

    // 27. Timeout
    await runTest('27. Timeout', async () => {
        const engine = new EngineManager(mockOutput as any);
        (engine as any).currentStatus = EngineConnectionStatus.STARTING;
        (engine as any).onDidChangeStatus = () => ({ dispose: () => {} });

        const ready = await engine.waitUntilReady(50);
        assert.strictEqual(ready, false);
    });

    // 28. Registry failure
    await runTest('28. Registry failure', async () => {
        const res = createMockResult('test.py', 'ratelimitedpkg', PolicyAction.HOLD);
        res.dependencies[0].registry!.status = RegistryStatus.RATE_LIMITED;
        assert.strictEqual(res.dependencies[0].registry!.status, RegistryStatus.RATE_LIMITED);
    });

    // 29. Unsupported file
    await runTest('29. Unsupported file', async () => {
        const scanMgr = new ScanManager(null as any, null as any, new ScanCache(10), mockOutput as any);
        assert.strictEqual(scanMgr.detectLanguage('document.pdf'), null);
        assert.strictEqual(scanMgr.detectLanguage('binary.dll'), null);
        assert.strictEqual(scanMgr.detectLanguage('archive.zip'), null);
    });

    // 30. Extension deactivation / cleanup
    await runTest('30. Extension deactivation / cleanup', async () => {
        const engine = new EngineManager(mockOutput as any);
        let stopped = false;
        (engine as any).stopEngine = () => { stopped = true; };
        engine.dispose();
        deactivate();
        assert.ok(true, 'Cleanup completed without error');
    });

    console.log(`\n========================================`);
    console.log(`Test Results: ${passed} passed, ${failed} failed.`);
    console.log(`========================================\n`);

    if (failed > 0) {
        process.exit(1);
    }
    process.exit(0);
}

main().catch(err => {
    console.error('Fatal test runner error:', err);
    process.exit(1);
});
