const fs = require('fs');
const path = require('path');

// Hook vscode module
require('../vscode-extension/out/test/mockVscode');
const { CliDiscovery } = require('../vscode-extension/out/services/cliDiscovery');
const { CliClient } = require('../vscode-extension/out/services/cliClient');
const { DiagnosticsProvider } = require('../vscode-extension/out/providers/diagnosticsProvider');
const { MockOutputChannel, MockUri } = require('../vscode-extension/out/test/mockVscode');

async function runAcceptanceTest() {
    console.log('🚀 Starting Real-World Acceptance Test for SLOPGUARD...');

    const testFile = path.resolve(__dirname, '../test.py');
    const outputChannel = new MockOutputChannel();

    // 1. Verify automatic CLI discovery
    console.log('\n[Step 1] Running automatic CLI discovery...');
    const discovered = await CliDiscovery.discover(undefined, outputChannel);
    if (!discovered) {
        throw new Error('Automatic CLI discovery failed!');
    }
    console.log(`✓ Discovered CLI at: ${discovered.displayPath}`);
    console.log(`✓ Version: ${discovered.version}`);

    // 2. Initialize real CliClient
    const client = new CliClient('slopguard', outputChannel);

    // 3. Scan test.py with (requests, requets, cv2)
    console.log('\n[Step 2] Scanning test.py with buggy import "requets"...');
    fs.writeFileSync(testFile, 'import requests\nimport requets\nimport cv2\n', 'utf8');

    const result1 = await client.scanFile(testFile);
    console.log(`✓ Scan finished. Total extracted: ${result1.dependencies.length}`);

    const reqDep = result1.dependencies.find(d => d.extracted.name === 'requests');
    const badDep = result1.dependencies.find(d => d.extracted.name === 'requets');
    const cv2Dep = result1.dependencies.find(d => d.extracted.name === 'cv2');

    console.log(`- requests verdict: ${reqDep?.decision?.action} (expected ALLOW)`);
    console.log(`- requets verdict: ${badDep?.decision?.action} (expected BLOCK)`);
    console.log(`- cv2 canonical: ${cv2Dep?.identity?.resolved_package} (expected opencv-python)`);

    if (reqDep?.decision?.action !== 'ALLOW') throw new Error('requests was not ALLOW!');
    if (badDep?.decision?.action !== 'BLOCK') throw new Error('requets was not BLOCK!');
    if (cv2Dep?.identity?.resolved_package !== 'opencv-python') throw new Error('cv2 did not resolve to opencv-python!');

    // 4. Test Diagnostics publication
    const diagProvider = new DiagnosticsProvider({ onScanCompleted: () => {} });
    diagProvider.updateDiagnostics(testFile, result1);
    let diags = diagProvider.diagnosticCollection.get(MockUri.file(testFile));
    console.log(`✓ Published diagnostics count: ${diags ? diags.length : 0}`);
    if (!diags || diags.length !== 1) throw new Error('Expected 1 BLOCK diagnostic for requets!');
    console.log(`✓ Diagnostic message snippet: \n${diags[0].message}`);

    // 5. User fixes requets -> requests
    console.log('\n[Step 3] Fixing "requets" -> "requests" and rescanning...');
    fs.writeFileSync(testFile, 'import requests\nimport cv2\n', 'utf8');
    const result2 = await client.scanFile(testFile);
    diagProvider.updateDiagnostics(testFile, result2);
    diags = diagProvider.diagnosticCollection.get(MockUri.file(testFile));
    const diagCount = diags ? diags.length : 0;
    console.log(`✓ Diagnostics count after fix: ${diagCount} (expected 0)`);
    if (diagCount !== 0) throw new Error('Diagnostics should be cleared after fix!');

    // 6. User introduces bad import again
    console.log('\n[Step 4] Changing back to "requets" and rescanning...');
    fs.writeFileSync(testFile, 'import requests\nimport requets\nimport cv2\n', 'utf8');
    const result3 = await client.scanFile(testFile);
    diagProvider.updateDiagnostics(testFile, result3);
    diags = diagProvider.diagnosticCollection.get(MockUri.file(testFile));
    console.log(`✓ Diagnostics count after re-introducing bug: ${diags ? diags.length : 0} (expected 1)`);
    if (!diags || diags.length !== 1) throw new Error('BLOCK diagnostic should reappear!');

    console.log('\n🎉 ALL REAL-WORLD ACCEPTANCE CRITERIA MET AND VERIFIED!');
}

runAcceptanceTest().catch(err => {
    console.error('Acceptance test failed:', err);
    process.exit(1);
});
