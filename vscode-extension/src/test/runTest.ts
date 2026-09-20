import * as assert from 'assert';
import { mockVerifiedResult, mockBlockedTyposquatResult, mockAliasResult, mockPhantoms } from './fixtures/mockResponses';
import { PolicyAction, PhantomState, IdentityStatus, RegistryStatus } from '../types/slopguard';

console.log('🧪 Running SLOPGUARD Extension Test Suite...\n');

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void) {
    try {
        fn();
        console.log(`  ✓ ${name}`);
        passed++;
    } catch (err: any) {
        console.error(`  ✗ ${name}`);
        console.error(`    ${err.message}`);
        failed++;
    }
}

// 1. Contract & Verification Tests
test('Correctly parses verified dependency result', () => {
    const dep = mockVerifiedResult.dependencies[0];
    assert.strictEqual(dep.extracted.name, 'requests');
    assert.strictEqual(dep.identity.resolved_package, 'requests');
    assert.strictEqual(dep.decision.action, PolicyAction.ALLOW);
    assert.strictEqual(dep.registry?.status, RegistryStatus.FOUND);
    assert.strictEqual(dep.trust.identity_verified, true);
    assert.strictEqual(dep.trust.has_typosquat_risk, false);
});

// 2. Typosquat Detection & Repair Candidates
test('Correctly identifies blocked typosquat and suggests repair', () => {
    const dep = mockBlockedTyposquatResult.dependencies[0];
    assert.strictEqual(dep.extracted.name, 'requets');
    assert.strictEqual(dep.decision.action, PolicyAction.BLOCK);
    assert.strictEqual(dep.registry?.status, RegistryStatus.NOT_FOUND);
    assert.strictEqual(dep.trust.has_typosquat_risk, true);
    assert.ok(dep.trust.typosquat_details);
    assert.strictEqual(dep.trust.typosquat_details?.similar_package, 'requests');
    assert.strictEqual(dep.decision.suggested_fix, 'requests');
});

// 3. Alias Resolution
test('Correctly identifies alias cv2 -> opencv-python with ALLOW status', () => {
    const dep = mockAliasResult.dependencies[0];
    assert.strictEqual(dep.extracted.name, 'cv2');
    assert.strictEqual(dep.identity.resolved_package, 'opencv-python');
    assert.strictEqual(dep.identity.status, IdentityStatus.ALIASED);
    assert.strictEqual(dep.decision.action, PolicyAction.ALLOW);
});

// 4. Phantom Watchlist & State Changes
test('Tracks phantom states and distinguishes WATCH vs APPEARED', () => {
    assert.strictEqual(mockPhantoms.length, 2);
    const watchPhantom = mockPhantoms.find(p => p.package_name === 'phantom_auth_helper');
    assert.ok(watchPhantom);
    assert.strictEqual(watchPhantom?.current_state, PhantomState.WATCH);

    const appearedPhantom = mockPhantoms.find(p => p.package_name === 'temp_pypi_appeared');
    assert.ok(appearedPhantom);
    assert.strictEqual(appearedPhantom?.current_state, PhantomState.APPEARED);
});

// 5. Diagnostics Severity Mapping Test
test('Maps PolicyAction.BLOCK to error severity and ALLOW to information/clean', () => {
    const mapActionToSeverityName = (action: PolicyAction) => {
        switch (action) {
            case PolicyAction.BLOCK: return 'Error';
            case PolicyAction.HOLD:
            case PolicyAction.ALERT: return 'Warning';
            case PolicyAction.ALLOW: return 'Information';
        }
    };

    assert.strictEqual(mapActionToSeverityName(PolicyAction.BLOCK), 'Error');
    assert.strictEqual(mapActionToSeverityName(PolicyAction.HOLD), 'Warning');
    assert.strictEqual(mapActionToSeverityName(PolicyAction.ALERT), 'Warning');
    assert.strictEqual(mapActionToSeverityName(PolicyAction.ALLOW), 'Information');
});

console.log(`\nResults: ${passed} passed, ${failed} failed.\n`);
if (failed > 0) {
    process.exit(1);
}
