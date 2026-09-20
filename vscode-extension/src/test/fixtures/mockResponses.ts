import {
    PolicyAction,
    ScanResult,
    PhantomState,
    PhantomRecord,
    IdentityStatus,
    RegistryStatus,
    TrustLevel
} from '../../types/slopguard';

export const mockVerifiedResult: ScanResult = {
    scan_id: 'scan-test-001',
    timestamp: '2026-09-20T12:00:00Z',
    file_path: 'app.py',
    language: 'python',
    summary: {
        total_extracted: 1,
        stdlib_count: 0,
        allowed_count: 1,
        hold_count: 0,
        blocked_count: 0,
        alert_count: 0
    },
    dependencies: [
        {
            extracted: {
                name: 'requests',
                line_number: 1,
                ecosystem: 'pypi',
                is_stdlib: false,
                is_relative: false
            },
            identity: {
                input_name: 'requests',
                normalized_name: 'requests',
                resolved_package: 'requests',
                ecosystem: 'pypi',
                status: IdentityStatus.RESOLVED,
                confidence: 1.0,
                is_stdlib: false,
                evidence_notes: ['Exact PyPI match']
            },
            registry: {
                package_name: 'requests',
                ecosystem: 'pypi',
                status: RegistryStatus.FOUND,
                latest_version: '2.31.0',
                release_count: 45,
                repository_url: 'https://github.com/psf/requests'
            },
            trust: {
                package_name: 'requests',
                ecosystem: 'pypi',
                level: TrustLevel.VERIFIED,
                identity_verified: true,
                registry_verified: true,
                is_stdlib: false,
                has_typosquat_risk: false,
                signals: {},
                reasons: ['Verified official library']
            },
            phantom_state: PhantomState.NONE,
            decision: {
                action: PolicyAction.ALLOW,
                reasons: ['Package verified with high trust and clean advisory history'],
                risk_level: 'LOW',
                confidence: 0.98,
                requires_human_review: false
            }
        }
    ]
};

export const mockBlockedTyposquatResult: ScanResult = {
    scan_id: 'scan-test-002',
    timestamp: '2026-09-20T12:01:00Z',
    file_path: 'app.py',
    language: 'python',
    summary: {
        total_extracted: 1,
        stdlib_count: 0,
        allowed_count: 0,
        hold_count: 0,
        blocked_count: 1,
        alert_count: 0
    },
    dependencies: [
        {
            extracted: {
                name: 'requets',
                line_number: 2,
                ecosystem: 'pypi',
                is_stdlib: false,
                is_relative: false
            },
            identity: {
                input_name: 'requets',
                normalized_name: 'requets',
                resolved_package: 'requets',
                ecosystem: 'pypi',
                status: IdentityStatus.UNRESOLVED,
                confidence: 0.1,
                is_stdlib: false,
                evidence_notes: ['Not found on PyPI']
            },
            registry: {
                package_name: 'requets',
                ecosystem: 'pypi',
                status: RegistryStatus.NOT_FOUND
            },
            trust: {
                package_name: 'requets',
                ecosystem: 'pypi',
                level: TrustLevel.SUSPICIOUS,
                identity_verified: false,
                registry_verified: false,
                is_stdlib: false,
                has_typosquat_risk: true,
                typosquat_details: {
                    target_package: 'requets',
                    similar_package: 'requests',
                    distance: 1,
                    similarity_ratio: 0.93,
                    confidence: 0.95,
                    reason: 'Typosquat detected for popular package requests'
                },
                signals: {},
                reasons: ['High probability typosquat']
            },
            phantom_state: PhantomState.NOT_FOUND,
            decision: {
                action: PolicyAction.BLOCK,
                reasons: [
                    'Package does not exist on PyPI registry (HTTP 404)',
                    'High probability typosquat of popular package requests'
                ],
                risk_level: 'CRITICAL',
                confidence: 0.95,
                requires_human_review: true,
                suggested_fix: 'requests'
            }
        }
    ]
};

export const mockAliasResult: ScanResult = {
    scan_id: 'scan-test-003',
    timestamp: '2026-09-20T12:02:00Z',
    file_path: 'vision.py',
    language: 'python',
    summary: {
        total_extracted: 1,
        stdlib_count: 0,
        allowed_count: 1,
        hold_count: 0,
        blocked_count: 0,
        alert_count: 0
    },
    dependencies: [
        {
            extracted: {
                name: 'cv2',
                line_number: 1,
                ecosystem: 'pypi',
                is_stdlib: false,
                is_relative: false
            },
            identity: {
                input_name: 'cv2',
                normalized_name: 'cv2',
                resolved_package: 'opencv-python',
                ecosystem: 'pypi',
                status: IdentityStatus.ALIASED,
                confidence: 1.0,
                is_stdlib: false,
                evidence_notes: ['Known import alias']
            },
            registry: {
                package_name: 'opencv-python',
                ecosystem: 'pypi',
                status: RegistryStatus.FOUND,
                latest_version: '4.8.1.78'
            },
            trust: {
                package_name: 'opencv-python',
                ecosystem: 'pypi',
                level: TrustLevel.VERIFIED,
                identity_verified: true,
                registry_verified: true,
                is_stdlib: false,
                has_typosquat_risk: false,
                signals: {},
                reasons: ['Official package']
            },
            phantom_state: PhantomState.NONE,
            decision: {
                action: PolicyAction.ALLOW,
                reasons: ['Import alias cv2 resolved to official package opencv-python'],
                risk_level: 'LOW',
                confidence: 0.95,
                requires_human_review: false
            }
        }
    ]
};

export const mockPhantoms: PhantomRecord[] = [
    {
        package_name: 'phantom_auth_helper',
        ecosystem: 'pypi',
        first_seen: '2026-09-18T10:00:00Z',
        last_seen: '2026-09-20T12:00:00Z',
        occurrence_count: 5,
        current_state: PhantomState.WATCH,
        previous_state: PhantomState.NOT_FOUND,
        transitions: [],
        notes: ['Observed in LLM test prompt']
    },
    {
        package_name: 'temp_pypi_appeared',
        ecosystem: 'pypi',
        first_seen: '2026-09-10T10:00:00Z',
        last_seen: '2026-09-20T13:00:00Z',
        occurrence_count: 1,
        current_state: PhantomState.APPEARED,
        previous_state: PhantomState.NOT_FOUND,
        transitions: [],
        notes: ['State change alert']
    }
];
