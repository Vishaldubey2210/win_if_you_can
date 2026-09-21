export enum PolicyAction {
    ALLOW = 'ALLOW',
    HOLD = 'HOLD',
    BLOCK = 'BLOCK',
    ALERT = 'ALERT'
}

export enum RegistryStatus {
    FOUND = 'FOUND',
    NOT_FOUND = 'NOT_FOUND',
    RATE_LIMITED = 'RATE_LIMITED',
    SERVER_ERROR = 'SERVER_ERROR',
    TIMEOUT = 'TIMEOUT',
    NETWORK_ERROR = 'NETWORK_ERROR',
    MALFORMED_RESPONSE = 'MALFORMED_RESPONSE',
    SKIPPED = 'SKIPPED'
}

export enum IdentityStatus {
    RESOLVED = 'RESOLVED',
    ALIASED = 'ALIASED',
    STDLIB = 'STDLIB',
    UNRESOLVED = 'UNRESOLVED',
    AMBIGUOUS = 'AMBIGUOUS'
}

export enum TrustLevel {
    VERIFIED = 'VERIFIED',
    REVIEW = 'REVIEW',
    SUSPICIOUS = 'SUSPICIOUS',
    UNRESOLVED = 'UNRESOLVED'
}

export enum PhantomState {
    NONE = 'NONE',
    NOT_FOUND = 'NOT_FOUND',
    WATCH = 'WATCH',
    APPEARED = 'APPEARED',
    RESOLVED = 'RESOLVED'
}

export enum EngineConnectionStatus {
    INITIALIZING = 'INITIALIZING',
    STARTING = 'STARTING',
    READY = 'READY',
    RUNNING_REST = 'RUNNING_REST',
    CLI_FALLBACK = 'CLI_FALLBACK',
    OFFLINE = 'OFFLINE',
    STOPPED = 'STOPPED',
    ERROR = 'ERROR',
    UNAVAILABLE = 'UNAVAILABLE'
}

export type Ecosystem = 'pypi' | 'npm' | 'unknown';

export interface ExtractedDependency {
    name: string;
    version_constraint?: string;
    ecosystem: Ecosystem;
    source_type?: string;
    file_path?: string;
    line_number?: number;
    raw_statement?: string;
    is_stdlib: boolean;
    is_relative: boolean;
}

export interface IdentityResolution {
    input_name: string;
    normalized_name: string;
    resolved_package: string;
    ecosystem: Ecosystem;
    status: IdentityStatus;
    confidence: number;
    is_stdlib: boolean;
    evidence_notes: string[];
}

export interface RegistryEvidence {
    package_name: string;
    ecosystem: Ecosystem;
    status: RegistryStatus;
    http_status?: number;
    latest_version?: string;
    all_versions?: string[];
    release_count?: number;
    first_release_time?: string;
    latest_release_time?: string;
    repository_url?: string;
    homepage_url?: string;
    author?: string;
    maintainers?: string[];
    description_summary?: string;
    latency_ms?: number;
    error_message?: string;
    cached?: boolean;
    timestamp?: string;
}

export interface TyposquatCandidate {
    target_package: string;
    similar_package: string;
    distance: number;
    similarity_ratio: float;
    confidence: number;
    reason: string;
}

export interface TrustAssessment {
    package_name: string;
    ecosystem: Ecosystem;
    level: TrustLevel;
    identity_verified: boolean;
    registry_verified: boolean;
    is_stdlib: boolean;
    has_typosquat_risk: boolean;
    typosquat_details?: TyposquatCandidate;
    signals: Record<string, any>;
    reasons: string[];
}

export interface PolicySimulationResult {
    policy_profile: string;
    policy_version: string;
    package: string;
    simulated_action: PolicyAction;
    risk_level: string;
    requires_human_review: boolean;
    reasons: string[];
    suggested_fix?: string;
}

export function extractSuggestedTarget(dep: EvaluatedDependency): { target: string; reason: string } | undefined {
    if (dep.trust.typosquat_details?.similar_package) {
        return {
            target: dep.trust.typosquat_details.similar_package,
            reason: dep.trust.typosquat_details.reason
        };
    }

    const stdlibAlts: Record<string, string> = {
        'pytz': 'zoneinfo',
        'simplejson': 'json',
        'mock': 'unittest.mock',
        'pathlib2': 'pathlib',
        'six': 'builtins'
    };
    const lowerName = dep.extracted.name.toLowerCase();
    if (stdlibAlts[lowerName]) {
        return {
            target: stdlibAlts[lowerName],
            reason: `Modern standard library replacement: '${stdlibAlts[lowerName]}'`
        };
    }

    if (dep.decision.suggested_fix) {
        const fix = dep.decision.suggested_fix;
        const match = /['"`]([a-zA-Z0-9_\-\.]+)['"`]/.exec(fix);
        if (match && match[1].toLowerCase() !== dep.extracted.name.toLowerCase()) {
            return {
                target: match[1],
                reason: fix
            };
        }
        if (!fix.includes(' ')) {
            return {
                target: fix,
                reason: 'Recommended canonical package alternative.'
            };
        }
    }

    return undefined;
}

export interface PolicyDecision {
    action: PolicyAction;
    reasons: string[];
    risk_level: string;
    confidence: number;
    requires_human_review: boolean;
    suggested_fix?: string;
}

export interface EvaluatedDependency {
    extracted: ExtractedDependency;
    identity: IdentityResolution;
    registry?: RegistryEvidence;
    trust: TrustAssessment;
    phantom_state: PhantomState;
    decision: PolicyDecision;
    timestamp?: string;
}

export interface ScanSummary {
    total_extracted: number;
    stdlib_count: number;
    allowed_count: number;
    hold_count: number;
    blocked_count: number;
    alert_count: number;
    duration_ms?: number;
}

export interface ScanResult {
    scan_id: string;
    timestamp?: string;
    source_label?: string;
    ecosystem?: Ecosystem;
    file_path?: string;
    language?: string;
    dependencies: EvaluatedDependency[];
    summary: ScanSummary;
}

export interface StateTransition {
    from_state: PhantomState;
    to_state: PhantomState;
    timestamp: string;
    reason: string;
}

export interface PhantomRecord {
    package_name: string;
    ecosystem: Ecosystem;
    first_seen: string;
    last_seen: string;
    occurrence_count: number;
    current_state: PhantomState;
    previous_state: PhantomState;
    transitions: StateTransition[];
    last_known_registry_status?: RegistryStatus;
    notes: string[];
}

export interface RepairCandidate {
    candidate_package: string;
    original_dependency: string;
    ecosystem: Ecosystem;
    confidence: number;
    compatibility_score?: number;
    reason: string;
    is_stdlib_alternative?: boolean;
    evidence_notes?: string[];
}

export interface PatchProposal {
    original_code: string;
    patched_code: string;
    original_import: string;
    replacement_import: string;
    diff: string;
    candidate: RepairCandidate;
}

export interface RescanValidation {
    success: boolean;
    rescan_verdict: PolicyAction;
    reasons: string[];
    remaining_blocked_count: number;
}

export interface ProposeRepairResponse {
    dependency: string;
    ecosystem: string;
    candidate_count: number;
    proposals: PatchProposal[];
}

export interface HealthCheckResponse {
    status: string;
    service: string;
    version: string;
    features?: string[];
}
type float = number;
