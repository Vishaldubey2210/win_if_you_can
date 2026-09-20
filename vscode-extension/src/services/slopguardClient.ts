import {
    HealthCheckResponse,
    PhantomRecord,
    ProposeRepairResponse,
    RegistryEvidence,
    RescanValidation,
    ScanResult,
    TrustAssessment
} from '../types/slopguard';

export class SlopguardClient {
    private baseUrl: string;
    private timeoutMs: number;

    constructor(baseUrl: string = 'http://localhost:8000', timeoutMs: number = 8000) {
        this.baseUrl = baseUrl.replace(/\/+$/, '');
        this.timeoutMs = timeoutMs;
    }

    public updateBaseUrl(url: string): void {
        this.baseUrl = url.replace(/\/+$/, '');
    }

    private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
        const url = `${this.baseUrl}${path}`;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal,
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Client': 'vscode-slopguard',
                    ...(options.headers || {})
                }
            });

            if (!response.ok) {
                const errorText = await response.text().catch(() => response.statusText);
                throw new Error(`SLOPGUARD API error (${response.status}): ${errorText}`);
            }

            return await response.json() as T;
        } catch (error: any) {
            if (error.name === 'AbortError') {
                throw new Error(`SLOPGUARD request timed out after ${this.timeoutMs}ms`);
            }
            throw error;
        } finally {
            clearTimeout(timeoutId);
        }
    }

    public async checkHealth(): Promise<HealthCheckResponse> {
        return this.request<HealthCheckResponse>('/api/v1/health');
    }

    public async isHealthy(): Promise<boolean> {
        try {
            const health = await this.checkHealth();
            return health.status === 'healthy';
        } catch {
            return false;
        }
    }

    public async scanCode(content: string, language: string = 'python', filePath: string = '<api_payload>'): Promise<ScanResult> {
        return this.request<ScanResult>('/api/v1/scan', {
            method: 'POST',
            body: JSON.stringify({
                content,
                language,
                source_label: filePath
            })
        });
    }

    public async verify(ecosystem: string, packageName: string): Promise<RegistryEvidence> {
        return this.request<RegistryEvidence>(`/api/v1/verify/${encodeURIComponent(ecosystem)}/${encodeURIComponent(packageName)}`);
    }

    public async verifyPackage(packageName: string, ecosystem: string = 'pypi'): Promise<RegistryEvidence> {
        return this.verify(ecosystem, packageName);
    }

    public async getEvidence(ecosystem: string, packageName: string): Promise<any> {
        return this.request<any>(`/api/v1/evidence/${encodeURIComponent(ecosystem)}/${encodeURIComponent(packageName)}`);
    }

    public async getTrust(ecosystem: string, packageName: string): Promise<TrustAssessment> {
        return this.request<TrustAssessment>(`/api/v1/trust/${encodeURIComponent(ecosystem)}/${encodeURIComponent(packageName)}`);
    }

    public async getGraph(ecosystem: string, packageName: string): Promise<any> {
        return this.request<any>(`/api/v1/graph/${encodeURIComponent(ecosystem)}/${encodeURIComponent(packageName)}`);
    }

    public async getPhantoms(): Promise<PhantomRecord[]> {
        return this.request<PhantomRecord[]>('/api/v1/phantoms');
    }

    public async getHistory(ecosystem: string, packageName: string): Promise<any> {
        return this.request<any>(`/api/v1/history/${encodeURIComponent(ecosystem)}/${encodeURIComponent(packageName)}`);
    }

    public async proposeRepair(dependencyName: string, code: string, ecosystem: string = 'pypi'): Promise<ProposeRepairResponse> {
        return this.request<ProposeRepairResponse>('/api/v1/repair/propose', {
            method: 'POST',
            body: JSON.stringify({
                dependency_name: dependencyName,
                code,
                ecosystem
            })
        });
    }

    public async rescanRepair(patchedCode: string, language: string = 'python'): Promise<RescanValidation> {
        return this.request<RescanValidation>('/api/v1/repair/rescan', {
            method: 'POST',
            body: JSON.stringify({
                patched_code: patchedCode,
                language
            })
        });
    }
}
