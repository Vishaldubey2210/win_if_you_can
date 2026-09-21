import * as crypto from 'crypto';
import * as path from 'path';
import { ScanResult } from '../types/slopguard';

export interface CacheEntry {
    contentHash: string;
    timestamp: number;
    result: ScanResult;
}

export class ScanCache {
    private cache: Map<string, CacheEntry> = new Map();
    private ttlMs: number;

    /**
     * @param ttlMinutes Duration in minutes to consider cached registry results fresh (default 10 min)
     */
    constructor(ttlMinutes: number = 10) {
        this.ttlMs = ttlMinutes * 60 * 1000;
    }

    public computeHash(content: string): string {
        return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    }

    public get(filePath: string, currentContent: string): ScanResult | null {
        const normalized = path.normalize(filePath);
        const entry = this.cache.get(normalized);
        if (!entry) {
            return null;
        }

        // Check if content has changed
        const currentHash = this.computeHash(currentContent);
        if (entry.contentHash !== currentHash) {
            return null; // Content modified
        }

        // Check TTL expiration
        const age = Date.now() - entry.timestamp;
        if (age >= this.ttlMs) {
            this.cache.delete(normalized);
            return null; // TTL expired, requires fresh policy re-evaluation
        }

        return entry.result;
    }

    public set(filePath: string, content: string, result: ScanResult): void {
        const normalized = path.normalize(filePath);
        this.cache.set(normalized, {
            contentHash: this.computeHash(content),
            timestamp: Date.now(),
            result
        });
    }

    public invalidate(filePath: string): void {
        const normalized = path.normalize(filePath);
        this.cache.delete(normalized);
    }

    public clear(): void {
        this.cache.clear();
    }

    public size(): number {
        return this.cache.size;
    }
}
