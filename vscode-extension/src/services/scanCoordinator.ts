import * as vscode from 'vscode';
import * as path from 'path';
import * as crypto from 'crypto';
import { EngineManager } from './engineManager';
import { ScanManager } from './scanManager';
import { EngineConnectionStatus, ScanResult } from '../types/slopguard';

export interface QueuedScanItem {
    filePath: string;
    uri: vscode.Uri;
    document?: vscode.TextDocument;
    version?: number;
    contentHash?: string;
    timestamp: number;
    retryCount: number;
    resolve: (result: ScanResult | null) => void;
    reject: (err: any) => void;
}

export class ScanCoordinator implements vscode.Disposable {
    private engineManager: EngineManager;
    private scanManager: ScanManager;
    private outputChannel: vscode.OutputChannel;
    private pendingQueue: Map<string, QueuedScanItem> = new Map();
    private disposables: vscode.Disposable[] = [];
    private isFlushing: boolean = false;
    private readonly maxRetries: number = 3;

    constructor(
        engineManager: EngineManager,
        scanManager: ScanManager,
        outputChannel: vscode.OutputChannel
    ) {
        this.engineManager = engineManager;
        this.scanManager = scanManager;
        this.outputChannel = outputChannel;

        // Subscribe to engine readiness event
        this.disposables.push(
            this.engineManager.onReady(async (status) => {
                this.outputChannel.appendLine('[SLOPGUARD] Engine ready.');
                this.outputChannel.appendLine(`[SLOPGUARD] Engine state: ${status}`);
                await this.flushPendingScans();
            })
        );
    }

    public getPendingQueueSize(): number {
        return this.pendingQueue.size;
    }

    public hasPendingScan(filePath: string): boolean {
        return this.pendingQueue.has(path.normalize(filePath).toLowerCase());
    }

    /**
     * Dispatches or queues a scan request depending on current engine readiness.
     * Deduplicates requests per document path, always preserving the latest document state.
     */
    public async requestScan(
        target: vscode.TextDocument | string,
        isSaveEvent: boolean = false
    ): Promise<ScanResult | null> {
        let filePath: string;
        let document: vscode.TextDocument | undefined;
        let uri: vscode.Uri;
        let contentHash: string | undefined;

        if (typeof target === 'string') {
            filePath = path.normalize(target);
            uri = vscode.Uri.file(filePath);
        } else {
            document = target;
            filePath = path.normalize(target.uri.fsPath);
            uri = target.uri;
            try {
                contentHash = crypto.createHash('sha256').update(target.getText()).digest('hex');
            } catch {
                contentHash = undefined;
            }
        }

        const key = filePath.toLowerCase();

        // 1. Engine is READY (RUNNING_REST or CLI_FALLBACK) -> execute immediately
        if (this.engineManager.isReady()) {
            return this.executeDirectScan(document, filePath);
        }

        // 2. Engine is INITIALIZING / STARTING -> Queue request with deduplication
        const currentStatus = this.engineManager.getConnectionStatus();
        if (this.engineManager.isInitializing() || currentStatus === EngineConnectionStatus.STARTING) {
            this.outputChannel.appendLine(`[SLOPGUARD] Scan queued because engine is not ready.`);
            this.outputChannel.appendLine(`[SLOPGUARD] Engine state: ${currentStatus}`);

            return new Promise<ScanResult | null>((resolve, reject) => {
                // Deduplicate: if an entry already exists for this document, resolve previous with replaced null
                const existing = this.pendingQueue.get(key);
                if (existing) {
                    existing.resolve(null); // Obsolete version superseded
                }

                this.pendingQueue.set(key, {
                    filePath,
                    uri,
                    document,
                    version: document ? document.version : undefined,
                    contentHash,
                    timestamp: Date.now(),
                    retryCount: 0,
                    resolve,
                    reject
                });
            });
        }

        // 3. Engine is STOPPED / UNAVAILABLE -> Attempt bounded wait/retry before failing
        this.outputChannel.appendLine(`[SLOPGUARD] Engine not ready (state: ${currentStatus}). Waiting for engine readiness...`);
        const becameReady = await this.engineManager.waitUntilReady(5000);
        if (becameReady) {
            return this.executeDirectScan(document, filePath);
        }

        const errorMsg = `SLOPGUARD engine is unavailable (status: ${this.engineManager.getConnectionStatus()}). Scan could not be completed for ${filePath}`;
        this.outputChannel.appendLine(`[SLOPGUARD ERROR] ${errorMsg}`);
        throw new Error(errorMsg);
    }

    /**
     * Flushes all pending queued scans once the engine becomes ready.
     */
    public async flushPendingScans(): Promise<void> {
        if (this.isFlushing || this.pendingQueue.size === 0) {
            return;
        }

        this.isFlushing = true;
        this.outputChannel.appendLine('[SLOPGUARD] Flushing pending scan queue.');

        const queuedItems = Array.from(this.pendingQueue.values());
        this.pendingQueue.clear();

        for (const item of queuedItems) {
            try {
                this.outputChannel.appendLine(`[SLOPGUARD] Executing queued scan for: ${item.filePath}`);
                const result = await this.executeDirectScan(item.document, item.filePath);
                item.resolve(result);
            } catch (err: any) {
                if (item.retryCount < this.maxRetries && !this.engineManager.isReady()) {
                    item.retryCount++;
                    this.pendingQueue.set(item.filePath.toLowerCase(), item);
                } else {
                    this.outputChannel.appendLine(`[SLOPGUARD ERROR] Queued scan failed for ${item.filePath}: ${err.message}`);
                    item.reject(err);
                }
            }
        }

        this.isFlushing = false;
    }

    private async executeDirectScan(document: vscode.TextDocument | undefined, filePath: string): Promise<ScanResult | null> {
        if (document && !document.isClosed) {
            return this.scanManager.scanDocument(document);
        }
        return this.scanManager.scanFileByPath(filePath);
    }

    public dispose(): void {
        this.pendingQueue.clear();
        while (this.disposables.length) {
            const d = this.disposables.pop();
            if (d) {
                d.dispose();
            }
        }
    }
}
