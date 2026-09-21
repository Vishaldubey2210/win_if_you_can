import * as vscode from 'vscode';
import * as http from 'http';
import { spawn, ChildProcess } from 'child_process';
import { EngineConnectionStatus } from '../types/slopguard';
import { CliDiscovery, DiscoveredCli } from './cliDiscovery';

export { EngineConnectionStatus };

export class EngineManager implements vscode.Disposable {
    private currentStatus: EngineConnectionStatus = EngineConnectionStatus.INITIALIZING;
    private spawnedProcess?: ChildProcess;
    private serverUrl: string = 'http://localhost:8000';
    private port: number = 8000;
    private outputChannel: vscode.OutputChannel;
    private onDidChangeStatusEmitter = new vscode.EventEmitter<EngineConnectionStatus>();
    private onReadyEmitter = new vscode.EventEmitter<EngineConnectionStatus>();

    public readonly onDidChangeStatus = this.onDidChangeStatusEmitter.event;
    public readonly onReady = this.onReadyEmitter.event;

    constructor(outputChannel: vscode.OutputChannel) {
        this.outputChannel = outputChannel;
        this.reloadConfiguration();
    }

    public reloadConfiguration(): void {
        const config = vscode.workspace.getConfiguration('slopguard');
        this.serverUrl = config.get<string>('serverUrl') || config.get<string>('server.url', 'http://localhost:8000');
        this.port = config.get<number>('engine.port', 8000);
    }

    public getConnectionStatus(): EngineConnectionStatus {
        return this.currentStatus;
    }

    public isReady(): boolean {
        return this.currentStatus === EngineConnectionStatus.RUNNING_REST || 
               this.currentStatus === EngineConnectionStatus.READY ||
               this.currentStatus === EngineConnectionStatus.CLI_FALLBACK;
    }

    public isInitializing(): boolean {
        return this.currentStatus === EngineConnectionStatus.INITIALIZING ||
               this.currentStatus === EngineConnectionStatus.STARTING;
    }

    /**
     * Waits until the engine transitions to a ready state (RUNNING_REST, READY, or CLI_FALLBACK).
     */
    public async waitUntilReady(timeoutMs: number = 30000): Promise<boolean> {
        if (this.isReady()) {
            return true;
        }
        if (this.currentStatus === EngineConnectionStatus.ERROR || this.currentStatus === EngineConnectionStatus.UNAVAILABLE) {
            return false;
        }

        return new Promise<boolean>((resolve) => {
            let timer: NodeJS.Timeout;
            const listener = this.onDidChangeStatus((status) => {
                if (status === EngineConnectionStatus.RUNNING_REST || 
                    status === EngineConnectionStatus.READY || 
                    status === EngineConnectionStatus.CLI_FALLBACK) {
                    clearTimeout(timer);
                    listener.dispose();
                    resolve(true);
                } else if (status === EngineConnectionStatus.ERROR || status === EngineConnectionStatus.UNAVAILABLE) {
                    clearTimeout(timer);
                    listener.dispose();
                    resolve(false);
                }
            });

            timer = setTimeout(() => {
                listener.dispose();
                resolve(this.isReady());
            }, timeoutMs);
        });
    }

    public getServerUrl(): string {
        return this.serverUrl;
    }

    private setStatus(newStatus: EngineConnectionStatus): void {
        if (this.currentStatus !== newStatus) {
            this.currentStatus = newStatus;
            this.outputChannel.appendLine(`[SLOPGUARD Engine] Connection status changed to: ${newStatus}`);
            this.onDidChangeStatusEmitter.fire(newStatus);

            if (newStatus === EngineConnectionStatus.RUNNING_REST || 
                newStatus === EngineConnectionStatus.READY || 
                newStatus === EngineConnectionStatus.CLI_FALLBACK) {
                this.onReadyEmitter.fire(newStatus);
            }
        }
    }

    /**
     * Checks if the REST engine health endpoint is responding.
     */
    public async healthCheck(timeoutMs: number = 2000): Promise<boolean> {
        return new Promise<boolean>((resolve) => {
            try {
                const parsedUrl = new URL('/api/v1/health', this.serverUrl);
                const req = http.get(
                    {
                        hostname: parsedUrl.hostname,
                        port: parsedUrl.port || 80,
                        path: parsedUrl.pathname,
                        timeout: timeoutMs
                    },
                    (res) => {
                        let rawData = '';
                        res.on('data', chunk => { rawData += chunk; });
                        res.on('end', () => {
                            if (res.statusCode === 200) {
                                try {
                                    const json = JSON.parse(rawData);
                                    resolve(json.status === 'healthy' || json.status === 'ok');
                                } catch {
                                    resolve(true); // 200 OK
                                }
                            } else {
                                resolve(false);
                            }
                        });
                    }
                );

                req.on('error', () => resolve(false));
                req.on('timeout', () => {
                    req.destroy();
                    resolve(false);
                });
            } catch {
                resolve(false);
            }
        });
    }

    /**
     * Resolves the best available Python executable or slopguard binary using CliDiscovery.
     */
    public async resolveExecutable(): Promise<{ command: string; args: string[]; isPythonModule: boolean } | null> {
        const discovered = await CliDiscovery.discover(undefined, this.outputChannel);
        if (!discovered) {
            return null;
        }

        if (discovered.isPythonModule) {
            return {
                command: discovered.command,
                args: [...discovered.baseArgs, 'serve', '--host', '127.0.0.1', '--port', String(this.port)],
                isPythonModule: true
            };
        }

        return {
            command: discovered.command,
            args: ['serve', '--host', '127.0.0.1', '--port', String(this.port)],
            isPythonModule: false
        };
    }

    /**
     * Starts the SLOPGUARD REST engine daemon as a background child process.
     */
    public async startEngine(): Promise<boolean> {
        // If already serving and healthy, don't spawn duplicate
        const alreadyRunning = await this.healthCheck(1500);
        if (alreadyRunning) {
            this.setStatus(EngineConnectionStatus.RUNNING_REST);
            return true;
        }

        const execInfo = await this.resolveExecutable();
        if (!execInfo) {
            this.outputChannel.appendLine('[SLOPGUARD Engine] Could not locate Python or slopguard executable.');
            return false;
        }

        this.setStatus(EngineConnectionStatus.STARTING);
        this.outputChannel.appendLine(`[SLOPGUARD Engine] Starting daemon: ${execInfo.command} ${execInfo.args.join(' ')}`);

        try {
            const augmentedEnv = CliDiscovery.getAugmentedEnv();
            const child = spawn(execInfo.command, execInfo.args, {
                detached: false,
                stdio: ['ignore', 'pipe', 'pipe'],
                windowsHide: true,
                env: augmentedEnv
            });

            this.spawnedProcess = child;

            child.stdout?.on('data', (data) => {
                const text = data.toString().trim();
                if (text) {
                    this.outputChannel.appendLine(`[SLOPGUARD Server stdout] ${text}`);
                }
            });

            child.stderr?.on('data', (data) => {
                const text = data.toString().trim();
                if (text) {
                    this.outputChannel.appendLine(`[SLOPGUARD Server stderr] ${text}`);
                }
            });

            child.on('error', (err) => {
                this.outputChannel.appendLine(`[SLOPGUARD Server process spawn error] ${err.message}`);
                this.spawnedProcess = undefined;
            });

            child.on('exit', (code, signal) => {
                this.outputChannel.appendLine(`[SLOPGUARD Server process exited] code: ${code}, signal: ${signal}`);
                this.spawnedProcess = undefined;
                if (this.currentStatus === EngineConnectionStatus.RUNNING_REST || this.currentStatus === EngineConnectionStatus.READY) {
                    this.setStatus(EngineConnectionStatus.OFFLINE);
                }
            });

            // Wait for health check with retries up to startupTimeoutSeconds
            const config = vscode.workspace.getConfiguration('slopguard');
            const timeoutSeconds = config.get<number>('engine.startupTimeoutSeconds', 15);
            const startTime = Date.now();
            const maxWaitMs = timeoutSeconds * 1000;

            while (Date.now() - startTime < maxWaitMs) {
                await new Promise(r => setTimeout(r, 600));
                const healthy = await this.healthCheck(1000);
                if (healthy) {
                    this.setStatus(EngineConnectionStatus.RUNNING_REST);
                    this.outputChannel.appendLine(`[SLOPGUARD Engine] REST control plane ready at ${this.serverUrl}`);
                    return true;
                }
            }

            this.outputChannel.appendLine(`[SLOPGUARD Engine] Startup timed out after ${timeoutSeconds}s.`);
            return false;
        } catch (err: any) {
            this.outputChannel.appendLine(`[SLOPGUARD Engine] Failed to spawn process: ${err.message}`);
            return false;
        }
    }

    /**
     * Ensures an engine connection is active (REST preferred, falls back to CLI).
     */
    public async ensureRunning(): Promise<boolean> {
        this.reloadConfiguration();
        this.setStatus(EngineConnectionStatus.INITIALIZING);

        // 1. Check if REST is already healthy
        const isHealthy = await this.healthCheck(1500);
        if (isHealthy) {
            this.setStatus(EngineConnectionStatus.RUNNING_REST);
            return true;
        }

        // 2. Try auto-starting local REST engine
        const config = vscode.workspace.getConfiguration('slopguard');
        const autoStart = config.get<boolean>('engine.autoStart', true);
        if (autoStart) {
            const started = await this.startEngine();
            if (started) {
                return true;
            }
        }

        // 3. Fallback: Check if CLI can be invoked
        const discovered = await CliDiscovery.discover(undefined, this.outputChannel);
        if (discovered) {
            this.setStatus(EngineConnectionStatus.CLI_FALLBACK);
            this.outputChannel.appendLine('[SLOPGUARD Engine] REST engine unavailable; operating in local CLI fallback mode.');
            return true;
        }

        this.setStatus(EngineConnectionStatus.ERROR);
        this.outputChannel.appendLine('[SLOPGUARD Engine] Neither REST engine nor CLI fallback could be established.');
        return false;
    }

    /**
     * Stops the engine if spawned by this extension.
     */
    public async stopEngine(): Promise<void> {
        if (this.spawnedProcess) {
            this.outputChannel.appendLine('[SLOPGUARD Engine] Stopping background engine process...');
            try {
                this.spawnedProcess.kill('SIGTERM');
                await new Promise(r => setTimeout(r, 500));
                if (this.spawnedProcess && !this.spawnedProcess.killed) {
                    this.spawnedProcess.kill('SIGKILL');
                }
            } catch (err: any) {
                this.outputChannel.appendLine(`[SLOPGUARD Engine] Error terminating process: ${err.message}`);
            }
            this.spawnedProcess = undefined;
        }
        this.setStatus(EngineConnectionStatus.OFFLINE);
    }

    public dispose(): void {
        this.stopEngine();
        this.onDidChangeStatusEmitter.dispose();
        this.onReadyEmitter.dispose();
    }
}
