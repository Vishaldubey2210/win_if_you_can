import { execFile } from 'child_process';
import { promisify } from 'util';
import * as vscode from 'vscode';
import { ScanResult, RegistryEvidence } from '../types/slopguard';
import { CliDiscovery, DiscoveredCli } from './cliDiscovery';

const execFileAsync = promisify(execFile);

export interface CliInvocation {
    command: string;
    baseArgs: string[];
    displayPath?: string;
}

export class CliClient {
    private cliPath: string;
    private outputChannel?: vscode.OutputChannel;
    private cachedInvocation?: CliInvocation;

    constructor(cliPath: string = 'slopguard', outputChannel?: vscode.OutputChannel) {
        this.cliPath = cliPath;
        this.outputChannel = outputChannel;
    }

    public setOutputChannel(channel: vscode.OutputChannel): void {
        this.outputChannel = channel;
    }

    public updateCliPath(pathStr: string): void {
        this.cliPath = pathStr;
        this.cachedInvocation = undefined;
        CliDiscovery.clearCache();
    }

    public getAugmentedEnv(): NodeJS.ProcessEnv {
        return CliDiscovery.getAugmentedEnv();
    }

    public async discoverCli(): Promise<DiscoveredCli | null> {
        const discovered = await CliDiscovery.discover(this.cliPath, this.outputChannel);
        if (discovered) {
            this.cachedInvocation = {
                command: discovered.command,
                baseArgs: discovered.baseArgs,
                displayPath: discovered.displayPath
            };
        }
        return discovered;
    }

    public getResolvedInvocation(): CliInvocation {
        if (this.cachedInvocation) {
            return this.cachedInvocation;
        }

        // Return current configured path with no baseArgs as synchronous fallback
        return {
            command: this.cliPath || 'slopguard',
            baseArgs: [],
            displayPath: this.cliPath || 'slopguard'
        };
    }

    public getResolvedPath(): string {
        return this.getResolvedInvocation().command;
    }

    public async isAvailable(): Promise<boolean> {
        const discovered = await this.discoverCli();
        return discovered !== null;
    }

    public async scanFile(filePath: string, profile?: string): Promise<ScanResult> {
        // Ensure CLI is discovered
        if (!this.cachedInvocation) {
            await this.discoverCli();
        }

        const inv = this.getResolvedInvocation();
        const args = [...inv.baseArgs, 'scan', filePath, '--json'];
        if (profile) {
            args.push('--profile', profile.toLowerCase());
        }

        this.outputChannel?.appendLine('[SLOPGUARD] CLI scan started.');

        try {
            const { stdout } = await execFileAsync(inv.command, args, {
                env: this.getAugmentedEnv(),
                maxBuffer: 15 * 1024 * 1024,
                timeout: 30000
            });
            this.outputChannel?.appendLine('[SLOPGUARD] CLI scan completed.');
            return JSON.parse(stdout) as ScanResult;
        } catch (error: any) {
            // If the process exited with code 1 or 2 (blocked dependencies), stdout still contains the JSON
            if (error.stdout) {
                try {
                    const parsed = JSON.parse(error.stdout) as ScanResult;
                    this.outputChannel?.appendLine('[SLOPGUARD] CLI scan completed.');
                    return parsed;
                } catch {
                    // Fallthrough
                }
            }
            const errMsg = error.stderr ? `${error.message}: ${error.stderr}` : error.message;
            this.outputChannel?.appendLine(`[SLOPGUARD ERROR] CLI scan failed: ${errMsg}`);
            throw new Error(`SLOPGUARD CLI scan failed: ${errMsg}`);
        }
    }

    public async verify(packageName: string, ecosystem: string = 'pypi'): Promise<RegistryEvidence> {
        if (!this.cachedInvocation) {
            await this.discoverCli();
        }

        const inv = this.getResolvedInvocation();
        const args = [...inv.baseArgs, 'verify', packageName, '--ecosystem', ecosystem, '--json'];
        const { stdout } = await execFileAsync(inv.command, args, {
            env: this.getAugmentedEnv(),
            timeout: 15000
        });
        return JSON.parse(stdout) as RegistryEvidence;
    }
}
