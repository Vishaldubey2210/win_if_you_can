import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { ScanResult, RegistryEvidence } from '../types/slopguard';

const execFileAsync = promisify(execFile);

export class CliClient {
    private cliPath: string;

    constructor(cliPath: string = 'slopguard') {
        this.cliPath = cliPath;
    }

    public updateCliPath(pathStr: string): void {
        this.cliPath = pathStr;
    }

    public getResolvedPath(): string {
        if (this.cliPath && this.cliPath !== 'slopguard') {
            return this.cliPath;
        }

        // Check workspace virtualenvs automatically
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders) {
            for (const folder of workspaceFolders) {
                const root = folder.uri.fsPath;
                const candidates = [
                    path.join(root, '.venv', 'Scripts', 'slopguard.exe'),
                    path.join(root, '.venv', 'bin', 'slopguard'),
                    path.join(root, 'venv', 'Scripts', 'slopguard.exe'),
                    path.join(root, 'venv', 'bin', 'slopguard'),
                    path.join(root, '.venv', 'Scripts', 'slopguard'),
                    path.join(root, 'venv', 'Scripts', 'slopguard')
                ];

                for (const cand of candidates) {
                    if (fs.existsSync(cand)) {
                        return cand;
                    }
                }
            }
        }

        return this.cliPath || 'slopguard';
    }

    public async isAvailable(): Promise<boolean> {
        const exe = this.getResolvedPath();
        try {
            const { stdout } = await execFileAsync(exe, ['--version']);
            return stdout.toLowerCase().includes('slopguard');
        } catch {
            return false;
        }
    }

    public async scanFile(filePath: string, profile?: string): Promise<ScanResult> {
        const exe = this.getResolvedPath();
        const args = ['scan', filePath, '--json'];
        if (profile) {
            args.push('--profile', profile.toLowerCase());
        }

        try {
            const { stdout } = await execFileAsync(exe, args, { maxBuffer: 10 * 1024 * 1024 });
            return JSON.parse(stdout) as ScanResult;
        } catch (error: any) {
            // If the process exited with code 1 or 2 (blocked dependencies), stdout still contains the JSON
            if (error.stdout) {
                try {
                    return JSON.parse(error.stdout) as ScanResult;
                } catch {
                    // Fallthrough to throw original error
                }
            }
            throw new Error(`SLOPGUARD CLI scan failed: ${error.message || error}`);
        }
    }

    public async verify(packageName: string, ecosystem: string = 'pypi'): Promise<RegistryEvidence> {
        const exe = this.getResolvedPath();
        const args = ['verify', packageName, '--ecosystem', ecosystem, '--json'];
        const { stdout } = await execFileAsync(exe, args);
        return JSON.parse(stdout) as RegistryEvidence;
    }
}
