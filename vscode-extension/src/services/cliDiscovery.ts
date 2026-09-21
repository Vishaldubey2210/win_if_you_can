import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as vscode from 'vscode';

const execFileAsync = promisify(execFile);

export interface DiscoveredCli {
    command: string;
    baseArgs: string[];
    version?: string;
    isPythonModule: boolean;
    displayPath: string;
}

export class CliDiscovery {
    private static cachedCli?: DiscoveredCli;

    /**
     * Clear cached discovery result.
     */
    public static clearCache(): void {
        this.cachedCli = undefined;
    }

    /**
     * Builds an environment augmented with common Python/user script directories across platforms.
     */
    public static getAugmentedEnv(): NodeJS.ProcessEnv {
        const env = { ...process.env };
        const home = os.homedir();
        const sep = path.delimiter;
        const extraDirs: string[] = [];

        // 1. Workspace virtualenv directories
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders) {
            for (const folder of workspaceFolders) {
                const root = folder.uri.fsPath;
                extraDirs.push(
                    path.join(root, '.venv', 'Scripts'),
                    path.join(root, '.venv', 'bin'),
                    path.join(root, 'venv', 'Scripts'),
                    path.join(root, 'venv', 'bin')
                );
            }
        }

        // 2. Windows Python user Scripts locations
        if (process.platform === 'win32') {
            const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
            const localAppData = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');

            const pyUserRoot = path.join(appData, 'Python');
            if (fs.existsSync(pyUserRoot)) {
                try {
                    const entries = fs.readdirSync(pyUserRoot);
                    for (const entry of entries) {
                        extraDirs.push(path.join(pyUserRoot, entry, 'Scripts'));
                    }
                } catch {
                    // Ignore readdir errors
                }
            }

            const pyProgRoot = path.join(localAppData, 'Programs', 'Python');
            if (fs.existsSync(pyProgRoot)) {
                try {
                    const entries = fs.readdirSync(pyProgRoot);
                    for (const entry of entries) {
                        extraDirs.push(path.join(pyProgRoot, entry, 'Scripts'));
                        extraDirs.push(path.join(pyProgRoot, entry));
                    }
                } catch {
                    // Ignore readdir errors
                }
            }
        } else {
            // 3. macOS / Linux paths
            extraDirs.push(
                path.join(home, '.local', 'bin'),
                '/opt/homebrew/bin',
                '/opt/homebrew/sbin',
                '/usr/local/bin',
                '/usr/local/sbin',
                path.join(home, '.pyenv', 'shims'),
                path.join(home, 'miniconda3', 'bin'),
                path.join(home, 'anaconda3', 'bin'),
                path.join(home, 'miniforge3', 'bin')
            );
        }

        const validExtras = extraDirs.filter(d => {
            try { return fs.existsSync(d); } catch { return false; }
        });

        const currentPath = env.PATH || '';
        env.PATH = [...validExtras, currentPath].filter(Boolean).join(sep);
        return env;
    }

    /**
     * Robustly discovers the SLOPGUARD executable following the required priority chain:
     * 1. User-configured executable path
     * 2. Existing cached valid path
     * 3. slopguard available on PATH
     * 4. Windows Python user Scripts locations
     * 5. macOS/Linux Python user bin locations
     * 6. Common Python virtual environment locations
     * 7. Python interpreter based discovery (python -m slopguard.cli.main)
     */
    public static async discover(
        explicitPath?: string,
        outputChannel?: vscode.OutputChannel
    ): Promise<DiscoveredCli | null> {
        outputChannel?.appendLine('[SLOPGUARD] CLI discovery started.');

        const env = this.getAugmentedEnv();
        const candidates: Array<{ command: string; baseArgs: string[]; isPythonModule: boolean; displayPath: string }> = [];

        // Priority 1: User-configured executable path
        const config = vscode.workspace.getConfiguration('slopguard');
        const configuredPath = explicitPath || config.get<string>('cliPath') || config.get<string>('cli.path');
        if (configuredPath && configuredPath !== 'slopguard') {
            candidates.push({
                command: configuredPath,
                baseArgs: [],
                isPythonModule: false,
                displayPath: configuredPath
            });
        }

        // Priority 2: Return cached if still valid
        if (this.cachedCli) {
            const valid = await this.validateExecutable(this.cachedCli.command, this.cachedCli.baseArgs, env);
            if (valid) {
                outputChannel?.appendLine(`[SLOPGUARD] CLI found (cached): ${this.cachedCli.displayPath}`);
                if (this.cachedCli.version) {
                    outputChannel?.appendLine(`[SLOPGUARD] CLI version: ${this.cachedCli.version}`);
                }
                outputChannel?.appendLine('[SLOPGUARD] CLI connection established.');
                return this.cachedCli;
            }
            this.cachedCli = undefined;
        }

        // Priority 3: slopguard on PATH
        candidates.push({
            command: 'slopguard',
            baseArgs: [],
            isPythonModule: false,
            displayPath: 'slopguard (system PATH)'
        });

        const home = os.homedir();

        // Priority 4: Windows Python user Scripts locations
        if (process.platform === 'win32') {
            const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
            const localAppData = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');

            // %APPDATA%\Python\Python*\Scripts\slopguard.exe
            const pyUserRoot = path.join(appData, 'Python');
            if (fs.existsSync(pyUserRoot)) {
                try {
                    const entries = fs.readdirSync(pyUserRoot);
                    for (const entry of entries) {
                        const target = path.join(pyUserRoot, entry, 'Scripts', 'slopguard.exe');
                        if (fs.existsSync(target)) {
                            candidates.push({
                                command: target,
                                baseArgs: [],
                                isPythonModule: false,
                                displayPath: target
                            });
                        }
                    }
                } catch {
                    // Ignore readdir errors
                }
            }

            // %LOCALAPPDATA%\Programs\Python\Python*\Scripts\slopguard.exe
            const pyProgRoot = path.join(localAppData, 'Programs', 'Python');
            if (fs.existsSync(pyProgRoot)) {
                try {
                    const entries = fs.readdirSync(pyProgRoot);
                    for (const entry of entries) {
                        const target = path.join(pyProgRoot, entry, 'Scripts', 'slopguard.exe');
                        if (fs.existsSync(target)) {
                            candidates.push({
                                command: target,
                                baseArgs: [],
                                isPythonModule: false,
                                displayPath: target
                            });
                        }
                    }
                } catch {
                    // Ignore readdir errors
                }
            }
        } else {
            // Priority 5: macOS/Linux Python user bin locations
            const unixCandidates = [
                path.join(home, '.local', 'bin', 'slopguard'),
                '/opt/homebrew/bin/slopguard',
                '/usr/local/bin/slopguard',
                path.join(home, '.pyenv', 'shims', 'slopguard'),
                path.join(home, 'miniconda3', 'bin', 'slopguard'),
                path.join(home, 'anaconda3', 'bin', 'slopguard')
            ];
            for (const target of unixCandidates) {
                if (fs.existsSync(target)) {
                    candidates.push({
                        command: target,
                        baseArgs: [],
                        isPythonModule: false,
                        displayPath: target
                    });
                }
            }
        }

        // Priority 6: Common Python virtual environment locations
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders) {
            for (const folder of workspaceFolders) {
                const root = folder.uri.fsPath;
                const venvCandidates = [
                    path.join(root, '.venv', 'Scripts', 'slopguard.exe'),
                    path.join(root, '.venv', 'bin', 'slopguard'),
                    path.join(root, 'venv', 'Scripts', 'slopguard.exe'),
                    path.join(root, 'venv', 'bin', 'slopguard'),
                    path.join(root, '.env', 'Scripts', 'slopguard.exe'),
                    path.join(root, '.env', 'bin', 'slopguard'),
                    path.join(root, 'env', 'Scripts', 'slopguard.exe'),
                    path.join(root, 'env', 'bin', 'slopguard')
                ];
                for (const target of venvCandidates) {
                    if (fs.existsSync(target)) {
                        candidates.push({
                            command: target,
                            baseArgs: [],
                            isPythonModule: false,
                            displayPath: target
                        });
                    }
                }
            }
        }

        // Priority 7: Python interpreter based discovery (python -m slopguard.cli.main)
        const pyCandidates: string[] = [];
        if (workspaceFolders) {
            for (const folder of workspaceFolders) {
                const root = folder.uri.fsPath;
                pyCandidates.push(
                    path.join(root, '.venv', 'Scripts', 'python.exe'),
                    path.join(root, '.venv', 'bin', 'python'),
                    path.join(root, 'venv', 'Scripts', 'python.exe'),
                    path.join(root, 'venv', 'bin', 'python')
                );
            }
        }
        pyCandidates.push('python3', 'python');

        for (const py of pyCandidates) {
            candidates.push({
                command: py,
                baseArgs: ['-m', 'slopguard.cli.main'],
                isPythonModule: true,
                displayPath: `${py} -m slopguard.cli.main`
            });
        }

        // Test each candidate in priority order
        for (const cand of candidates) {
            const version = await this.validateExecutable(cand.command, cand.baseArgs, env);
            if (version) {
                const discovered: DiscoveredCli = {
                    command: cand.command,
                    baseArgs: cand.baseArgs,
                    version,
                    isPythonModule: cand.isPythonModule,
                    displayPath: cand.displayPath
                };
                this.cachedCli = discovered;

                outputChannel?.appendLine(`[SLOPGUARD] CLI found:\n${cand.displayPath}`);
                outputChannel?.appendLine(`[SLOPGUARD] CLI version: ${version}`);
                outputChannel?.appendLine('[SLOPGUARD] CLI connection established.');
                return discovered;
            }
        }

        outputChannel?.appendLine('[SLOPGUARD] Warning: No working SLOPGUARD CLI or Python module found.');
        return null;
    }

    private static async validateExecutable(
        command: string,
        baseArgs: string[],
        env: NodeJS.ProcessEnv
    ): Promise<string | null> {
        try {
            const { stdout } = await execFileAsync(command, [...baseArgs, '--version'], {
                env,
                timeout: 5000
            });
            const text = stdout.trim();
            if (text.toLowerCase().includes('slopguard')) {
                // Parse version string like "slopguard, version 0.1.0" or "0.1.0"
                const match = text.match(/version\s+([0-9a-zA-Z.-]+)/i) || text.match(/([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9.-]*)/);
                return match ? match[1] : text;
            }
        } catch {
            // Failed validation
        }
        return null;
    }
}
