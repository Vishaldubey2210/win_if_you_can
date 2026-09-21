const Module = require('module');

export class MockEventEmitter<T> {
    private listeners: ((e: T) => any)[] = [];
    public event = (listener: (e: T) => any) => {
        this.listeners.push(listener);
        return {
            dispose: () => {
                this.listeners = this.listeners.filter(l => l !== listener);
            }
        };
    };
    public fire(data: T): void {
        for (const l of [...this.listeners]) {
            l(data);
        }
    }
    public dispose(): void {
        this.listeners = [];
    }
}

export class MockUri {
    public fsPath: string;
    constructor(filePath: string) {
        this.fsPath = filePath;
    }
    static file(filePath: string) {
        return new MockUri(filePath);
    }
}

export class MockPosition {
    constructor(public line: number, public character: number) {}
}

export class MockRange {
    public start: MockPosition;
    public end: MockPosition;
    constructor(public startLine: number, public startCol: number, public endLine: number, public endCol: number) {
        this.start = new MockPosition(startLine, startCol);
        this.end = new MockPosition(endLine, endCol);
    }
}

export enum MockDiagnosticSeverity {
    Error = 0,
    Warning = 1,
    Information = 2,
    Hint = 3
}

export class MockDiagnostic {
    public source: string = '';
    public code: string = '';
    public dependencyData?: any;
    constructor(public range: MockRange, public message: string, public severity: MockDiagnosticSeverity) {}
}

export class MockDiagnosticCollection {
    public diagnostics: Map<string, MockDiagnostic[]> = new Map();

    public set(uri: MockUri, diags: MockDiagnostic[]): void {
        this.diagnostics.set(uri.fsPath.toLowerCase(), diags);
    }

    public get(uri: MockUri): MockDiagnostic[] | undefined {
        return this.diagnostics.get(uri.fsPath.toLowerCase());
    }

    public delete(uri: MockUri): void {
        this.diagnostics.delete(uri.fsPath.toLowerCase());
    }

    public clear(): void {
        this.diagnostics.clear();
    }

    public dispose(): void {
        this.clear();
    }
}

export class MockOutputChannel {
    public lines: string[] = [];
    appendLine(value: string): void {
        this.lines.push(value);
    }
    clear(): void {
        this.lines = [];
    }
    dispose(): void {}
}

export class MockStatusBarItem {
    public text: string = '';
    public tooltip: any = '';
    public backgroundColor: any = undefined;
    public command: string = '';
    public isShown: boolean = false;
    show(): void { this.isShown = true; }
    hide(): void { this.isShown = false; }
    dispose(): void {}
}

export class MockWorkspaceEdit {
    public entries: Array<{ uri: MockUri; range: MockRange; newText: string }> = [];
    replace(uri: MockUri, range: MockRange, newText: string): void {
        this.entries.push({ uri, range, newText });
    }
}

export class MockCodeAction {
    public edit?: MockWorkspaceEdit;
    public command?: any;
    public isPreferred?: boolean;
    public diagnostics?: MockDiagnostic[];
    constructor(public title: string, public kind?: any) {}
}

export const mockVscode: any = {
    EventEmitter: MockEventEmitter,
    Uri: MockUri,
    Position: MockPosition,
    Range: MockRange,
    Diagnostic: MockDiagnostic,
    DiagnosticSeverity: MockDiagnosticSeverity,
    WorkspaceEdit: MockWorkspaceEdit,
    CodeAction: MockCodeAction,
    CodeActionKind: {
        QuickFix: 'QuickFix',
        Empty: 'Empty'
    },
    StatusBarAlignment: {
        Left: 1,
        Right: 2
    },
    ThemeColor: class { constructor(public id: string) {} },
    ThemeIcon: class { constructor(public id: string) {} },
    TreeItem: class {
        public label?: string;
        public collapsibleState?: any;
        public contextValue?: string;
        public description?: string;
        public tooltip?: any;
        public iconPath?: any;
        constructor(label: string, collapsibleState?: any) {
            this.label = label;
            this.collapsibleState = collapsibleState;
        }
    },
    TreeItemCollapsibleState: {
        None: 0,
        Collapsed: 1,
        Expanded: 2
    },
    MarkdownString: class { constructor(public value: string) {} },
    languages: {
        createDiagnosticCollection: (name: string) => new MockDiagnosticCollection(),
        registerCodeActionsProvider: (selector: any, provider: any, metadata?: any) => ({ dispose: () => {} })
    },
    window: {
        createOutputChannel: (name: string) => new MockOutputChannel(),
        createStatusBarItem: (align: any, priority?: number) => new MockStatusBarItem(),
        registerTreeDataProvider: (id: string, provider: any) => ({ dispose: () => {} }),
        showInformationMessage: async () => {},
        showWarningMessage: async () => {},
        showErrorMessage: async () => {}
    },
    commands: {
        registerCommand: (command: string, callback: (...args: any[]) => any) => ({ dispose: () => {} }),
        executeCommand: async (command: string, ...args: any[]) => {}
    },
    workspace: {
        workspaceFolders: [{ uri: MockUri.file(process.cwd()) }],
        getConfiguration: (section?: string) => ({
            get: (key: string, defaultValue?: any) => defaultValue
        }),
        onDidChangeConfiguration: (listener: any) => ({ dispose: () => {} }),
        onDidSaveTextDocument: (listener: any) => ({ dispose: () => {} }),
        onDidOpenTextDocument: (listener: any) => ({ dispose: () => {} }),
        onDidCreateFiles: (listener: any) => ({ dispose: () => {} }),
        onDidDeleteFiles: (listener: any) => ({ dispose: () => {} }),
        createFileSystemWatcher: () => ({
            onDidCreate: () => ({ dispose: () => {} }),
            onDidChange: () => ({ dispose: () => {} }),
            onDidDelete: () => ({ dispose: () => {} }),
            dispose: () => {}
        }),
        findFiles: async () => [],
        textDocuments: [],
        fs: {
            readFile: async (uri: MockUri) => Buffer.from('test')
        }
    }
};

// Install require hook so `import * as vscode from 'vscode'` works in Node tests
const originalLoad = Module._load;
Module._load = function (request: string, parent: any, isMain: boolean) {
    if (request === 'vscode') {
        return mockVscode;
    }
    return originalLoad.apply(this, arguments);
};
