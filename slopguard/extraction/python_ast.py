from __future__ import annotations
import ast
import sys
from typing import List, Set
from slopguard.core.models import DependencySourceType, Ecosystem, ExtractedDependency

# Fallback catalog for standard library in case of custom or older Python environments
_STDLIB_EXTRA = {
    "abc", "argparse", "array", "ast", "asyncio", "base64", "binascii", "bisect",
    "builtins", "bz2", "calendar", "cmath", "cmd", "code", "codecs", "collections",
    "colorsys", "compileall", "concurrent", "configparser", "contextlib", "contextvars",
    "copy", "copyreg", "csv", "ctypes", "curses", "dataclasses", "datetime", "dbm",
    "decimal", "difflib", "dis", "distutils", "doctest", "email", "encodings",
    "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput", "fnmatch",
    "fractions", "ftplib", "functools", "gc", "getopt", "getpass", "gettext", "glob",
    "graphlib", "gzip", "hashlib", "heapq", "hmac", "html", "http", "imaplib",
    "imghdr", "imp", "importlib", "inspect", "io", "ipaddress", "itertools", "json",
    "keyword", "linecache", "locale", "logging", "lzma", "mailbox", "mailcap",
    "marshal", "math", "mimetypes", "mmap", "modulefinder", "multiprocessing",
    "netrc", "nntplib", "numbers", "operator", "optparse", "os", "ossaudiodev",
    "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform",
    "plistlib", "poplib", "posix", "posixpath", "pprint", "profile", "pstats",
    "pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue", "quopri", "random",
    "re", "readline", "reprlib", "resource", "rlcompleter", "runpy", "sched",
    "secrets", "select", "selectors", "shelve", "shlex", "shutil", "signal",
    "site", "smtpd", "smtplib", "sndhdr", "socket", "socketserver", "spwd",
    "sqlite3", "ssl", "stat", "statistics", "string", "stringprep", "struct",
    "subprocess", "sunau", "symbol", "symtable", "sys", "sysconfig", "syslog",
    "tabnanny", "tarfile", "telnetlib", "tempfile", "termios", "test", "textwrap",
    "threading", "time", "timeit", "tkinter", "token", "tokenize", "tomllib",
    "trace", "traceback", "tracemalloc", "tty", "turtle", "turtledemo", "types",
    "typing", "unicodedata", "unittest", "urllib", "uu", "uuid", "venv", "warnings",
    "wave", "weakref", "webbrowser", "winreg", "winsound", "wsgiref", "xdrlib",
    "xml", "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib", "_thread"
}

def get_python_stdlib_names() -> Set[str]:
    """Retrieve full standard library set combining runtime sys.stdlib_module_names and catalog."""
    stdlib = set(_STDLIB_EXTRA)
    if hasattr(sys, "stdlib_module_names"):
        stdlib.update(sys.stdlib_module_names)
    return stdlib


class PythonASTExtractor:
    """
    Extracts dependencies from Python source code using Python's AST parser.
    Identifies import statements, extracts root module names, flags standard library,
    and isolates relative imports.
    """

    def __init__(self) -> None:
        self.stdlib_names = get_python_stdlib_names()

    def extract(self, code: str, file_path: str = "<string>") -> List[ExtractedDependency]:
        results: List[ExtractedDependency] = []
        try:
            tree = ast.parse(code, filename=file_path)
        except SyntaxError as exc:
            # If code has a syntax error, we don't fail silently; we document it
            raise ValueError(f"Syntax error in {file_path}:{exc.lineno}: {exc.msg}") from exc

        code_lines = code.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                raw_stmt = code_lines[node.lineno - 1] if 0 < node.lineno <= len(code_lines) else None
                for alias in node.names:
                    root_name = alias.name.split(".")[0]
                    is_std = root_name in self.stdlib_names
                    results.append(
                        ExtractedDependency(
                            name=root_name,
                            ecosystem=Ecosystem.PYPI,
                            source_type=DependencySourceType.SOURCE_CODE,
                            file_path=file_path,
                            line_number=node.lineno,
                            raw_statement=raw_stmt,
                            is_stdlib=is_std,
                            is_relative=False,
                        )
                    )

            elif isinstance(node, ast.ImportFrom):
                raw_stmt = code_lines[node.lineno - 1] if 0 < node.lineno <= len(code_lines) else None
                is_relative = (node.level or 0) > 0
                if is_relative or not node.module:
                    # Relative import, e.g., 'from . import foo' or 'from ..models import bar'
                    results.append(
                        ExtractedDependency(
                            name=node.module or ".",
                            ecosystem=Ecosystem.PYPI,
                            source_type=DependencySourceType.SOURCE_CODE,
                            file_path=file_path,
                            line_number=node.lineno,
                            raw_statement=raw_stmt,
                            is_stdlib=False,
                            is_relative=True,
                        )
                    )
                else:
                    root_name = node.module.split(".")[0]
                    is_std = root_name in self.stdlib_names
                    results.append(
                        ExtractedDependency(
                            name=root_name,
                            ecosystem=Ecosystem.PYPI,
                            source_type=DependencySourceType.SOURCE_CODE,
                            file_path=file_path,
                            line_number=node.lineno,
                            raw_statement=raw_stmt,
                            is_stdlib=is_std,
                            is_relative=False,
                        )
                    )

        # Deduplicate while preserving order and first occurrence
        seen = set()
        deduped: List[ExtractedDependency] = []
        for item in results:
            key = (item.name, item.is_relative, item.file_path, item.line_number)
            if key not in seen:
                seen.add(key)
                deduped.append(item)

        return deduped
