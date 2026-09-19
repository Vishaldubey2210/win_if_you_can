from __future__ import annotations
import re
from typing import List, Set, Tuple, Optional
from slopguard.core.models import DependencySourceType, Ecosystem, ExtractedDependency

NODE_BUILTINS: Set[str] = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "fs/promises", "http", "http2", "https", "inspector",
    "module", "net", "os", "path", "path/posix", "path/win32", "perf_hooks",
    "process", "punycode", "querystring", "readline", "readline/promises",
    "repl", "stream", "stream/consumers", "stream/promises", "stream/web",
    "string_decoder", "sys", "timers", "timers/promises", "tls", "trace_events",
    "tty", "url", "util", "util/types", "v8", "vm", "wasi", "worker_threads", "zlib"
}

def clean_js_package_name(import_specifier: str) -> Tuple[str, bool, bool]:
    """
    Given an import specifier (e.g. 'lodash/debounce', '@angular/core/testing', 'node:fs', './utils'),
    returns: (canonical_package_name, is_stdlib, is_relative)
    """
    spec = import_specifier.strip().strip("'\"`")
    
    # Check relative
    if spec.startswith((".", "/")):
        return spec, False, True

    # Check node prefix e.g. 'node:fs'
    if spec.startswith("node:"):
        builtin = spec[5:]
        return builtin, True, False

    # Check built-in without prefix
    if spec in NODE_BUILTINS:
        return spec, True, False

    # Check scoped package: @scope/pkg-name/subpath
    if spec.startswith("@"):
        parts = spec.split("/")
        if len(parts) >= 2:
            pkg_name = f"{parts[0]}/{parts[1]}"
            return pkg_name, False, False
        return spec, False, False

    # Standard package with subpath: lodash/map -> lodash
    parts = spec.split("/")
    pkg_name = parts[0]
    return pkg_name, False, False


class JavaScriptExtractor:
    """
    Robust lexical extractor for JavaScript and TypeScript dependencies.
    Extracts static ES6 imports, dynamic import() expressions, and CommonJS require() calls.
    Correctly ignores line comments, block comments, and distinguishes built-ins and relative paths.
    """

    def extract(self, code: str, file_path: str = "<string>") -> List[ExtractedDependency]:
        results: List[ExtractedDependency] = []
        lines = code.splitlines()

        # Tokenize code line-by-line while stripping block comments and single-line comments
        in_block_comment = False

        # Regular expressions for import statements and require statements on active code
        # 1. import ... from ['"]spec['"] or import ['"]spec['"] or export ... from ['"]spec['"]
        import_stmt_pattern = re.compile(
            r"""(?:import|export)\s+(?:(?:type\s+)?[\w\s{},*]+\s+from\s+)?['"]([^'"]+)['"]"""
        )
        # 2. require(['"]spec['"])
        require_stmt_pattern = re.compile(
            r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)"""
        )
        # 3. dynamic import(['"]spec['"])
        dynamic_import_pattern = re.compile(
            r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)"""
        )

        for line_idx, line in enumerate(lines, start=1):
            line_content = line

            # Handle block comments /* ... */
            clean_line = ""
            i = 0
            while i < len(line_content):
                if in_block_comment:
                    end_block = line_content.find("*/", i)
                    if end_block != -1:
                        in_block_comment = False
                        i = end_block + 2
                    else:
                        break
                else:
                    start_block = line_content.find("/*", i)
                    start_line_comment = line_content.find("//", i)

                    # If line comment comes before block comment
                    if start_line_comment != -1 and (start_block == -1 or start_line_comment < start_block):
                        clean_line += line_content[i:start_line_comment]
                        break
                    elif start_block != -1:
                        clean_line += line_content[i:start_block]
                        in_block_comment = True
                        i = start_block + 2
                    else:
                        clean_line += line_content[i:]
                        break

            if not clean_line.strip():
                continue

            # Check ES imports / exports
            for match in import_stmt_pattern.finditer(clean_line):
                spec = match.group(1)
                pkg_name, is_std, is_rel = clean_js_package_name(spec)
                results.append(
                    ExtractedDependency(
                        name=pkg_name,
                        ecosystem=Ecosystem.NPM,
                        source_type=DependencySourceType.SOURCE_CODE,
                        file_path=file_path,
                        line_number=line_idx,
                        raw_statement=line.strip(),
                        is_stdlib=is_std,
                        is_relative=is_rel,
                    )
                )

            # Check require(...)
            for match in require_stmt_pattern.finditer(clean_line):
                spec = match.group(1)
                pkg_name, is_std, is_rel = clean_js_package_name(spec)
                results.append(
                    ExtractedDependency(
                        name=pkg_name,
                        ecosystem=Ecosystem.NPM,
                        source_type=DependencySourceType.SOURCE_CODE,
                        file_path=file_path,
                        line_number=line_idx,
                        raw_statement=line.strip(),
                        is_stdlib=is_std,
                        is_relative=is_rel,
                    )
                )

            # Check dynamic import(...)
            for match in dynamic_import_pattern.finditer(clean_line):
                spec = match.group(1)
                pkg_name, is_std, is_rel = clean_js_package_name(spec)
                results.append(
                    ExtractedDependency(
                        name=pkg_name,
                        ecosystem=Ecosystem.NPM,
                        source_type=DependencySourceType.SOURCE_CODE,
                        file_path=file_path,
                        line_number=line_idx,
                        raw_statement=line.strip(),
                        is_stdlib=is_std,
                        is_relative=is_rel,
                    )
                )

        # Deduplicate while preserving line order
        seen = set()
        deduped: List[ExtractedDependency] = []
        for item in results:
            key = (item.name, item.is_relative, item.file_path, item.line_number)
            if key not in seen:
                seen.add(key)
                deduped.append(item)

        return deduped
