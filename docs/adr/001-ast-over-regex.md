# ADR 001: AST-Based Dependency Extraction Over Regular Expressions

## Status
Accepted

## Context
Dependency extraction from arbitrary source code (Python, JavaScript, TypeScript) can be attempted via regular expressions or via proper Abstract Syntax Tree (AST) / parser traversal.
Regular expressions frequently fail on:
- Multi-line imports and import aliases (`import a as b, c as d`)
- Commented-out imports (`# import malicious_pkg`)
- String literals containing code snippets or documentation
- Dynamic or nested imports within conditionals or functions
- Relative vs absolute imports

## Decision
SLOPGUARD mandates AST-based parsing for Python using the built-in `ast` module, and lexical/syntactic parser tokenization for JavaScript and TypeScript. Regex-only extraction is prohibited for security-critical gate decisions.

## Consequences
- Deterministic extraction accuracy with zero false positives from comments or docstrings.
- Syntax errors in source files are explicitly caught and flagged as unparseable rather than silently missed.
