# ADR 009: Unicode Confusable and Homoglyph Detection

## Status
Accepted

## Context
Attackers publish malicious packages using visual homoglyphs (e.g. Cyrillic `а`, `е`, `о`, `р`, `у`, `х`, Greek `ο`, `ν`, `ρ`) that appear indistinguishable from popular packages (e.g., `requests`, `numpy`, `lodash`) in IDEs, pull requests, and terminals. Standard string comparison and Levenshtein distance with default encoding fail to detect these deliberate visual spoofs.

## Decision
SLOPGUARD incorporates Unicode NFKC normalization combined with a bidirectional `HOMOGLYPH_MAP` translating confusable Cyrillic, Greek, and non-standard separator characters into Latin ASCII equivalents.
When a package name uses non-ASCII characters that map to a popular target (e.g. `numpу` with Cyrillic `у` U+0443), SLOPGUARD flags it as a `CRITICAL` typosquatting homoglyph attack and enforces an immediate `BLOCK`.

## Consequences
- Neutralizes homoglyph spoofing attacks before package installation can occur.
- Zero false positives on pure ASCII package names.
