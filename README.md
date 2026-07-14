# Password Strength Checker

A defensive security tool that evaluates password strength using entropy analysis with Unicode awareness, timing-attack resistance, and memory hygiene.

## Features

- **Entropy-based analysis** — accounts for character set size, length, and Unicode expansion
- **Single-pass O(n) validation** — walks the password exactly once
- **Timing-attack resistant** — uses `hmac.compare_digest` for constant-time equality checks
- **Penalty system** — flags common passwords, repeated characters, uniform character types
- **Unicode-aware** — expands keyspace estimation for non-ASCII characters
- **Color-coded verdicts** — WEAK, MEDIUM, STRONG, VERY STRONG

## Usage

# Clone in Linux:

gh repo clone ateeqmalikz01-dev/Pa55w0rd_5trength_Checker

# How to Use:

```bash
# Interactive mode (hidden input)
python password_strength.py

# Single password from CLI
python password_strength.py -p 'P@ssw0rd!'

# Loop mode (keep evaluating until Ctrl+C)
python password_strength.py -l

# Help
python password_strength.py --help
```

## Security Principles

- **O(n) linear-time** validation
- **Constant-time comparison** via `hmac.compare_digest`
- **No persistent storage** of passwords in memory
- **Local variable scrubbing** after each check
- **C-optimized built-ins** (`str`, `set`, `any`) for speed and safety
