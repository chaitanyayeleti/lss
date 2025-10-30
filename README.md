# lss — Local Secret Scanner

lss scans local file trees and local git repositories for likely secrets using a rule-driven approach (regex heuristics + entropy checks). It is designed to run locally and not transmit any scanned data off the host.

This README documents how to build and use `lss`, the rule and config formats, `.lssignore` behavior, and a few examples.

## Highlights
- Scans files recursively and optionally scans git history (local repos found under the scan path).
- Rule-driven detection with tags and per-rule confidence scores.
- Entropy filtering (Shannon entropy) to reduce false positives.
- Parallel file scanning for speed.
- Output in human or JSON format.
- `rules` subcommands (list rules, JSON + pagination).

## Build

You need Rust and Cargo. Recommended: stable toolchain.

```bash
# build in debug
cargo build

# build release
cargo build --release
```

## Quick start (scan)

Scan the current directory and print human-readable results:

```bash
cargo run -- scan --path . --format human
```

JSON output (machine-friendly):

```bash
cargo run -- scan --path /path/to/project --format json
```

Scan and override the entropy threshold (useful to reduce false positives):

```bash
cargo run -- scan --path . --entropy-threshold 4.0
```

Include/exclude by tags and minimum confidence:

```bash
cargo run -- scan --path . --include-tags secret,aws --exclude-tags public --min-confidence 0.6
```

Notes:
- `lss` will automatically detect local git repositories (folders containing `.git`) in the scan path and run a light scan of their history.
- Files and repository paths can be ignored using config ignores and `.lssignore` (see below).

## CLI reference (important flags)

- `scan` subcommand (default): Scan a path.
  - `--path <path>` — path to scan (default `.`)
  - `--format <human|json>` — output format
  - `--entropy-threshold <float>` — override the entropy threshold (default from config or 3.5)
  - `--ignore-file <path>` — path to a file with ignore patterns (one per line)
  - `--rules-file <path>` — load additional rules from a file
  - `--include-tags <csv>` — only include findings that have any of these tags
  - `--exclude-tags <csv>` — exclude findings that have any of these tags
  - `--min-confidence <float>` — minimum combined confidence for findings (0.0–1.0)

- `rules list` subcommand: list bundled (and loaded) rules.
  - `--json` — output JSON containing `total`, `page`, `per_page`, and `rules` (each rule shows name, pattern, tags, confidence)
  - `--page <n>` — 1-based page number
  - `--per-page <n>` — items per page

Run with `cargo run -- --help` or `cargo run -- scan --help` for full clap-generated usage.

## Rule format

Rules are textual and can be loaded from `rules/default_rules.txt` (bundled) or via `--rules-file`.

Each non-comment line uses this format:

```
Name::Regex::tag1,tag2::confidence
```

- `Name` — human-friendly rule name.
- `Regex` — a Rust-compatible regular expression (see the `regex` crate docs). Use `::` to separate fields.
- `tag1,tag2` — optional comma-separated tags (used for filtering). Optional — leave empty to have no tags.
- `confidence` — optional float between 0.0 and 1.0. Default is 0.5 when omitted.

Example lines:

```
AWS Access Key::AKIA[0-9A-Z]{16}::aws,credential::0.9
Private RSA Key Begin::-----BEGIN RSA PRIVATE KEY-----::private_key::0.99
JWT-like token::eyJ[A-Za-z0-9_-]{10,}::jwt,token::0.6
```

### Notes on regexes
- Rules are applied line-by-line. For multi-line secrets (e.g., PEM keys), rules that match the key BEGIN marker will be effective; the snippet printed is the matched line.

## How findings are produced

1. For each file, all rules are applied to each line.
2. If multiple rules match the same line/snippet, their confidences are combined using the probabilistic union formula:

   combined_confidence = 1 - Π(1 - ci)

   This increases the confidence when multiple independent heuristics match the same snippet.
3. Findings are filtered by entropy (Shannon entropy of the snippet) and `--min-confidence` if supplied.

## `.lssignore` and ignore behavior

- `lss` loads ignore patterns from multiple places and merges them (substring matching):
  - Config file `lss/config.toml` in your `$XDG_CONFIG_HOME` (or platform equivalent).
  - Root `.lssignore` in the scan root (e.g., `/path/to/scan/.lssignore`).
  - Per-directory `.lssignore` files discovered walking up from file parents to the scan root.
  - CLI-provided `--ignore-file` file.

Patterns are treated as simple substring matches (not globs) for simplicity. Any file path containing a listed pattern will be skipped.

Example `.lssignore`:

```
.venv
/node_modules
/dist
```

## Config file

Location: `$XDG_CONFIG_HOME/lss/config.toml` (or OS default config dir). Example:

```toml
ignore = [".venv", "node_modules", "dist"]
entropy_threshold = 3.5
```

`ignore` is an array of substrings to skip. `entropy_threshold` is a float used when computing whether a matched snippet is likely secret.

## Examples

- List rules (human):

```bash
cargo run -- rules list --page 1 --per-page 20
```

- List rules (JSON, page 1):

```bash
cargo run -- rules list --json --page 1 --per-page 50
```

- Scan a project, show only findings tagged `aws` and with combined confidence >= 0.7:

```bash
cargo run -- scan --path /home/me/projects/myapp --include-tags aws --min-confidence 0.7 --format human
```

- Scan and output JSON:

```bash
cargo run -- scan --path /home/me/projects/myapp --format json > findings.json
```

## Tests

Run unit tests with:

```bash
cargo test
```

## Contributing

If you'd like to add rules, please follow the rule format and include tags and a confidence estimate. Small PRs that add high-quality rules (with examples) are welcome.

## Security & Privacy

`lss` reads files on the host and does not transmit findings anywhere. Be careful running it on sensitive directories — treat findings carefully and rotate any exposed secrets.

## License

MIT (see LICENSE file)
