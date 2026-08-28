# Evilbox

CLI that **statically** deobfuscates JavaScript and PHP. It unwraps common encodings and rewrites the syntax tree. It does **not** execute the input (no `eval` in a JS or PHP engine).

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```text
evilbox packed.js -o clean.js
evilbox packed.php --lang php
evilbox - --lang js < packed.js
```

`deobfuscate` is kept as an alias for the same CLI.

| Flag | Meaning |
| --- | --- |
| `--lang auto\|js\|php` | Language (default: `auto` from path and contents) |
| `-o PATH` | Write to a file instead of stdout |
| `--max-passes N` | Unwrap/fold iterations (default: 8) |

Exit status `1` means the result still does not parse cleanly. Warnings go to stderr; the best-effort output is still written.

## PHP sandbox (evalhook, no real internet)

Optional Docker lab for packed PHP. Each run **builds a throwaway image tag, starts a new container with `--network none`, then deletes the container and image tag**. The sample is mounted read-only. Nothing from the run is committed back into an image.

Inside the container:

- [php-eval-hook](https://github.com/extremecoders-re/php-eval-hook) dumps every `eval()`
- dnsmasq answers **every** DNS name with `127.0.0.1` (no upstream resolvers)
- an HTTP/HTTPS sink returns **200 OK** and logs Host/URL/body
- a **sandbox CA** is generated at start and trusted by PHP `curl` / OpenSSL so HTTPS still completes
- tcpdump writes `traffic.pcap` on loopback

```text
evilbox packed.php --sandbox dump
evilbox packed.php --sandbox observe --logs-dir ./sandbox-logs --timeout 20
```

| Mode | Behavior |
| --- | --- |
| `dump` | Log eval payloads and **do not** execute them |
| `observe` | Log eval payloads **and** let the script run (requests hit the fake sink) |

Logs land in `./sandbox-logs/<timestamp-id>/` (`domains.txt`, `http.jsonl`, `dns.log`, `eval-*.php`, `deobfuscated.php`, `indicators.json`, `traffic.pcap`). Override the default root with `EVILBOX_LOGS`. Domains are also printed on stderr. Stdout is the static cleanup of the last eval dump (or the original file if none).

After deobfuscation the CLI prints an **indicators** block on stderr (URLs, domains, IPs, emails, dropped filenames, Windows/UNC paths, registry keys, and APIs such as `WScript.Shell` / `ActiveXObject`). If you pass `-o clean.js`, the same data is written to `clean.iocs.json`.

Requires Docker. The sample never gets a route to the public internet (`--network none`). That is still **malware execution inside the container** in `observe` mode — only use samples you intend to analyze.

### Supply chain (sandbox image)

- **evalhook** is **vendored** at a pinned commit under [`sandbox/php/vendor/php-eval-hook/`](sandbox/php/vendor/php-eval-hook/). The image **does not** `git clone` at build time. See [`sandbox/php/vendor/SOURCES.md`](sandbox/php/vendor/SOURCES.md) for the GitHub URL, commit, and archive SHA-256.
- **PHP** is not stored in git. The Dockerfile uses `php:8.3-cli-bookworm@sha256:…` so the tag cannot drift. Docker still **pulls that digest once** if you do not already have it.
- Extra Debian packages (`dnsmasq`, `python3-cryptography`, …) are still installed from apt on the first uncached build; they are not copied into this repo.

## What v1 does

- Unescape string literals (`\xNN`, `\uNNNN`, octal, HTML entities)
- Concatenate adjacent string literals (`+` in JS, `.` in PHP)
- Fold simple numeric/boolean constants (`1+2`, `!0`)
- JS: `eval(atob(...))`, `unescape` / `decodeURIComponent`, `String.fromCharCode(...)` when arguments are literals
- PHP: `eval(base64_decode(...))`, `gzinflate` / `gzuncompress` / `gzdecode`, `str_rot13`, `hex2bin`, `pack('H*', ...)`
- Rename `_0x...` junk identifiers (and PHP `$` hex names of that form)

Not in v1: control-flow flattening, VM/dispatcher unpackers, or running a JavaScript engine.

## Tests

```bash
pytest
```
