from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evilbox.detect import PHP_EXTS, JS_EXTS, detect_language
from evilbox.extract import extract_indicators, format_indicators
from evilbox.pipeline import deobfuscate
from evilbox.report import build_report, dump_json, format_analysis, render_html
from evilbox.sandbox import SandboxError, default_logs_root, run_php_sandbox

SAMPLE_EXTS = JS_EXTS | PHP_EXTS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evilbox",
        description="Evilbox: deobfuscate JavaScript or PHP, classify capabilities/roles, and extract scanner-visible signatures from the original file.",
    )
    parser.add_argument("input", help="Input file, directory of samples, or - for stdin")
    parser.add_argument("-o", "--output", help="Write cleaned source to this file (or directory in batch mode)")
    parser.add_argument(
        "--lang",
        choices=("auto", "js", "php"),
        default="auto",
        help="Language (default: auto-detect from path and contents)",
    )
    parser.add_argument("--max-passes", type=int, default=8, help="Maximum unwrap/fold iterations (default: 8)")
    parser.add_argument(
        "--sandbox",
        choices=("dump", "observe"),
        help="Run the sample in an isolated Docker lab. PHP uses evalhook. JavaScript is deobfuscated statically (no PHP sandbox).",
    )
    parser.add_argument(
        "--logs-dir",
        help="Directory for sandbox logs (default: EVILBOX_LOGS or ./sandbox-logs)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Sandbox PHP timeout in seconds (default: 15)",
    )
    parser.add_argument("--report", help="Write JSON report to this path (directory in batch mode)")
    parser.add_argument("--html", help="Write HTML report to this path (directory in batch mode)")
    args = parser.parse_args(argv)

    if args.input != "-" and Path(args.input).is_dir():
        return _run_batch(args)

    path: str | None
    source: str
    if args.input == "-":
        source = sys.stdin.read()
        path = None
    else:
        path = args.input
        source = Path(args.input).read_text(encoding="utf-8", errors="replace")

    lang = detect_language(source, path=path, lang=args.lang)

    if args.sandbox:
        if lang == "js":
            print(
                "warning: --sandbox dump/observe uses the PHP evalhook lab; "
                "this file is JavaScript, so running static JS cleanup instead.",
                file=sys.stderr,
            )
            result = deobfuscate(source, language="js", path=path, max_passes=args.max_passes)
            return _emit(args, result, path)
        return _run_sandbox(args, source, path)

    result = deobfuscate(source, language=lang, path=path, max_passes=args.max_passes)
    return _emit(args, result, path)


def _run_batch(args) -> int:
    root = Path(args.input)
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SAMPLE_EXTS)
    if not files:
        print("error: no .js/.php samples in directory", file=sys.stderr)
        return 2
    out_dir = Path(args.output) if args.output else Path(args.report) if args.report else root / "evilbox-out"
    out_dir.mkdir(parents=True, exist_ok=True)
    html_dir = Path(args.html) if args.html else None
    if html_dir:
        html_dir.mkdir(parents=True, exist_ok=True)
    status = 0
    clusters: dict[str, list[str]] = {}
    for sample in files:
        source = sample.read_text(encoding="utf-8", errors="replace")
        result = deobfuscate(source, language=args.lang, path=str(sample), max_passes=args.max_passes)
        clusters.setdefault(result.cluster_sha256, []).append(str(sample))
        dest = out_dir / (sample.stem + ".clean" + sample.suffix)
        report_path = out_dir / (sample.stem + ".report.json")
        html_path = (html_dir / (sample.stem + ".report.html")) if html_dir else None
        fake = argparse.Namespace(
            output=str(dest),
            report=str(report_path),
            html=str(html_path) if html_path else None,
        )
        code = _emit(fake, result, str(sample), stdout_code=False)
        if code:
            status = code
        print(f"{sample.name}: {', '.join(r.name for r in result.classification.roles) or 'unclassified'}", file=sys.stderr)
    (out_dir / "clusters.json").write_text(json.dumps(clusters, indent=2) + "\n", encoding="utf-8")
    return status


def _run_sandbox(args, source: str, path: str | None) -> int:
    logs_root = Path(args.logs_dir) if args.logs_dir else default_logs_root()
    tmp_sample: Path | None = None
    if path is None or args.input == "-":
        logs_root.mkdir(parents=True, exist_ok=True)
        tmp_sample = logs_root / ".stdin-sample.php"
        tmp_sample.write_text(source, encoding="utf-8")
        sample = tmp_sample
    else:
        sample = Path(path)

    try:
        result = run_php_sandbox(sample, mode=args.sandbox, logs_root=logs_root, timeout=args.timeout)
    except SandboxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if tmp_sample is not None:
            tmp_sample.unlink(missing_ok=True)

    print(f"sandbox logs: {result.log_dir}", file=sys.stderr)
    analysis = result.analysis
    iocs = extract_indicators(result.deobfuscated, extra_domains=result.domains)
    sandbox_meta = {
        "log_dir": str(result.log_dir),
        "mode": args.sandbox,
        "domains": result.domains,
        "http": result.http,
        "eval_dumps": [p.name for p in result.eval_dumps],
        "docker_status": result.docker_status,
    }
    (result.log_dir / "indicators.json").write_text(
        json.dumps(iocs.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )
    if result.eval_dumps:
        print("eval dumps: " + ", ".join(p.name for p in result.eval_dumps), file=sys.stderr)
    if analysis is None:
        return _write_output(args.output, result.deobfuscated)
    analysis.indicators = iocs
    code = _emit(args, analysis, str(sample), sandbox=sandbox_meta)
    return code


def _emit(args, result, path: str | None, sandbox=None, stdout_code: bool = True) -> int:
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    report = build_report(result=result, path=path, sandbox=sandbox)
    sys.stderr.write(format_indicators(result.indicators))
    sys.stderr.write(format_analysis(report))
    _write_iocs(args, result.indicators)
    report_path = getattr(args, "report", None)
    html_path = getattr(args, "html", None)
    output = getattr(args, "output", None)
    if not report_path and output:
        report_path = str(Path(output).with_name(Path(output).stem + ".report.json"))
    if report_path:
        Path(report_path).write_text(dump_json(report), encoding="utf-8")
    if html_path:
        Path(html_path).write_text(render_html(report), encoding="utf-8")
    if sandbox and sandbox.get("log_dir"):
        Path(sandbox["log_dir"], "report.json").write_text(dump_json(report), encoding="utf-8")
    if stdout_code:
        _write_output(output, result.text)
    else:
        if output:
            Path(output).write_text(result.text, encoding="utf-8")
    if not result.parse_ok:
        print("error: parse failed after deobfuscation", file=sys.stderr)
        return 1
    return 0


def _write_iocs(args, iocs) -> None:
    output = getattr(args, "output", None)
    if output:
        out = Path(output)
        iocs_path = out.with_name(out.stem + ".iocs.json")
        iocs_path.write_text(json.dumps(iocs.to_dict(), indent=2) + "\n", encoding="utf-8")


def _write_output(output: str | None, text: str) -> int:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        return 0
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")
    return 0
