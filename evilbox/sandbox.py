from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from evilbox.pipeline import deobfuscate

IMAGE_NAME = "evilbox-php-sandbox"
QUERY_RE = re.compile(r"query\[[^\]]+\]\s+(\S+)", re.I)


class SandboxError(RuntimeError):
    pass


def sandbox_context_dir() -> Path:
    start = Path(__file__).resolve().parent
    for base in [start, *start.parents]:
        candidate = base / "sandbox" / "php" / "Dockerfile"
        if candidate.is_file():
            return candidate.parent
    raise SandboxError("Could not find sandbox/php/Dockerfile (run from the Evilbox repo).")


@dataclass
class SandboxResult:
    log_dir: Path
    domains: list[str]
    eval_dumps: list[Path]
    deobfuscated: str
    docker_status: int
    image_tag: str


def _run(cmd: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout)


def build_image(context: Path, tag: str) -> None:
    proc = _run(
        ["docker", "build", "-t", tag, str(context)],
        timeout=600,
    )
    if proc.returncode != 0:
        raise SandboxError(
            "docker build failed:\n" + (proc.stderr or proc.stdout or "no output")
        )


def docker_run_args(
    *,
    tag: str,
    sample: Path,
    log_dir: Path,
    mode: str,
    timeout: int,
    container_name: str,
) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--network",
        "none",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "--pids-limit",
        "128",
        "--env",
        f"SANDBOX_MODE={mode}",
        "--env",
        f"SANDBOX_TIMEOUT={timeout}",
        "--env",
        "SANDBOX_LOGS=/logs",
        "--mount",
        f"type=bind,src={sample},dst=/samples/sample.php,readonly=true",
        "--mount",
        f"type=bind,src={log_dir},dst=/logs",
        "--mount",
        "type=tmpfs,destination=/tmp",
        tag,
        "/samples/sample.php",
    ]


def finalize_logs(log_dir: Path) -> tuple[list[str], list[Path]]:
    domains: set[str] = set()
    domains_file = log_dir / "domains.txt"
    if domains_file.exists():
        domains.update(
            line.strip().lower()
            for line in domains_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        )
    dns_log = log_dir / "dns.log"
    if dns_log.exists():
        for line in dns_log.read_text(encoding="utf-8", errors="replace").splitlines():
            match = QUERY_RE.search(line)
            if match:
                host = match.group(1).rstrip(".").lower()
                if host and host not in {".", "localhost"}:
                    domains.add(host)
    http_jsonl = log_dir / "http.jsonl"
    if http_jsonl.exists():
        for line in http_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = str(rec.get("host") or "").split(":")[0].lower()
            if host:
                domains.add(host)
    dumps = sorted(log_dir.glob("eval-*.php"))
    summary = {
        "domains": sorted(domains),
        "eval_dumps": [p.name for p in dumps],
    }
    (log_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    domains_file.write_text("".join(d + "\n" for d in sorted(domains)), encoding="utf-8")
    return sorted(domains), dumps


def _best_source(sample: Path, dumps: list[Path]) -> str:
    if dumps:
        return dumps[-1].read_text(encoding="utf-8", errors="replace")
    return sample.read_text(encoding="utf-8", errors="replace")


def run_php_sandbox(
    sample: Path,
    *,
    mode: str,
    logs_root: Path,
    timeout: int = 15,
) -> SandboxResult:
    if shutil.which("docker") is None:
        raise SandboxError("docker is not installed or not on PATH.")
    if mode not in {"dump", "observe"}:
        raise SandboxError("mode must be dump or observe")

    sample = sample.resolve()
    if not sample.is_file():
        raise SandboxError(f"sample not found: {sample}")

    context = sandbox_context_dir()
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    tag = f"{IMAGE_NAME}:{run_id}"
    container_name = f"evilbox-{run_id}"
    log_dir = (logs_root / run_id).resolve()
    log_dir.mkdir(parents=True, exist_ok=True)

    build_image(context, tag)
    args = docker_run_args(
        tag=tag,
        sample=sample,
        log_dir=log_dir,
        mode=mode,
        timeout=timeout,
        container_name=container_name,
    )
    host_timeout = timeout + 90
    proc: subprocess.CompletedProcess[str] | None = None
    timed_out = False
    try:
        proc = _run(args, timeout=host_timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _run(["docker", "rm", "-f", container_name], timeout=30)
    finally:
        rmi = _run(["docker", "rmi", "-f", tag], timeout=60)
        if rmi.returncode != 0:
            (log_dir / "docker.rmi.err").write_text(rmi.stderr or "", encoding="utf-8")

    if proc is not None:
        (log_dir / "docker.stdout.log").write_text(proc.stdout or "", encoding="utf-8")
        (log_dir / "docker.stderr.log").write_text(proc.stderr or "", encoding="utf-8")
        (log_dir / "docker.status").write_text(str(proc.returncode) + "\n", encoding="utf-8")
        status = proc.returncode
    else:
        (log_dir / "docker.status").write_text("timeout\n", encoding="utf-8")
        status = -1

    domains, dumps = finalize_logs(log_dir)
    source = _best_source(sample, dumps)
    cleaned = deobfuscate(source, language="php")
    (log_dir / "deobfuscated.php").write_text(cleaned.text, encoding="utf-8")
    if timed_out:
        raise SandboxError(f"sandbox timed out after {host_timeout}s; logs kept at {log_dir}")
    return SandboxResult(
        log_dir=log_dir,
        domains=domains,
        eval_dumps=dumps,
        deobfuscated=cleaned.text,
        docker_status=status,
        image_tag=tag,
    )


def default_logs_root() -> Path:
    env = os.environ.get("EVILBOX_LOGS") or os.environ.get("DEOBFUSCATOR_LOGS")
    if env:
        return Path(env)
    return Path.cwd() / "sandbox-logs"
