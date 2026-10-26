"""Local multi-client clean-room boundary, worktree collision, and ZDR memory scanner."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

TECHNICAL_SCOPE_NOTICE = (
    "Technical Scope Notice: Agent Posture Guard records process, filesystem-allowlist, "
    "and API-telemetry evidence configured on the host OS. Technical attestations document "
    "observed runtime boundaries and do not constitute legal opinions or third-party audit certifications."
)

PILOT_RESERVATION_URL = (
    "https://cjprybol.github.io/app-portfolio-landing-pages/agent-posture-guard/"
)

AGENT_PROCESS_PREFIXES = (
    "claude",
    "codex",
    "cursor",
    "gemini",
    "opencode",
    "aider",
    "python",
    "node",
)

MEMORY_LEAK_ENV_VARS: dict[str, tuple[str, ...]] = {
    "HINDSIGHT_ENABLED": ("1", "true", "yes", "on"),
    "OPENAI_STORE": ("1", "true", "yes", "on"),
    "ANTHROPIC_LOG_PROMPTS": ("1", "true", "yes", "on"),
    "LANGCHAIN_TRACING_V2": ("1", "true", "yes", "on"),
}


@dataclass(frozen=True)
class PosturePolicy:
    """Declarative boundary policy for one billable client scope."""

    client_scope: str
    allowed_paths: tuple[str, ...]
    quarantined_paths: tuple[str, ...] = ()
    require_zdr: bool = True

    @classmethod
    def from_file(cls, path: Path) -> PosturePolicy:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            client_scope=str(raw["client_scope"]),
            allowed_paths=tuple(str(Path(p).resolve()) for p in raw["allowed_paths"]),
            quarantined_paths=tuple(
                str(Path(p).resolve()) for p in raw.get("quarantined_paths", ())
            ),
            require_zdr=bool(raw.get("require_zdr", True)),
        )


@dataclass(frozen=True)
class ObservedProcess:
    """Normalized open-file/cwd snapshot for one active OS process."""

    pid: int
    command: str
    open_paths: tuple[str, ...]


@dataclass(frozen=True)
class PostureViolation:
    """Detected clean-room, worktree, or ZDR posture violation."""

    code: str
    severity: str
    detail: str
    pid: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class PostureScanResult:
    """Deterministic result of scanning a workstation against a PosturePolicy."""

    client_scope: str
    active_worktree: str
    git_branch: str
    git_head_sha: str
    quarantined_repo_count: int
    external_memory_bank_zdr: bool
    violations: tuple[PostureViolation, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        return not any(v.severity == "FAIL" for v in self.violations)

    @property
    def status_code(self) -> str:
        return "ZERO_CROSS_REPO_READS_VERIFIED" if self.passed else "POSTURE_VIOLATION_DETECTED"

    def to_dict(self) -> dict[str, object]:
        return {
            "client_scope": self.client_scope,
            "active_worktree": self.active_worktree,
            "git_branch": self.git_branch,
            "git_head_sha": self.git_head_sha,
            "quarantined_repo_count": self.quarantined_repo_count,
            "external_memory_bank_zdr": self.external_memory_bank_zdr,
            "passed": self.passed,
            "status_code": self.status_code,
            "violations": [v.to_dict() for v in self.violations],
        }


def parse_lsof_field_output(raw: str) -> list[ObservedProcess]:
    """Parse `lsof -F pcn` machine-readable output into ObservedProcess entries."""
    procs: list[ObservedProcess] = []
    cur_pid: int | None = None
    cur_cmd = ""
    cur_paths: list[str] = []

    for line in raw.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            if cur_pid is not None:
                procs.append(ObservedProcess(cur_pid, cur_cmd, tuple(cur_paths)))
            try:
                cur_pid = int(val)
            except ValueError:
                cur_pid = None
            cur_cmd = ""
            cur_paths = []
        elif tag == "c":
            cur_cmd = val
        elif tag == "n":
            if val.startswith("/"):
                cur_paths.append(val)

    if cur_pid is not None:
        procs.append(ObservedProcess(cur_pid, cur_cmd, tuple(cur_paths)))
    return procs


def default_process_probe() -> list[ObservedProcess]:
    """Probe open paths via `/usr/sbin/lsof -F pcn -d cwd,txt,0,1,2,3,4,5` if available."""
    lsof_bin = "/usr/sbin/lsof" if Path("/usr/sbin/lsof").exists() else "lsof"
    try:
        proc = subprocess.run(
            [lsof_bin, "-n", "-P", "-F", "pcn", "-d", "cwd"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        return parse_lsof_field_output(proc.stdout)
    except Exception:
        return []


def default_git_metadata(worktree: Path) -> tuple[str, str]:
    """Return (branch_name, head_sha) for a git directory, degrading cleanly if non-git."""
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null"}
    try:
        br = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            env=env,
            timeout=3.0,
            check=False,
        )
        sha = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            env=env,
            timeout=3.0,
            check=False,
        )
        branch = br.stdout.strip() if br.returncode == 0 else "detached-or-untracked"
        head = sha.stdout.strip() if sha.returncode == 0 else "0" * 40
        return branch, head
    except Exception:
        return "unknown", "0" * 40


def _is_subpath(candidate: str, root: str) -> bool:
    cand_norm = candidate.rstrip("/") + "/"
    root_norm = root.rstrip("/") + "/"
    return cand_norm.startswith(root_norm)


def _is_agent_process(cmd: str) -> bool:
    low = cmd.lower()
    return any(low.startswith(pref) for pref in AGENT_PROCESS_PREFIXES)


def scan_runtime_posture(
    policy: PosturePolicy,
    *,
    worktree: Path | None = None,
    current_pid: int | None = None,
    env: Mapping[str, str] | None = None,
    processes: Sequence[ObservedProcess] | None = None,
    git_probe: Callable[[Path], tuple[str, str]] = default_git_metadata,
) -> PostureScanResult:
    """Evaluate host process descriptors, worktree occupancy, and ZDR env against policy."""
    wt_resolved = (worktree or Path(policy.allowed_paths[0])).resolve()
    wt_str = str(wt_resolved)
    pid_self = os.getpid() if current_pid is None else current_pid
    env_map = os.environ if env is None else env
    observed = list(default_process_probe() if processes is None else processes)

    allowed_resolved = tuple(str(Path(p).resolve()) for p in policy.allowed_paths)
    quarantined_resolved = tuple(str(Path(p).resolve()) for p in policy.quarantined_paths)

    violations: list[PostureViolation] = []

    # 1. Verify active worktree itself is inside policy.allowed_paths and NOT quarantined
    if not any(_is_subpath(wt_str, allow) for allow in allowed_resolved):
        violations.append(
            PostureViolation(
                code="WORKTREE_OUTSIDE_ALLOWLIST",
                severity="FAIL",
                detail=f"Active worktree '{wt_str}' is outside allowed paths for client '{policy.client_scope}'.",
            )
        )
    if any(_is_subpath(wt_str, q) for q in quarantined_resolved):
        violations.append(
            PostureViolation(
                code="WORKTREE_IN_QUARANTINE",
                severity="FAIL",
                detail="Active worktree resolves inside a quarantined sibling repository.",
            )
        )

    # 2. Check ZDR / external memory-bank posture
    zdr_ok = True
    for var_name, truthy_vals in MEMORY_LEAK_ENV_VARS.items():
        val = env_map.get(var_name, "").strip().lower()
        if val in truthy_vals:
            zdr_ok = False
            if policy.require_zdr:
                violations.append(
                    PostureViolation(
                        code="MEMORY_POSTURE_DRIFT",
                        severity="FAIL",
                        detail=f"Environment variable {var_name}={env_map.get(var_name)!r} violates ZDR / zero-memory-bank requirement.",
                    )
                )
    if env_map.get("HINDSIGHT_BANK_ID", "").strip():
        zdr_ok = False
        if policy.require_zdr:
            violations.append(
                PostureViolation(
                    code="MEMORY_POSTURE_DRIFT",
                    severity="FAIL",
                    detail="Active HINDSIGHT_BANK_ID detected during ZDR-mandated client session.",
                )
            )

    # 3. Inspect OS processes for cross-repo quarantine breaches & concurrent worktree collisions
    other_agents_in_worktree: list[ObservedProcess] = []
    for proc in observed:
        if proc.pid == pid_self:
            # Self process must NEVER hold descriptors in quarantined repos
            for pth in proc.open_paths:
                if any(_is_subpath(pth, q) for q in quarantined_resolved):
                    violations.append(
                        PostureViolation(
                            code="QUARANTINE_FD_BREACH",
                            severity="FAIL",
                            detail=f"Current session PID {proc.pid} ({proc.command}) holds an open handle inside a quarantined repository.",
                            pid=proc.pid,
                        )
                    )
            continue

        if not _is_agent_process(proc.command):
            continue

        touches_active_wt = any(_is_subpath(pth, wt_str) for pth in proc.open_paths)
        touches_quarantine = any(
            _is_subpath(pth, q) for pth in proc.open_paths for q in quarantined_resolved
        )

        # Bridge hazard: a single agent process touching BOTH this client's worktree AND a quarantined repo!
        if touches_active_wt and touches_quarantine:
            violations.append(
                PostureViolation(
                    code="CROSS_REPO_BRIDGE_HAZARD",
                    severity="FAIL",
                    detail=f"Process PID {proc.pid} ({proc.command}) simultaneously accesses active worktree and a quarantined sibling repo.",
                    pid=proc.pid,
                )
            )
        elif touches_active_wt:
            other_agents_in_worktree.append(proc)

    for collider in other_agents_in_worktree:
        violations.append(
            PostureViolation(
                code="WORKTREE_COLLISION",
                severity="WARN",
                detail=f"Concurrent agent process PID {collider.pid} ({collider.command}) occupies worktree '{wt_str}'.",
                pid=collider.pid,
            )
        )

    branch, head_sha = git_probe(wt_resolved)
    return PostureScanResult(
        client_scope=policy.client_scope,
        active_worktree=wt_str,
        git_branch=branch,
        git_head_sha=head_sha,
        quarantined_repo_count=len(quarantined_resolved),
        external_memory_bank_zdr=zdr_ok,
        violations=tuple(violations),
    )
