"""Live audit board and telemetry recording for Auto Permissions Mode."""
import os
import sys
import json
import time
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from auto_permissions._console import ensure_utf8_console
ensure_utf8_console(vt100=True)

def get_audit_file() -> Path:
    """Get the persistent audit log file path."""
    audit_dir = Path.home() / ".gemini" / "antigravity" / "logs"
    audit_dir.mkdir(parents=True, exist_ok=True)
    return audit_dir / "audit.jsonl"

def _extract_project_name(context: Optional[Dict[str, Any]], args: Dict[str, Any]) -> str:
    """Extract project or workspace name from context or target path."""
    if context:
        ws_paths = context.get("workspace_paths", [])
        if ws_paths and isinstance(ws_paths, list):
            first_ws = ws_paths[0]
            if first_ws:
                return Path(str(first_ws)).name

    # Fallback to Cwd in tool args if available
    if isinstance(args, dict):
        cwd = args.get("Cwd")
        if cwd:
            return Path(str(cwd)).name

        # Or inspect a file target path (the file's parent directory is the project)
        for key in ("TargetFile", "AbsolutePath", "SearchPath"):
            path_val = args.get(key)
            if path_val and os.path.isabs(str(path_val)):
                return Path(str(path_val)).parent.name

        # Or a directory target itself (the directory is the project)
        for key in ("TargetDirectory", "DirectoryPath"):
            path_val = args.get(key)
            if path_val and os.path.isabs(str(path_val)):
                return Path(str(path_val)).name

    return "workspace"

_LAST_TRIM_CHECK_TIME = 0.0

def trim_audit_log(
    retention_days: int = 14,
    max_lines: int = 5000,
    audit_path: Optional[Path] = None,
) -> int:
    """Trim old entries from the audit log based on retention days and max lines.

    Returns the number of lines pruned.
    """
    if audit_path is None:
        audit_path = get_audit_file()
    if not audit_path.is_file():
        return 0

    temp_path = audit_path.parent / f"{audit_path.name}.{os.getpid()}.tmp"
    try:
        now = time.time()
        cutoff_timestamp = now - (retention_days * 86400) if retention_days > 0 else 0.0

        with open(audit_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        total_before = len(lines)
        surviving = []
        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                ts = float(data.get("timestamp", 0))
                if cutoff_timestamp > 0 and ts > 0 and ts < cutoff_timestamp:
                    continue  # expired by date
            except Exception:
                pass
            surviving.append(line_str)

        if max_lines > 0 and len(surviving) > max_lines:
            surviving = surviving[-max_lines:]

        pruned = total_before - len(surviving)
        if pruned > 0:
            with open(temp_path, "w", encoding="utf-8") as f:
                for item in surviving:
                    f.write(item + "\n")
                f.flush()
            try:
                temp_path.replace(audit_path)
            except (PermissionError, OSError):
                # Windows file locking or concurrent process access; abandon trim safely
                return 0

        return pruned
    except Exception:
        return 0
    finally:
        if temp_path.is_file():
            try:
                temp_path.unlink()
            except Exception:
                pass

def _maybe_trim_audit_log(
    audit_path: Path,
    config: Optional[Dict[str, Any]] = None,
) -> None:
    """Lightweight check to run trimming at most once per interval_seconds.

    Runs synchronously in the hook process rather than backgrounded: hook_handler is a
    short-lived CLI process that exits right after printing its JSON decision, so a
    daemon thread here would be killed before it could run, and spawning a detached
    subprocess cross-platform (DETACHED_PROCESS on Windows vs. fork/nohup on POSIX) is
    not worth the complexity given the cost — the interval/marker-file gate above makes
    this a single float/mtime comparison on 99.9% of calls, and the trim itself (capped
    at audit_max_lines, ~1MB) only runs once per interval and takes single-digit ms.
    """
    global _LAST_TRIM_CHECK_TIME
    now = time.time()
    cfg = config or {}
    interval = int(cfg.get("audit_trim_interval_seconds", 3600))
    if now - _LAST_TRIM_CHECK_TIME < interval:
        return

    _LAST_TRIM_CHECK_TIME = now
    marker_file = audit_path.parent / ".audit_last_trim"
    try:
        if marker_file.is_file():
            mtime = marker_file.stat().st_mtime
            if now - mtime < interval:
                return
        marker_file.write_text(str(now), encoding="utf-8")
        retention_days = int(cfg.get("audit_retention_days", 14))
        max_lines = int(cfg.get("audit_max_lines", 5000))
        trim_audit_log(retention_days=retention_days, max_lines=max_lines, audit_path=audit_path)
    except Exception:
        pass

def record_audit_event(
    tool_name: str,
    tool_args: Dict[str, Any],
    decision: str,
    reason: str,
    latency_ms: float,
    source: str = "LOCAL",
    context: Optional[Dict[str, Any]] = None,
    config: Optional[Dict[str, Any]] = None,
) -> None:
    """Append an evaluation event to the audit log in non-blocking fashion with retry (<0.5ms)."""
    try:
        project_name = _extract_project_name(context, tool_args)
        event = {
            "timestamp": time.time(),
            "time_str": time.strftime("%H:%M:%S"),
            "project": project_name,
            "source": source.upper(),
            "tool": tool_name,
            "args_summary": _summarize_args(tool_name, tool_args),
            "decision": decision.upper(),
            "reason": reason,
            "latency_ms": round(latency_ms, 1),
            "conversation_id": (context or {}).get("conversation_id", "")[:8],
        }
        line = json.dumps(event) + "\n"
        audit_path = get_audit_file()
        # Single best-effort attempt: this runs on the PreToolUse hot path for every
        # tool call, so a blocking sleep-and-retry loop on write contention would
        # directly inflate the latency budget the rest of this codebase tunes to the
        # millisecond. Losing an occasional telemetry line under contention is fine.
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()

        _maybe_trim_audit_log(audit_path, config=config)
    except Exception:
        pass

def _summarize_args(tool_name: str, args: Dict[str, Any]) -> str:
    """Format key tool arguments concisely for the dashboard."""
    if not isinstance(args, dict):
        return str(args)[:60]

    if "CommandLine" in args:
        return str(args["CommandLine"])
    if "AbsolutePath" in args:
        return Path(str(args["AbsolutePath"])).name
    if "TargetFile" in args:
        return Path(str(args["TargetFile"])).name
    if "DirectoryPath" in args:
        return Path(str(args["DirectoryPath"])).name
    if "Query" in args:
        return f"query: {args['Query']}"
    if "Url" in args:
        return str(args["Url"])

    s = json.dumps(args)
    return s if len(s) <= 60 else s[:57] + "..."

def run_live_board() -> None:
    """Stream live hook evaluations in a real-time terminal dashboard with dynamic terminal width."""
    audit_file = get_audit_file()
    print("\033[2J\033[H", end="") # Clear screen

    term_width = shutil.get_terminal_size((120, 24)).columns
    term_width = max(term_width, 80)

    print("=" * term_width)
    print("                              AUTO PERMISSIONS MODE — LIVE AUDIT DASHBOARD")
    print("=" * term_width)
    print(f"Log File : {audit_file}")
    print("Surfaces : Antigravity IDE | Antigravity 2.0 | VS Code Extension | agy CLI (Multi-Workspace)")
    print("Status   : STREAMING LIVE HOOK EVALUATIONS (Press Ctrl+C to stop)")
    print("=" * term_width)
    print(f"{'TIME':<9} | {'PROJECT':<16} | {'SOURCE':<10} | {'DECISION':<10} | {'LATENCY':<8} | {'TOOL':<14} | {'TARGET / COMMAND'}")
    print("-" * term_width)

    # Trim stale entries on monitor startup
    if audit_file.is_file():
        try:
            from auto_permissions.config import load_config
            cfg = load_config()
            trim_audit_log(
                retention_days=int(cfg.get("audit_retention_days", 14)),
                max_lines=int(cfg.get("audit_max_lines", 5000)),
                audit_path=audit_file
            )
        except Exception:
            pass

    # Display recent events
    last_pos = 0
    if audit_file.is_file():
        try:
            with open(audit_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for line in lines[-12:]:
                    _print_event_line(line)
                last_pos = f.tell()
        except Exception:
            pass

    # Tail the file in real-time
    try:
        while True:
            if not audit_file.is_file():
                time.sleep(0.3)
                continue

            with open(audit_file, "r", encoding="utf-8") as f:
                f.seek(last_pos)
                line = f.readline()
                while line:
                    _print_event_line(line)
                    last_pos = f.tell()
                    line = f.readline()
            time.sleep(0.15)
    except KeyboardInterrupt:
        print("\n\n✓ Live audit dashboard stopped.\n")

def _print_event_line(raw_json_line: str) -> None:
    """Render a single event line, expanding full command details on DENY or FORCE_ASK."""
    try:
        data = json.loads(raw_json_line.strip())
        dec = data.get("decision", "UNKNOWN")
        src = data.get("source", "LOCAL").upper()
        time_str = data.get("time_str", "")
        project = data.get("project", "workspace")[:15]
        lat = f"{data.get('latency_ms', 0):.1f}ms"
        tool = data.get("tool", "")[:13]
        summary = data.get("args_summary", "")

        # Compute remaining space on current terminal window
        term_width = shutil.get_terminal_size((120, 24)).columns
        fixed_prefix_len = 9 + 3 + 16 + 3 + 10 + 3 + 10 + 3 + 8 + 3 + 14 + 3 # ~82 chars
        available_target_len = max(15, term_width - fixed_prefix_len - 2)

        # In table view, clip if too long to maintain clean alignment
        display_summary = summary if len(summary) <= available_target_len else summary[:max(10, available_target_len - 3)] + "..."

        # ANSI Source Badges: AUTO (deterministic fast-path) vs USER-APP vs LOCAL-LLM vs FAILOVER vs CLOUD-LLM
        if src in ("FAST-PATH", "FASTPATH", "RULES", "RULE", "AUTO"):
            src_badge = "\033[32mAUTO      \033[0m" # Green (Instant deterministic 0ms auto-approval)
        elif src in ("USER-APPROVED", "USER-APP", "USER", "APPROVED"):
            src_badge = "\033[92mUSER-APP  \033[0m" # Bright Green (Explicit user authorization via modal)
        elif src == "LOCAL":
            src_badge = "\033[36mLOCAL-LLM \033[0m" # Cyan (Local Qwen/Gemma GPU inference)
        elif "FAIL" in src:
            src_badge = "\033[35mFAILOVER  \033[0m" # Magenta (Cloud failover fallback)
        elif src == "CLOUD":
            src_badge = "\033[34mCLOUD-LLM \033[0m" # Blue (Direct Cloud model)
        elif src == "OFFLINE":
            src_badge = "\033[31mOFFLINE   \033[0m" # Red (Model server offline)
        elif src == "ERROR":
            src_badge = "\033[31mHOOK ERR  \033[0m" # Red (Hook crashed before evaluation ran)
        elif src == "TIMEOUT":
            src_badge = "\033[33mTIMEOUT   \033[0m" # Yellow (Evaluation deadline exceeded)
        else:
            src_badge = f"{src:<10}"

        # ANSI Decision Badges
        if dec == "ALLOW":
            badge = "\033[32mALLOW     \033[0m"
        elif dec == "DENY":
            badge = "\033[31mDENY      \033[0m"
        elif dec in ("ASK", "QUESTION"):
            badge = "\033[93mASK       \033[0m"
        elif dec in ("FORCE_ASK", "FORCEASK"):
            badge = "\033[33mFORCE_ASK \033[0m"
        else:
            badge = f"{dec:<10}"

        print(f"{time_str:<9} | {project:<16} | {src_badge} | {badge} | {lat:<8} | {tool:<14} | {display_summary}")

        # If DENY, ASK, FORCE_ASK, or USER-APPROVED: print the full details AND the reason!
        if dec in ("DENY", "FORCE_ASK", "FORCEASK", "ASK", "QUESTION") or src in ("USER-APPROVED", "USER-APP", "APPROVED"):
            # 1. Print full target if it was truncated in the table line
            if len(summary) > available_target_len:
                print(f"   ↳ 📋 FULL PAYLOAD: \033[97m{summary}\033[0m")

            # 2. Print exact reason and safe alternative
            if data.get("reason"):
                reason_text = data["reason"].strip()
                if src in ("USER-APPROVED", "USER-APP", "APPROVED"):
                    prefix = "   ↳ 👤 USER-APPROVED: "
                    color = "\033[92m"
                elif dec == "DENY":
                    prefix = "   ↳ 🛑 REASON: "
                    color = "\033[91m"
                elif dec in ("ASK", "QUESTION"):
                    prefix = "   ↳ ❓ ALTERNATIVES: "
                    color = "\033[93m"
                elif dec in ("FORCE_ASK", "FORCEASK"):
                    prefix = "   ↳ ⚠️ CONFIRMATION: "
                    color = "\033[33m"
                else:
                    prefix = "   ↳ ℹ️ INFO: "
                    color = "\033[37m"
                print(f"{color}{prefix}{reason_text}\033[0m")
    except Exception:
        pass
