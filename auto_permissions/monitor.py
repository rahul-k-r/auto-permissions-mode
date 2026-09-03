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

def record_audit_event(
    tool_name: str,
    tool_args: Dict[str, Any],
    decision: str,
    reason: str,
    latency_ms: float,
    source: str = "LOCAL",
    context: Optional[Dict[str, Any]] = None
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

        # ANSI Source Badges: AUTO (deterministic fast-path) vs LOCAL-LLM vs FAILOVER vs CLOUD-LLM
        if src in ("FAST-PATH", "FASTPATH", "RULES", "RULE", "AUTO"):
            src_badge = "\033[32mAUTO      \033[0m" # Green (Instant deterministic 0ms auto-approval)
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
        elif "ASK" in dec:
            badge = "\033[33mFORCE_ASK \033[0m"
        else:
            badge = f"{dec:<10}"

        print(f"{time_str:<9} | {project:<16} | {src_badge} | {badge} | {lat:<8} | {tool:<14} | {display_summary}")

        # If DENY or FORCE_ASK: print the full untruncated command/target AND the reason!
        if dec in ("DENY", "FORCE_ASK", "ASK"):
            # 1. Print full target if it was truncated in the table line
            if len(summary) > available_target_len:
                print(f"   ↳ 📋 FULL PAYLOAD: \033[97m{summary}\033[0m")

            # 2. Print exact reason and safe alternative
            if data.get("reason"):
                reason_text = data["reason"].strip()
                prefix = "   ↳ 🛑 REASON: " if dec == "DENY" else "   ↳ ⚠️ CONFIRMATION: "
                color = "\033[91m" if dec == "DENY" else "\033[93m"
                print(f"{color}{prefix}{reason_text}\033[0m")
    except Exception:
        pass
