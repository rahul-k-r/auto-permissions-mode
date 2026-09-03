"""Shared Windows console setup (UTF-8 stdio, VT100 ANSI processing)."""
import sys

def ensure_utf8_console(stdin: bool = False, vt100: bool = False) -> None:
    """Reconfigure stdio to UTF-8 and optionally enable VT100 ANSI escapes on Windows."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace") # type: ignore
        except Exception:
            pass
    if stdin and hasattr(sys.stdin, "reconfigure"):
        try:
            sys.stdin.reconfigure(encoding="utf-8", errors="replace") # type: ignore
        except Exception:
            pass
    if vt100 and sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            hStdOut = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(hStdOut, ctypes.byref(mode))
            kernel32.SetConsoleMode(hStdOut, mode.value | 0x0004) # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass
