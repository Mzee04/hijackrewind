"""In-process kill switch.

Tripping it is a flag any thread can see. The HTTP task polls the flag and
cancels the in-flight call. The flag is not an asyncio primitive, so a second
event loop (a later CLI command, or the dashboard) still observes it.
Closing a laptop lid or kill -9 is not this switch.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

from hijackrewind.audit import AuditLog


class ToolCancelled(Exception):
    """A tool call was refused or aborted because the kill switch is tripped."""


class KillSwitch:
    def __init__(self, flag_path: Path | None = None) -> None:
        self.flag_path = flag_path
        self._tripped = False
        self.reason: str | None = None
        self._thread = threading.Event()
        self._lock = threading.Lock()

    def _poll_file(self) -> None:
        path = self.flag_path
        if path is None or self._tripped or not path.exists():
            return
        try:
            reason = path.read_text(encoding="utf-8").strip() or "kill file"
        except OSError:
            reason = "kill file"
        self.trip(reason, write_file=False)

    @property
    def tripped(self) -> bool:
        self._poll_file()
        return self._tripped

    def trip(
        self,
        reason: str,
        audit: AuditLog | None = None,
        run_id: str = "-",
        *,
        write_file: bool = True,
    ) -> None:
        with self._lock:
            already = self._tripped
            self._tripped = True
            self.reason = reason
        self._thread.set()
        if write_file and self.flag_path is not None:
            self.flag_path.parent.mkdir(parents=True, exist_ok=True)
            self.flag_path.write_text(reason + "\n", encoding="utf-8")
        if audit is not None and not already:
            audit.append(
                run_id=run_id,
                actor="kill_switch",
                action="tripped",
                detail={"reason": reason},
            )

    def raise_if_tripped(self) -> None:
        if self.tripped:
            raise ToolCancelled(self.reason or "kill switch")

    async def wait(self) -> None:
        while not self.tripped:
            await asyncio.sleep(0.05)

    def reset(self, audit: AuditLog | None = None) -> None:
        """Operator clears the switch for a later run. The cancelled call stays cancelled."""
        with self._lock:
            self._tripped = False
            self.reason = None
        self._thread.clear()
        if self.flag_path is not None and self.flag_path.exists():
            self.flag_path.unlink()
        if audit is not None:
            audit.append(run_id="-", actor="operator", action="kill_switch_reset", detail={})
