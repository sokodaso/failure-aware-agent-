"""Local environment whose commands run under macOS sandbox-exec: writes only inside the working
directory (and temp), no reads of /Users outside it, no network."""

import shlex
import sys
from pathlib import Path

from minisweagent.environments.local import LocalEnvironment

PROFILE = """
(version 1)
(allow default)
(deny file-write*)
(allow file-write* (subpath (param "WORK")) (subpath "/private/tmp") (subpath "/private/var/folders")
       (regex #"^/dev/(null|tty|zero|dtracehelper|fd/.*)$"))
(deny file-read* (subpath "/Users"))
(allow file-read* (subpath (param "WORK")))
(deny network*)
"""

SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"  # no project venv under /Users


class SandboxedLocalEnvironment(LocalEnvironment):
    def __init__(self, *, cwd: str, **kwargs):
        if sys.platform != "darwin":
            raise RuntimeError("SandboxedLocalEnvironment needs macOS sandbox-exec; use a Docker environment elsewhere")
        work = Path(cwd).resolve()  # /tmp is a symlink; the profile needs the real path
        work.mkdir(parents=True, exist_ok=True)
        kwargs["env"] = {"PATH": SAFE_PATH, "HOME": str(work), **kwargs.get("env", {})}
        super().__init__(cwd=str(work), **kwargs)
        self._work = str(work)

    def execute(self, action: dict, cwd: str = "", *, timeout: int | None = None) -> dict:
        command = action.get("command", "")
        wrapped = f"sandbox-exec -D WORK={shlex.quote(self._work)} -p {shlex.quote(PROFILE)} bash -c {shlex.quote(command)}"
        return super().execute({**action, "command": wrapped}, cwd, timeout=timeout)
