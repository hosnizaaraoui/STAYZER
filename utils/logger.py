import click
from datetime import datetime


class Logger:

    def __init__(self):
        self.verbose = False

    def configure(self, verbose: bool):
        self.verbose = verbose

    def _log(self, level: str, color: str, message: str, force: bool = False):
        # WARNING and ERROR are always shown (force=True) so that partial
        # coverage (skipped hosts/users, permission failures, etc.) is never
        # silently swallowed when --verbose isn't passed. Only INFO/SUCCESS
        # are gated behind --verbose since they're purely informational.
        if not self.verbose and not force:
            return

        now = datetime.now().strftime("%H:%M:%S")
        click.secho(
            f"[{now}] {level:<7} {message}",
            fg=color,
        )

    def info(self, message: str):
        self._log("INFO", "blue", message)

    def success(self, message: str):
        self._log("SUCCESS", "green", message)

    def warning(self, message: str):
        self._log("WARNING", "yellow", message, force=True)

    def error(self, message: str):
        self._log("ERROR", "red", message, force=True)


logger = Logger()
