import asyncssh

from .base import Host


class SSHHost(Host):

    def __init__(
        self,
        hostname: str,
        username: str,
        known_hosts: str | None = None,
        insecure: bool = False,
    ):
        self.hostname = hostname
        self.username = username
        self._connection = None

        self._insecure = insecure
        self._known_hosts = known_hosts

    async def connect(self):
        """Establish an SSH connection to the remote host."""

        if self._connection is None:

            connect_kwargs = {
                "username": self.username,
            }

            if self._insecure:
                connect_kwargs["known_hosts"] = None
            elif self._known_hosts:
                connect_kwargs["known_hosts"] = self._known_hosts

            self._connection = await asyncssh.connect(
                self.hostname,
                **connect_kwargs,
            )

        return self

    async def close(self):
        """Close the SSH connection."""

        if self._connection is not None:
            self._connection.close()
            await self._connection.wait_closed()
            self._connection = None

    async def __aenter__(self):
        return await self.connect()

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()

    async def execute(self, command: str) -> str:
        """Execute a command on the remote host."""

        if self._connection is None:
            await self.connect()

        result = await self._connection.run(
            command,
            check=False,
        )

        if result.exit_status == 0:
            return result.stdout

        stderr = result.stderr.strip()

        if "No such file or directory" in stderr:
            raise FileNotFoundError(stderr)

        if "Permission denied" in stderr:
            raise PermissionError(stderr)

        raise RuntimeError(
            stderr or
            f"Command exited with status {result.exit_status}"
        )

    async def read_file(self, file: str):
        """Read a file from the remote host."""

        output = await self.execute(
            f"sudo cat {file}"
        )

        return output.splitlines()
