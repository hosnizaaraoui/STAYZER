import shlex
import asyncssh
import click
from time import perf_counter

from hosts.ssh import SSHHost
from collectors.passwd import filter_human_users
from filters.parser import apply_filters, get_users_excluded, parse_filter_expression
from models.host import HostModel
from models.sshkey import SSHKey
from utils.logger import logger


async def _check_authorized_keys_paths(
    host: SSHHost,
) -> list[str] | None:
    """
    Return the configured AuthorizedKeysFile paths.

    Returns:
        list[str]: Configured paths.
        None: Directive is commented out or not present.
    """

    sshd_config = await host.read_file("/etc/ssh/sshd_config")

    for line in sshd_config:

        line = line.strip()

        # Ignore blank and commented lines
        if not line or line.startswith("#"):
            continue

        fields = line.split()

        if fields[0] == "AuthorizedKeysFile":
            return fields[1:]

    return None


def _expand_authorized_keys_paths(
    templates: list[str] | None,
    user,
) -> list[str]:

    if templates is None:
        return [
            f"/home/{user.username}/.ssh/authorized_keys"
        ]

    paths = []

    for template in templates:

        path = (
            template
            .replace("%h", f"/home/{user.username}")
            .replace("%u", user.username)
            .replace("%U", str(user.uid))
        )

        if not path.startswith("/"):
            path = f"/home/{user.username}/{path}"

        paths.append(path)

    return paths


def _classify_duplicate(occurrences: list[tuple[str, str, str]]) -> tuple[str, str]:
    """Classify a duplicate-key finding by severity.

    - same_host_multi_user   : one host, several local accounts share a key.
                                Usually a provisioning shortcut.
    - shared_service_account : same username reused across hosts (e.g. a
                                deploy/service account intentionally sharing
                                a key).
    - cross_host_cross_user  : different users AND different hosts share the
                                same private key.
    """

    hosts = {hostname for hostname, _, _ in occurrences}
    users = {username for _, username, _ in occurrences}

    if len(hosts) == 1:
        return "same_host_multi_user", "medium"
    elif len(users) == 1:
        return "shared_service_account", "low"
    else:
        return "cross_host_cross_user", "critical"


def check_duplicate_keys(
    trust_results: list[HostModel],
    verbose: bool
) -> list[dict]:
    """Detect SSH keys authorized on multiple accounts."""

    fingerprints: dict[
        str,
        list[tuple[str, str]]
    ] = {}

    for host in trust_results:
        for user in host.users:
            for key in user.ssh_keys:
                fingerprints.setdefault(
                    key.fingerprint,
                    []
                ).append(
                    (host.hostname, user.username, key.comment)
                )

    findings = []

    for fingerprint, occurrences in fingerprints.items():

        if len(occurrences) < 2:
            continue

        category, severity = _classify_duplicate(occurrences)

        finding = {
            "type": "duplicate_key",
            "category": category,
            "severity": severity,
            "fingerprint": fingerprint,
            "occurrences": len(occurrences),
            "locations": [
                {
                    "hostname": hostname,
                    "username": username,
                    "comment": comment,
                }
                for hostname, username, comment in occurrences
            ],
        }

        findings.append(finding)

        logger.warning(
            f"Shared SSH key detected [{category}/{severity}] "
            f"({len(occurrences)} occurrences)"
        )

        if verbose:

            click.secho(
                f".... Fingerprint : {fingerprint}",
                fg="yellow",
            )

            click.secho(
                ".... Locations:",
                fg="yellow",
            )

            for hostname, username, comment in occurrences:
                click.secho(
                    f"    - {hostname}\n"
                    f"      User    : {username}\n"
                    f"      Comment : {comment}",
                    fg="yellow",
                )

            print()

    return findings


async def analyze_ssh_trust(
    target_hosts: list,
    filter_expression: str,
    verbose: bool,
):
    """Execute the SSH trust analysis."""

    logger.verbose = verbose
    start_time = perf_counter()

    trust_results: list[HostModel] = []
    failed_hosts: list[dict] = []

    filters = parse_filter_expression(
        filter_expression
    )
    total_users = 0
    users_excluded = get_users_excluded(filters)

    logger.info(
        f"Starting SSH trust analysis on "
        f"{len(target_hosts)} host(s)."
    )

    for host in target_hosts:

        logger.info(
            f"Analyzing host '{host.hostname}'."
        )

        # One SSH connection for the entire host analysis.
        try:
            async with host:

                try:
                    passwd_content = await host.read_file(
                        "/etc/passwd"
                    )

                except Exception as e:
                    logger.error(
                        f"Failed to read /etc/passwd from "
                        f"'{host.hostname}': {e}"
                    )
                    continue

                users = filter_human_users(
                    passwd_content
                )

                logger.success(
                    f"Found {len(users)} human user(s) on "
                    f"'{host.hostname}'."
                )

                total_users += len(users)

                users = [
                    user
                    for user in users
                    if apply_filters(user, host, filters)
                ]

                host_result = HostModel(
                    hostname=host.hostname
                )

                try:
                    configured_paths = await _check_authorized_keys_paths(host)
                except Exception as e:
                    logger.error(
                        f"Failed to read /etc/ssh/sshd_config from "
                        f"'{host.hostname}': {e}"
                    )
                    continue

                for user in users:

                    logger.info(
                        f"Inspecting authorized_keys for "
                        f"'{user.username}'."
                    )
                    paths = _expand_authorized_keys_paths(
                        configured_paths,
                        user,
                    )

                    try:

                        for path in paths:

                            safe_path = shlex.quote(path)

                            try:
                                output = await host.execute(f"sudo ssh-keygen -lf {safe_path} -E sha256")
                            except FileNotFoundError:
                                continue
                            except PermissionError:
                                logger.warning(
                                    f"Permission denied reading '{path}' for '{user.username}'.")
                                continue

                            ssh_keys = []

                            for line in output.splitlines():

                                fields = line.split()

                                if len(fields) < 4:
                                    continue

                                ssh_key = SSHKey(
                                    fingerprint=fields[1],
                                    type=fields[-1][1:-1],
                                    comment=" ".join(
                                        fields[2:-1]
                                    ),
                                )

                                ssh_keys.append(ssh_key)

                            user.ssh_keys.extend(
                                ssh_keys
                            )

                            key_count = len(
                                user.ssh_keys
                            )

                            key_label = (
                                "Key"
                                if key_count == 1
                                else "Keys"
                            )

                            logger.success(
                                f"User: {user.username}\n"
                                f".... SSH Keys : "
                                f"{key_count} {key_label}"
                            )

                            if logger.verbose:

                                for index, key in enumerate(
                                    user.ssh_keys,
                                    start=1,
                                ):
                                    click.secho(
                                        f".... Key #{index}",
                                        fg="green",
                                    )

                                    click.secho(
                                        f"       Type        : "
                                        f"{key.type}",
                                        fg="green",
                                    )

                                    click.secho(
                                        f"       Fingerprint : "
                                        f"{key.fingerprint}",
                                        fg="green",
                                    )

                                    click.secho(
                                        f"       Comment     : "
                                        f"{key.comment}",
                                        fg="green",
                                    )

                                print()
                        if not user.ssh_keys:
                            logger.info(
                                f"User '{user.username}' has no authorized SSH keys."
                            )
                        else:
                            host_result.users.append(
                                user
                            )

                    except Exception as e:
                        logger.error(
                            f"Failed to analyze SSH trust for "
                            f"'{user.username}': {e}"
                        )

                trust_results.append(
                    host_result
                )
        except asyncssh.misc.HostKeyNotVerifiable as e:
            logger.error(
                f"Host key verification failed for '{host.hostname}'."
            )
            logger.info(
                "Trust the host with ssh, use --known-hosts, "
                "or --insecure in a lab."
            )

            failed_hosts.append({
                "hostname": host.hostname,
                "error": type(e).__name__,
                "reason": str(e),
            })
            continue
        except asyncssh.misc.PermissionDenied as e:
            logger.error(
                f"Permission Denied for user {host.username} on host '{host.hostname}'."
            )

            failed_hosts.append({
                "hostname": host.hostname,
                "error": type(e).__name__,
                "reason": str(e),
            })
            continue
    findings = check_duplicate_keys(
        trust_results,
        logger.verbose
    )

    elapsed = perf_counter() - start_time
    return (
        trust_results,
        findings,
        failed_hosts,
        total_users,
        users_excluded,
        elapsed,
    )
