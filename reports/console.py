from datetime import datetime

import click

from models.host import HostModel


from dataclasses import asdict
from datetime import datetime


def prepare_report(
    trust_results,
    findings,
    failed_hosts,
    total_users: int,
    users_excluded: list[str],
    duration,
    generation_time=None,
):
    """Prepare a normalized STAyzer report."""
    if generation_time is None:
        generation_time = datetime.now().isoformat(
            timespec="seconds"
        )

    total_hosts = len(trust_results) + len(failed_hosts)

    total_keys = sum(
        len(user.ssh_keys)
        for host in trust_results
        for user in host.users
    )

    duplicate_keys = [
        finding
        for finding in findings
        if finding["type"] == "duplicate_key"
    ]
    users_audited = sum(len(host_result.users)
                        for host_result in trust_results)

    return {
        "scan": {
            "tool": "STAyzer",
            "generated_on": generation_time,
            "duration": duration,
            "hosts_scanned": total_hosts,
            "hosts_succeeded": len(trust_results),
            "hosts_failed": len(failed_hosts),
            "users_audited": users_audited,
            "users_excluded": users_excluded,
            "keys_discovered": total_keys,
        },

        "hosts": [
            asdict(host)
            for host in trust_results
        ],

        "failed_hosts": failed_hosts,

        "findings": findings,

        "statistics": {
            "total_hosts": total_hosts,
            "successful_hosts": len(trust_results),
            "failed_hosts": len(failed_hosts),
            "total_users": total_users,
            "total_keys": total_keys,
            "duplicate_keys": len(duplicate_keys),
            "total_findings": len(findings),
        },
    }


def print_report(report: dict):
    """Print a formatted STAyzer trust analysis report."""

    scan = report["scan"]
    hosts = report["hosts"]
    failed_hosts = report["failed_hosts"]
    findings = report["findings"]
    statistics = report["statistics"]

    click.secho(
        "\n" + "=" * 72,
        fg="cyan",
    )

    click.secho(
        " STAyzer - SSH Trust Analysis Report",
        fg="cyan",
        bold=True,
    )

    click.secho(
        "=" * 72,
        fg="cyan",
    )

    click.echo(
        f"Generated On....: {scan['generated_on']}"
    )

    click.echo(
        f"Duration........: {scan['duration']}"
    )

    click.echo(
        f"Hosts Scanned...: {scan['hosts_scanned']}"
    )

    click.echo(
        f"Successful......: {scan['hosts_succeeded']}"
    )

    click.echo(
        f"Failed..........: {scan['hosts_failed']}"
    )

    click.echo(
        f"Users Found.....: {statistics['total_users']}"
    )

    click.echo(
        f"Users Audited...: {scan['users_audited']}"
    )

    excluded = scan["users_excluded"]

    click.echo(
        "Users Excluded..: "
        + (", ".join(excluded) if excluded else "None")
    )

    click.echo(
        f"Keys Discovered.: {scan['keys_discovered']}"
    )

    click.secho(
        "=" * 72,
        fg="cyan",
    )

    for host in hosts:

        click.echo()

        click.secho(
            f"Host: {host['hostname']}",
            fg="blue",
            bold=True,
        )

        click.echo(
            f"Users with SSH keys : {len(host['users'])}"
        )

        click.echo("-" * 72)

        if not host["users"]:
            click.echo(
                "No SSH authorized keys discovered."
            )
            continue

        for user in host["users"]:

            key_count = len(user["ssh_keys"])

            key_label = (
                "Key"
                if key_count == 1
                else "Keys"
            )

            click.secho(
                f"User: {user['username']}",
                fg="green",
                bold=True,
            )

            click.echo(
                f"  UID  : {user['uid']}"
            )

            click.echo(
                f"  Keys : {key_count} {key_label}"
            )

            for index, key in enumerate(
                user["ssh_keys"],
                start=1,
            ):

                click.echo()

                click.echo(
                    f"  Key #{index}"
                )

                click.echo(
                    f"    Type        : {key['type']}"
                )

                click.echo(
                    f"    Fingerprint : {key['fingerprint']}"
                )

                if key["comment"]:
                    click.echo(
                        f"    Comment     : {key['comment']}"
                    )

        click.echo("-" * 72)

    click.secho(
        "=" * 72,
        fg="cyan",
    )

    click.secho(
        "Findings",
        fg="cyan",
        bold=True,
    )

    click.echo("-" * 72)

    if not findings:

        click.secho(
            "No security findings detected.",
            fg="green",
        )

    else:

        for finding in findings:

            finding_type = finding.get("type")

            if finding_type == "duplicate_key":

                occurrences = finding["occurrences"]
                category = finding.get("category", "unknown")
                severity = finding.get("severity", "unknown")

                severity_color = {
                    "critical": "red",
                    "medium": "yellow",
                    "low": "yellow",
                }.get(severity, "yellow")

                click.secho(
                    f"[{severity.upper()}] Shared SSH key "
                    f"detected ({occurrences} occurrences) "
                    f"- {category}",
                    fg=severity_color,
                    bold=True,
                )

                click.echo(
                    f"  Fingerprint : "
                    f"{finding['fingerprint']}"
                )

                click.echo("  Locations:")

                for location in finding["locations"]:

                    click.echo(
                        f"    - "
                        f"{location['hostname']}"
                    )

                    click.echo(
                        f"      User    : "
                        f"{location['username']}"
                    )

                    if location.get("comment"):
                        click.echo(
                            f"      Comment : "
                            f"{location['comment']}"
                        )

                click.echo()

            else:

                click.secho(
                    f"[WARNING] {finding_type}",
                    fg="yellow",
                )

    click.secho(
        "=" * 72,
        fg="cyan",
    )
    click.echo()

    click.secho(
        "Failed Hosts",
        fg="red",
        bold=True,
    )

    click.echo("-" * 72)

    if not failed_hosts:

        click.secho(
            "None",
            fg="green",
        )

    else:

        for host in failed_hosts:

            click.secho(
                host["hostname"],
                fg="red",
                bold=True,
            )

            click.echo(
                f"  Error  : {host['error']}"
            )

            click.echo(
                f"  Reason : {host['reason']}"
            )

            click.echo()

    click.secho(
        "=" * 72,
        fg="cyan",
    )
    click.secho(
        "Summary",
        fg="cyan",
        bold=True,
    )

    click.echo("-" * 72)

    click.echo(
        f"Hosts Scanned........: {statistics['total_hosts']}"
    )

    click.echo(
        f"Successful Hosts.....: {statistics['successful_hosts']}"
    )

    click.echo(
        f"Failed Hosts.........: {statistics['failed_hosts']}"
    )

    click.echo(
        f"Users Found..........: {statistics['total_users']}"
    )

    click.echo(
        f"Users Audited........: {scan['users_audited']}"
    )

    click.echo(
        f"SSH Keys Discovered..: "
        f"{statistics['total_keys']}"
    )

    click.echo(
        f"Duplicate Keys.......: "
        f"{statistics['duplicate_keys']}"
    )

    click.echo(
        f"Total Findings.......: "
        f"{statistics['total_findings']}"
    )

    click.echo()

    if statistics["failed_hosts"]:

        result = "INCOMPLETE"

        color = "red"

    elif findings:

        result = "ATTENTION REQUIRED"

        color = "yellow"

    else:

        result = "HEALTHY"

        color = "green"

    click.secho(
        f"Overall Result.....: {result}",
        fg=color,
        bold=True,
    )
