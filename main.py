import asyncio

import asyncssh
import click

from reports.html import export_html
from reports.json import export_json
from collectors.analyzer import analyze_ssh_trust, check_duplicate_keys
from hosts.local import LocalHost
from hosts.ssh import SSHHost
from datetime import datetime
from reports.console import prepare_report, print_report

from pathlib import Path


def _resolve_known_hosts(
    known_hosts: str | None,
    insecure: bool,
) -> str | None:
    """Return the known_hosts file to use."""

    if insecure:
        return None

    if known_hosts is not None:
        return known_hosts

    return str(Path.home() / ".ssh" / "known_hosts")


def _build_target_hosts(
    hosts: tuple[str],
    inventory: str | None,
    username: str,
    exclude_localhost: bool,
    known_hosts: str | None = None,
    insecure: bool = False,
):
    """Build the list of hosts to analyze."""

    target_hosts = []

    if hosts and inventory:
        raise click.UsageError(
            "Use either --host or --inventory, not both."
        )

    if hosts:
        for hostname in hosts:
            target_hosts.append(
                SSHHost(
                    hostname,
                    username,
                    known_hosts=known_hosts,
                    insecure=insecure,
                )
            )

    elif inventory:
        with open(inventory) as file:
            for line in file:
                parts = line.strip().split(">", 1)
                hostname = parts[0]
                host_user = parts[1] if len(
                    parts) > 1 and parts[1] else username

                if hostname:
                    target_hosts.append(
                        SSHHost(
                            hostname,
                            host_user,
                            known_hosts=known_hosts,
                            insecure=insecure,
                        )
                    )

    if not exclude_localhost:
        target_hosts.append(LocalHost())

    return target_hosts


def _format_duration(seconds: float):
    if seconds < 60:
        duration = f"{seconds:.2f} second(s)"
    elif seconds < 3600:
        duration = f"{seconds / 60:.2f} minute(s)"
    else:
        duration = f"{seconds / 3600:.2f} hour(s)"
    return duration


@click.group()
def cli():
    """STAyazer - SSH Trust Analayzer."""
    pass


@cli.command(
    help="""\b
   ______________                        
  / ___/_  __/   | __  ______  ___  _____
  \\__ \\ / / / /| |/ / / /_  / / _ \\/ ___/
 ___/ // / / ___ / /_/ / / /_/  __/ /    
/____//_/ /_/  |_\\__, / /___/\\___/_/     
                /____/                   
Audit SSH authorized_keys trust across hosts and detect shared/duplicate keys."""
)
@click.option(
    "-s",
    "--host",
    multiple=True,
    help="Remote host to analyze. Can be specified multiple times.",
)
@click.option(
    "-i",
    "--inventory",
    type=click.Path(exists=True),
    help="Inventory file containing one host per line.",
)
@click.option(
    "-u",
    "--user",
    default="oopser",
    show_default=True,
    help="SSH username.",
)
@click.option(
    "--exclude-localhost",
    is_flag=True,
    help="Skip Analyzing the local machine.",
)
@click.option(
    "--known-hosts",
    type=click.Path(exists=True),
    default=None,
    help="Path to a known_hosts file used to verify remote host keys.",
)
@click.option(
    "--insecure",
    is_flag=True,
    help=(
        "DANGEROUS: disable SSH host key verification. "
        "Only use for lab/throwaway environments."
    ),
)
@click.option(
    "-f",
    "--filter",
    "filter_expression",
    help=(
        "Filter expression. Examples: "
        "'username=hosni', "
        "'host=web01'"
    ),
)
@click.option(
    "-e",
    "--export",
    multiple=True,
    type=click.Choice(["json", "html"], case_sensitive=False),
    help="Export the report to the specified format."
)
@click.option(
    "-o",
    "--output",
    default="analyzing_report",
    show_default=True,
    help="Output filename without extension. Used with --export."
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Show detailed execution information."
)
def analyze(
    host,
    inventory,
    user,
    exclude_localhost,
    known_hosts,
    insecure,
    filter_expression,
    export,
    output,
    verbose
):
    if insecure and known_hosts:
        raise click.UsageError(
            "--known-hosts cannot be used together "
            "with --insecure."
        )

    if insecure:
        click.secho(
            "WARNING: --insecure disables SSH host key verification. "
            "Connections are vulnerable to MITM. Use only in trusted "
            "lab environments.",
            fg="red",
            bold=True,
        )

    known_hosts = _resolve_known_hosts(
        known_hosts,
        insecure,
    )
    target_hosts = _build_target_hosts(
        hosts=host,
        inventory=inventory,
        username=user,
        exclude_localhost=exclude_localhost,
        known_hosts=known_hosts,
        insecure=insecure,
    )

    (
        trust_results,
        findings,
        failed_hosts,
        total_users,
        users_excluded,
        elapsed,
    ) = asyncio.run(
        analyze_ssh_trust(
            target_hosts,
            filter_expression,
            verbose,
        )
    )

    generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration = _format_duration(elapsed)

    report = prepare_report(
        trust_results,
        findings,
        failed_hosts,
        total_users,
        users_excluded,
        duration,
        generation_time,
    )

    print_report(report)

    if "json" in export:
        export_json(output, report)

    if "html" in export:
        export_html(
            output,
            report,

        )


if __name__ == "__main__":
    cli()
