import json

from utils.logger import logger


def export_json(output: str, report: dict):
    """Export a STAyzer report to a JSON file."""

    if not output.endswith(".json"):
        output += ".json"

    with open(output, "w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            default=str,
        )

    logger.success(
        f"JSON report written to '{output}'"
    )
