from html import escape

from utils.logger import logger


def export_html(output: str, report: dict):
    """Export a STAyzer report to an HTML file."""

    if not output.endswith(".html"):
        output += ".html"

    scan = report["scan"]
    hosts = report["hosts"]
    findings = report["findings"]
    statistics = report["statistics"]

    html = f"""<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>STAyzer SSH Trust Analysis Report</title>

<style>

body {{
    font-family: monospace;
    color: #000;
    background: #fff;
    margin: 20px;
}}

.container {{
    max-width: 1200px;
    margin: auto;
}}

h1 {{
    font-size: 20px;
    font-weight: bold;
    margin: 0 0 5px 0;
}}

h2 {{
    font-size: 16px;
    font-weight: bold;
    margin: 25px 0 10px 0;
}}

h3 {{
    font-size: 14px;
    margin: 15px 0 8px 0;
}}

.subtitle {{
    color: #444;
    margin-bottom: 20px;
    font-size: 13px;
}}

.summary {{
    margin: 20px 0;
    border: 1px solid #000;
    padding: 12px;
}}

.summary-item {{
    display: inline-block;
    margin-right: 30px;
    margin-bottom: 5px;
    width:10rem;
}}

.summary-item strong {{
    font-weight: bold;
}}

.section {{
    margin-top: 30px;
}}

.host {{
    margin-top: 25px;
    border-top: 1px solid #ccc;
    padding-top: 15px;
}}

.user {{
    margin: 15px 0;
    padding: 10px;
    border-left: 3px solid #000;
}}

.user-header {{
    font-weight: bold;
    margin-bottom: 8px;
}}

.failed {{
    margin: 10px 0;
    padding: 10px;
    border-left: 3px solid #cc003a;
    background-color: #cc003a10;

}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
    font-size: 13px;
}}

th {{
    background: #000;
    color: #fff;
    padding: 7px 8px;
    text-align: left;
    font-weight: bold;
}}

td {{
    padding: 6px 8px;
    border-bottom: 1px solid #ddd;
    vertical-align: top;
}}

tr:hover {{
    background: #f0f0f0;
}}

.finding {{
    border: 1px solid #cc6600;
    background: #fff8e6;
    padding: 12px;
    margin: 12px 0;
}}

.finding-title {{
    font-weight: bold;
    color: #cc6600;
    margin-bottom: 8px;
}}

.finding-label {{
    font-weight: bold;
}}

.no-findings {{
    border: 1px solid #00aa00;
    padding: 12px;
    color: #00aa00;
    background-color: #00aa0010;
}}

.failed-hosts {{
    border: 1px solid #cc6600;
    padding: 12px;
    padding-block: 24px;
    color: #cc6600;
    background-color: #cc660010;
}}

.healthy {{
    color: #00aa00;
    font-weight: bold;
}}

.attention {{
    color: #cc6600;
    font-weight: bold;
}}

.incomplete {{
    color: #cc003a;
    font-weight: bold;
}}

.footer {{
    margin-top: 40px;
    border-top: 1px solid #000;
    padding-top: 15px;
    font-size: 13px;
}}
a {{
    text-decoration: none;
    color: inherit;
}}
</style>

</head>

<body>

<div class="container">

<h1>STAyzer - SSH Trust Analysis Report</h1>

<p class="subtitle">
Generated: {escape(str(scan["generated_on"]))}
|
Duration: {scan["duration"]}
</p>

<div class="summary">

<span class="summary-item">
<strong>Hosts Scanned:</strong>
{statistics["total_hosts"]}
</span>
<span class="summary-item">
<strong>Successful Hosts:</strong>
{statistics["successful_hosts"]}
</span>

<span class="summary-item">
<strong>Failed Hosts:</strong>
{statistics["failed_hosts"]}
</span>

</div>

<div class="summary">

<span class="summary-item">
<strong>Users Found:</strong>
{statistics["total_users"]}
</span>

<span class="summary-item">
<strong>Users Audited:</strong>
{scan["users_audited"]}
</span>

<span class="summary-item">
<strong>Users Excluded:</strong>
{
        ",".join(scan["users_excluded"]) if scan["users_excluded"] else "None"}
</span>

</div>

<div class="summary">

<span class="summary-item">
<strong>SSH Keys:</strong>
{statistics["total_keys"]}
</span>

<span class="summary-item">
<strong>Shared Keys:</strong>
{statistics["duplicate_keys"]}
</span>

<span class="summary-item">
<strong>Findings:</strong>
{statistics["total_findings"]}
</span>

</div>

"""

    # Findings

    html += """
<div class="section">

<h2>Security Findings</h2>
"""

    if not findings and not report["failed_hosts"]:

        html += """
<div class="no-findings">
    <strong>No SSH trust issues were detected.</strong><br>
    All successfully scanned hosts appear to have healthy SSH trust relationships.
</div>
"""
    if not findings and report["failed_hosts"]:

        html += """
<div class="failed-hosts">
    <strong>No SSH trust issues were detected on the successfully scanned hosts.</strong><br>
    <p>Some hosts could not be analyzed. Review the <a href="#failed-hosts"><strong>Failed Hosts</strong></a> section to ensure no issues were missed.</p>
</div>
"""
    else:

        for finding in findings:

            finding_type = finding.get("type")

            if finding_type == "duplicate_key":

                fingerprint = escape(
                    str(finding.get("fingerprint", "Unknown"))
                )

                occurrences = finding.get(
                    "occurrences",
                    len(finding.get("locations", [])),
                )
                category: str = finding.get("category", "unknown")
                severity = finding.get("severity", "unknown")

                html += f"""
<div class="finding">

<div class="finding-title">
Shared SSH Key Detected [{severity.upper()}]<br/>
({occurrences} occurrences)<br/>
- {category.replace("_", " ").title()}
</div>

<p>
<span class="finding-label">Fingerprint:</span>
{fingerprint}
</p>

<p class="finding-label">
Locations:
</p>

<table>

<tr>
    <th>Host</th>
    <th>User</th>
    <th>Comment</th>
</tr>
"""

                for location in finding.get("locations", []):

                    hostname = escape(
                        str(location.get("hostname", "Unknown"))
                    )

                    username = escape(
                        str(location.get("username", "Unknown"))
                    )

                    comment = escape(
                        str(location.get("comment", ""))
                    )

                    html += f"""
<tr>
    <td>{hostname}</td>
    <td>{username}</td>
    <td>{comment}</td>
</tr>
"""

                html += """
</table>

</div>
"""

            else:

                html += f"""
<div class="finding">

<div class="finding-title">
{escape(str(finding_type))}
</div>

<pre>{escape(str(finding))}</pre>

</div>
"""

    html += """
</div>
"""

    # Hosts

    html += """
<div class="section">

<h2>SSH Trust Inventory</h2>
"""

    if not hosts:

        html += """
<p>No hosts were successfully analyzed.</p>
"""

    for host in hosts:

        hostname = escape(str(host["hostname"]))

        html += f"""
<div class="host">

<h2>
{hostname}
({len(host["users"])} users with SSH keys)
</h2>
"""

        if not host["users"]:

            html += """
<p>No SSH authorized keys discovered.</p>
"""

        for user in host["users"]:

            username = escape(str(user["username"]))

            html += f"""
<div class="user">

<div class="user-header">
User: {username}
</div>

<div>
UID: {user["uid"]}
|
SSH Keys: {len(user["ssh_keys"])}
</div>
"""

            if user["ssh_keys"]:

                html += """
<table>

<tr>
    <th>#</th>
    <th>Type</th>
    <th>Fingerprint</th>
    <th>Comment</th>
</tr>
"""

                for index, key in enumerate(
                    user["ssh_keys"],
                ):

                    key_type = escape(
                        str(key["type"])
                    )

                    fingerprint = escape(
                        str(key["fingerprint"])
                    )

                    comment = escape(
                        str(key["comment"] or "")
                    )

                    html += f"""
<tr>
    <td>{index+1}</td>
    <td>{key_type}</td>
    <td>{fingerprint}</td>
    <td>{comment}</td>
</tr>
"""

                html += """
</table>
"""

            html += """
</div>
"""

        html += """
</div>
"""

    html += """
</div>
<div class="section" id="failed-hosts">
<h2>Failed Hosts: </h2>
"""
    if report["failed_hosts"]:
        for host in report["failed_hosts"]:
            html += f"""
            <div class="failed">
                <p class="incomplete">Host: {escape(
                str(host.get("hostname", "Unknown"))
            )}:</p>
                <p class="attention">...Error : {escape(
                str(host.get("error", "Unknown"))
            )}</p>
                <p class="attention">...Reason: {escape(
                str(host.get("reason", "Unknown"))
            )}</p>
            </div>  
"""
    else:
        html += "<p class='no-findings'>Status: All hosts passed</p>"
    # Final summary

    if report["failed_hosts"]:

        overall_result = "INCOMPLETE"
        overall_class = "incomplete"

    elif findings:

        overall_result = "ATTENTION REQUIRED"
        overall_class = "attention"

    else:

        overall_result = "HEALTHY"
        overall_class = "healthy"

    html += f"""
    </div>
<p class="overall {overall_class}">
Overall Status: {overall_result}
</p>

<p>
Generated by STAyzer - SSH Trust Analyzer
</p>

</div>

</div>

</body>
</html>
"""

    with open(output, "w", encoding="utf-8") as file:
        file.write(html)

    logger.success(
        f"HTML report written to '{output}'"
    )
