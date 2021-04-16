import json
import logging

from cvss.cvss3 import CVSS3

LOGGER = logging.getLogger(__name__)


def parse(file):
    data = json.load(file)
    temp = []
    if type(data) is list:
        for tree in data:
            for vuln in tree["vulnerabilities"]:
                temp.append(get_item(vuln))
    else:
        for vuln in data["vulnerabilities"]:
            temp.append(get_item(vuln))
    return temp


def get_item(vulnerability):

    # vulnerable and unaffected versions can be in string format for a single vulnerable version,
    # or an array for multiple versions depending on the language.
    if isinstance(vulnerability["semver"]["vulnerable"], list):
        vulnerable_versions = ", ".join(vulnerability["semver"]["vulnerable"])

    # else:
    #    vulnerable_versions = vulnerability["semver"]["vulnerable"]

    if "severityWithCritical" in vulnerability:
        severity = vulnerability["severityWithCritical"].title()
    else:
        # raise ValueError("severity" + str(vulnerability))
        severity = vulnerability["severity"].title()

    references = ""
    if "id" in vulnerability:
        references = "**SNYK ID**: https://app.snyk.io/vuln/{}\n\n".format(
            vulnerability["id"]
        )

    # Append vuln references to references section
    for item in vulnerability.get("references", []):
        references += "**" + item["title"] + "**: " + item["url"] + "\n"

    # create the finding object
    finding = {
        "title": vulnerability["from"][0] + ": " + vulnerability["title"],
        "severity": severity,
        "severity_justification": "Issue severity of: **"
        + severity
        + "** from a base "
        + "CVSS score of: **"
        + str(vulnerability.get("cvssScore"))
        + "**",
        "description": "## Component Details\n - **Vulnerable Package**: "
        + vulnerability["packageName"]
        + "\n- **Current Version**: "
        + str(vulnerability["version"])
        + "\n- **Vulnerable Version(s)**: "
        + vulnerable_versions
        + "\n- **Vulnerable Path**: "
        + " > ".join(vulnerability["from"])
        + "\n"
        + vulnerability["description"],
        "mitigation": "A fix (if available) will be provided in the description.",
        "references": references,
        "component_name": vulnerability["packageName"],
        "component_version": vulnerability["version"],
        "static_finding": True,
        "dynamic_finding": False,
        "vuln_id_from_tool": vulnerability["id"],
    }

    if "packageManager" in vulnerability:
        finding["component_vendor"] = vulnerability["packageManager"]

    # CVSSv3 vector
    if "CVSSv3" in vulnerability:
        finding["cvssv3"] = CVSS3(vulnerability["CVSSv3"]).clean_vector()

    # manage CVE and CWE with idnitifiers
    if "identifiers" in vulnerability:
        if "CVE" in vulnerability["identifiers"]:
            finding["cves"] = vulnerability["identifiers"]["CVE"]

        if "CWE" in vulnerability["identifiers"]:
            finding["cwes"] = []
            cwes = vulnerability["identifiers"]["CWE"]
            for cve in cwes:
                # Per the current json format, if several CWEs, take the first one.
                finding["cwes"].append(int(cve.split("-")[1]))

    # Find remediation string limit indexes
    remediation_index = finding["description"].find("## Remediation")
    references_index = finding["description"].find("## References")

    # Add the remediation substring to mitigation section
    if (remediation_index != -1) and (references_index != -1):
        finding["mitigation"] = finding["description"][
            remediation_index:references_index
        ]

    return finding
