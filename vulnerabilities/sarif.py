"""
OASIS Static Analysis Results Interchange Format (SARIF) for version 2.1.0 only.

https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif
"""

import json
import logging
import re
import textwrap

import dateutil.parser

logger = logging.getLogger(__name__)

CWE_REGEX = r"cwe-\d+$"


def parse(filehandle):
    """Parse SARIF file"""
    tree = json.load(filehandle)
    items = []
    # for each runs
    for run in tree.get("runs", []):
        # load rules
        rules = {}
        for item in run["tool"]["driver"].get("rules", []):
            rules[item["id"]] = item
        run_date = _get_last_invocation_date(run)
        for result in run.get("results", []):
            item = get_item(result, rules)
            if run_date:
                item["date"] = run_date
            items.append(item)
    return True, "parsed without errors", items


def _get_last_invocation_date(data):
    invocations = data.get("invocations", [])
    if len(invocations) == 0:
        return None
    # try to get the last 'endTimeUtc'
    raw_date = invocations[-1].get("endTimeUtc")
    if raw_date is None:
        return None
    # if the data is here we try to convert it to datetime
    return dateutil.parser.isoparse(raw_date)


def get_rule_tags(rule):
    """Get the tags from a rule"""
    if "properties" not in rule:
        return []
    if "tags" not in rule["properties"]:
        return []
    return rule["properties"]["tags"]


def get_rule_cwes(rule):
    """extract CWE from tags of a rule by regex (could be more than one"""
    cwes = []
    for tag in get_rule_tags(rule):
        matches = re.search(CWE_REGEX, tag, re.IGNORECASE)
        if matches:
            cwes.append(int(matches[0].split("-")[1]))
    return cwes


def get_severity(data):
    """Convert level value to severity"""
    if data == "warning":
        return "Medium"
    if data == "error":
        return "Critical"
    return "Info"


def get_message_from_multiformat_message(data, rule):
    """Get a message from multimessage struct"""
    if rule is not None and "id" in data:
        text = rule["messageStrings"][data["id"]].get("text")
        arguments = data.get("arguments", [])
        # argument substitution
        for i in range(6):  # the specification limit to 6
            substitution_str = "{" + str(i) + "}"
            if substitution_str in text:
                text = text.replace(substitution_str, arguments[i])
            else:
                return text
    return data.get("text")


def cve_try(val):
    """Match only the first CVE!"""
    cve_search = re.search("(CVE-[0-9]+-[0-9]+)", val, re.IGNORECASE)
    if cve_search:
        return cve_search.group(1).upper()
    return None


def get_item(result, rules):
    """Convert a resut node into a record"""
    mitigation = result.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
    references = result.get("Remediation", {}).get("Recommendation", {}).get("Url")

    # if there is a location get it
    file_path = None
    line = -1
    if "locations" in result:
        location = result["locations"][0]
        if "physicalLocation" in location:
            file_path = location["physicalLocation"]["artifactLocation"]["uri"]
            # 'region' attribute is optionnal
            if "region" in location["physicalLocation"]:
                line = location["physicalLocation"]["region"]["startLine"]

    # test rule link
    rule = rules.get(result["ruleId"])
    title = result["ruleId"]
    if "message" in result:
        description = get_message_from_multiformat_message(result["message"], rule)
        if len(description) < 150:
            title = description
    description = ""
    severity = get_severity(result.get("level", "warning"))
    if rule is not None:
        # get the severity from the rule
        if "defaultConfiguration" in rule:
            severity = get_severity(rule["defaultConfiguration"].get("level", "warning"))

        if "shortDescription" in rule:
            description = get_message_from_multiformat_message(rule["shortDescription"], rule)
        elif "fullDescription" in rule:
            description = get_message_from_multiformat_message(rule["fullDescription"], rule)
        elif "name" in rule:
            description = rule["name"]
        else:
            description = rule["id"]

    finding = {
        "title": textwrap.shorten(title, 150),
        "severity": severity,
        "description": description,
        "mitigation": mitigation,
        "references": references,
        "cve": cve_try(result["ruleId"]),
        "cwe": get_rule_cwes(rule),
        "static_finding": True,  # by definition
        "dynamic_finding": False,  # by definition
        "file_path": file_path,
        "line": line,
    }

    if "ruleId" in result:
        finding["vuln_id_from_tool"] = result["ruleId"]

    return finding
