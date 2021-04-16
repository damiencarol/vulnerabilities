import json


def parse(file):
    data = json.load(file)
    try:
        res = list(parse_internal(data))
    except ValueError as exc:
        return False, str(exc), None
    return True, "parsed with success", res


def parse_internal(data):

    for item in data["results"]:

        finding = {
            "title": item["check_id"],
            "description": item["extra"]["message"],
            "severity": convert_severity(item["extra"]["severity"]),
            "file_path": item["path"],
            "line": item["start"]["line"],
            "static_finding": True,
            "dynamic_finding": False,
            "vuln_id_from_tool": item["check_id"],
        }

        # manage CWE
        if "cwe" in item["extra"]["metadata"]:
            finding["cwe"] = int(
                item["extra"]["metadata"].get("cwe").partition(":")[0].partition("-")[2]
            )

        # manage references from metadata
        if "references" in item["extra"]["metadata"]:
            finding["references"] = item["extra"]["metadata"]["references"]

        # manage mitigation from metadata
        if "fix" in item["extra"]:
            finding["mitigation"] = item["extra"]["fix"]
        elif "fix_regex" in item["extra"]:
            finding["mitigation"] = "\n".join(
                [
                    "**You can automaticaly apply this regex:**",
                    "\n```\n",
                    json.dumps(item["extra"]["fix_regex"]),
                    "\n```\n",
                ]
            )

        yield finding


def convert_severity(val):
    if "WARNING" == val.upper():
        return "Low"
    elif "ERROR" == val.upper():
        return "High"
    else:
        raise ValueError(f"Unknown value for severity: {val}")
