import json


class SemgrepParser(object):
    def get_scan_types(self):
        return ["SEMGREP"]

    def get_label_for_scan_types(self, scan_type):
        return "Semgrep Scan"

    def get_description_for_scan_types(self, scan_type):
        return "JSON report format (--json option)"

    def get_findings(self, filename, test):
        data = json.load(filename)

        dupes = dict()

        for item in data["results"]:

            find = {
                "title": item["extra"]["message"].rsplit(".")[0] + ".",
                "description": item["extra"]["message"],
                "severity": self.convert_severity(item["extra"]["severity"]),
                "references": item["extra"]["metadata"]["references"],
                "file_path": item["path"],
                "line": item["start"]["line"],
                "static_finding": True,
                "dynamic_finding": False,
                "vuln_id_from_tool": ":".join(
                    [
                        item["check_id"],
                    ]
                ),
            }

            dupe_key = find["title"] + find["file_path"] + str(find["line"])

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = find

        return list(dupes.values())

    def convert_severity(self, val):
        if "WARNING" == val.upper():
            return "Low"
        elif "ERROR" == val.upper():
            return "High"
        else:
            raise ValueError(f"Unknown value for severity: {val}")
