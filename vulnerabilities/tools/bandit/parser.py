import json

import dateutil.parser


class BanditParser(object):
    def get_scan_types(self):
        return ["BANDIT"]

    def get_label_for_scan_types(self, scan_type):
        return "Bandit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "JSON report format"

    def get_findings(self, filename, test):
        data = json.load(filename)

        dupes = dict()
        if "generated_at" in data:
            find_date = dateutil.parser.parse(data["generated_at"])

        for item in data["results"]:

            findingdetail = "Filename: `" + item["filename"] + "`\n"
            findingdetail += "Line number: `" + str(item["line_number"]) + "`\n"
            findingdetail += "Issue Confidence: `" + item["issue_confidence"] + "`\n\n"
            findingdetail += "Code:\n"
            findingdetail += item["code"] + "\n"

            references = item["test_id"]

            find = {
                "title": item["issue_text"],
                "description": findingdetail,
                "severity": item["issue_severity"].title(),
                "references": references,
                "file_path": item["filename"],
                "line": item["line_number"],
                "date": find_date,
                "static_finding": True,
                "dynamic_finding": False,
                "vuln_id_from_tool": ":".join([item["test_name"], item["test_id"]]),
            }

            dupe_key = find["title"] + item["filename"] + str(item["line_number"])

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = find

        return list(dupes.values())
