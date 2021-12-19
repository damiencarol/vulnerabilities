import datetime

import pytest
from dateutil.tz import tzutc

from vulnerabilities.sarif import parse
from utils import check_finding


class TestSarif:

    def test_sarif_appendix_k(self):
        testfile = open("tests/scans/sarif/appendix_k.sarif")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        assert 1 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "Critical" == finding["severity"]
        assert "collections/list.h" == finding["file_path"]
        assert 15 == finding["line"]
        assert "C2001" == finding["vuln_id_from_tool"]
        assert [] == finding["cwe"]

    def test_sarif_appendix_empty_invoc(self):
        testfile = open("tests/scans/sarif/appendix_empty_invoc.sarif")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        assert 0 == len(findings)

    # def test_sarif_appendix_k1(self):
    #     testfile = open("tests/scans/sarif/appendix_k1.sarif")
    #     success, message, findings = parse(testfile)
    #     findings = list(findings)
    #     assert success
    #     assert 1 == len(findings)

    # def test_Semgrep_parser_latest(self):
    #     testfile = open("tests/scans/semgrep/latest.json")
    #     success, message, findings = parse(testfile)
    #     findings = list(findings)
    #     assert success
    #     assert findings is not None
    #     for finding in findings:
    #         check_finding(finding)

    # def test_Semgrep_parser_report1(self):
    #     testfile = open("tests/scans/semgrep/report1.json")
    #     success, message, findings = parse(testfile)
    #     findings = list(findings)
    #     assert success
    #     assert 3 == len(findings)
    #     for finding in findings:
    #         check_finding(finding)
    #     finding = findings[1]
    #     assert "Low" == finding["severity"]
    #     assert "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02195.java" == finding["file_path"]
    #     assert 64 == finding["line"]
    #     assert "java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle" == finding["vuln_id_from_tool"]
    #     assert 696 == finding["cwe"]

    # def test_Semgrep_parser_report2(self):
    #     testfile = open("tests/scans/semgrep/report2.json")
    #     success, message, findings = parse(testfile)
    #     findings = list(findings)
    #     assert success
    #     assert 4 == len(findings)
    #     for finding in findings:
    #         check_finding(finding)
    #     finding = findings[1]
    #     assert "Low" == finding["severity"]
    #     assert "scripts/semgrep/payload.py" == finding["file_path"]
    #     assert 9 == finding["line"]
    #     assert (
    #         "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5" == finding["vuln_id_from_tool"]
    #     )
    #     assert 327 == finding["cwe"]

    # def test_Semgrep_parser_report_error1(self):
    #     testfile = open("tests/scans/semgrep/report_error1.json")
    #     success, message, findings = parse(testfile)
    #     assert not success
    #     assert "Unknown value for severity: error_value" == message

    # def test_Semgrep_parser_report3(self):
    #     testfile = open("tests/scans/semgrep/report3.json")
    #     success, message, findings = parse(testfile)
    #     findings = list(findings)
    #     assert success
    #     testfile.close()
    #     assert 48 == len(findings)
    #     for finding in findings:
    #         check_finding(finding)
    #     finding = findings[0]
    #     assert "High" == finding["severity"]
    #     assert "tasks.py" == finding["file_path"]
    #     assert 186 == finding["line"]
    #     finding = findings[1]
    #     assert "High" == finding["severity"]
    #     assert "finding/views.py" == finding["file_path"]
    #     assert 2047 == finding["line"]
    #     assert "python.lang.correctness.useless-eqeq.useless-eqeq" == finding["vuln_id_from_tool"]
    #     finding = findings[4]
    #     assert "Low" == finding["severity"]
    #     assert "tools/sslyze/parser_xml.py" == finding["file_path"]
    #     assert 124 == finding["line"]
    #     assert 327 == finding["cwe"]
    #     assert (
    #         "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5" == finding["vuln_id_from_tool"]
    #     )
    #     finding = findings[37]
    #     assert "High" == finding["severity"]
    #     assert "management/commands/csv_findings_export.py" == finding["file_path"]
    #     assert 33 == finding["line"]
    #     assert 1236 == finding["cwe"]
    #     assert "python.lang.security.unquoted-csv-writer.unquoted-csv-writer" == finding["vuln_id_from_tool"]

    # def test_Semgrep_parser_report_remediation1(self):
    #     testfile = open("tests/scans/semgrep/report_remediation1.json")
    #     success, message, findings = parse(testfile)
    #     findings = list(findings)
    #     assert success
    #     testfile.close()
    #     assert 4 == len(findings)
    #     for finding in findings:
    #         check_finding(finding)
    #     finding = findings[0]
    #     assert "Low" == finding["severity"]
    #     assert "tests/payload/payload.py" == finding["file_path"]
    #     assert 5 == finding["line"]
    #     # check one finding which have remediation data
    #     finding = findings[3]
    #     assert "High" == finding["severity"]
    #     assert "tests/payload/payload.py" == finding["file_path"]
    #     assert 1 == finding["line"]
    #     assert "mitigation" in finding
    #     assert finding["mitigation"] is not None

    def test_sarif_flawfinder(self):
        testfile = open("tests/scans/sarif/flawfinder.sarif")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        assert 54 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "Critical" == finding["severity"]
        assert "src/tree/param.cc" == finding["file_path"]
        assert 29 == finding["line"]
        assert "FF1048" == finding["vuln_id_from_tool"]
        assert 327 in finding["cwe"]

    def test_sarif_njsscan(self):
        testfile = open("tests/scans/sarif/njsscan.sarif")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        assert 2 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "Medium" == finding["severity"]
        assert "file:///src/index.js" == finding["file_path"]
        assert 321 == finding["line"]
        assert "node_insecure_random_generator" == finding["vuln_id_from_tool"]
        assert [] == finding["cwe"]

    def test_sarif_spotbugs(self):
        testfile = open("tests/scans/sarif/spotbugs.sarif")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        assert 56 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "Info" == finding["severity"]
        assert "Boot.java" == finding["file_path"]
        assert 23 == finding["line"]
        assert "DMI_HARDCODED_ABSOLUTE_FILENAME" == finding["vuln_id_from_tool"]
        assert [] == finding["cwe"]

    def test_sarif_dependencycheck(self):
        testfile = open("tests/scans/sarif/dependency_check.sarif")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        assert 13 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "Critical" == finding["severity"]
        assert "file:////src/.venv/lib/python3.9/site-packages/tastypie_swagger/static/tastypie_swagger/js/lib/handlebars-1.0.0.js" == finding["file_path"]
        assert -1 == finding["line"]
        assert "Disallow calling helperMissing and blockHelperMissing directly" == finding["vuln_id_from_tool"]
        assert [] == finding["cwe"]
        finding = findings[12]
        assert "Critical" == finding["severity"]
        assert "file:////src/.venv/lib/python3.9/site-packages/coverage/htmlfiles/jquery.min.js" == finding["file_path"]
        assert -1 == finding["line"]
        assert "CVE-2020-11023" == finding["vuln_id_from_tool"]
        assert [] == finding["cwe"]
        assert "CVE-2020-11023" == finding["cve"]
