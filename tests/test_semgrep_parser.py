import datetime

import pytest
from dateutil.tz import tzutc

from vulnerabilities.tools.semgrep.parser import parse
from utils import check_finding


class TestSemgrepParser:

    def test_Semgrep_parser_has_no_finding(self):
        testfile = open("tests/scans/semgrep/empty.json")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        assert 0 == len(findings)

    def test_Semgrep_parser_latest(self):
        testfile = open("tests/scans/semgrep/latest.json")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        assert findings is not None
        for finding in findings:
            check_finding(finding)

    def test_Semgrep_parser_report1(self):
        testfile = open("tests/scans/semgrep/report1.json")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        assert 3 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[1]
        assert "Low" == finding["severity"]
        assert "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02195.java" == finding["file_path"]
        assert 64 == finding["line"]
        assert "java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle" == finding["vuln_id_from_tool"]
        assert 696 == finding["cwe"]

    def test_Semgrep_parser_report2(self):
        testfile = open("tests/scans/semgrep/report2.json")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        assert 4 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[1]
        assert "Low" == finding["severity"]
        assert "scripts/semgrep/payload.py" == finding["file_path"]
        assert 9 == finding["line"]
        assert (
            "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5" == finding["vuln_id_from_tool"]
        )
        assert 327 == finding["cwe"]

    def test_Semgrep_parser_report_error1(self):
        testfile = open("tests/scans/semgrep/report_error1.json")
        success, message, findings = parse(testfile)
        assert not success
        assert "Unknown value for severity: error_value" == message

    def test_Semgrep_parser_report3(self):
        testfile = open("tests/scans/semgrep/report3.json")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        testfile.close()
        assert 48 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "High" == finding["severity"]
        assert "tasks.py" == finding["file_path"]
        assert 186 == finding["line"]
        finding = findings[1]
        assert "High" == finding["severity"]
        assert "finding/views.py" == finding["file_path"]
        assert 2047 == finding["line"]
        assert "python.lang.correctness.useless-eqeq.useless-eqeq" == finding["vuln_id_from_tool"]
        finding = findings[4]
        assert "Low" == finding["severity"]
        assert "tools/sslyze/parser_xml.py" == finding["file_path"]
        assert 124 == finding["line"]
        assert 327 == finding["cwe"]
        assert (
            "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5" == finding["vuln_id_from_tool"]
        )
        finding = findings[37]
        assert "High" == finding["severity"]
        assert "management/commands/csv_findings_export.py" == finding["file_path"]
        assert 33 == finding["line"]
        assert 1236 == finding["cwe"]
        assert "python.lang.security.unquoted-csv-writer.unquoted-csv-writer" == finding["vuln_id_from_tool"]

    def test_Semgrep_parser_report_remediation1(self):
        testfile = open("tests/scans/semgrep/report_remediation1.json")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        testfile.close()
        assert 4 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "Low" == finding["severity"]
        assert "tests/payload/payload.py" == finding["file_path"]
        assert 5 == finding["line"]
        # check one finding which have remediation data
        finding = findings[3]
        assert "High" == finding["severity"]
        assert "tests/payload/payload.py" == finding["file_path"]
        assert 1 == finding["line"]
        assert "mitigation" in finding
        assert finding["mitigation"] is not None
