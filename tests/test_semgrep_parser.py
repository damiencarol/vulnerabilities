import datetime

import pytest
from dateutil.tz import tzutc

from vulnerabilities.tools.semgrep.parser import SemgrepParser
from utils import check_finding


class TestSemgrepParser:
    def test_Semgrep_parser_get_scan_types(self):
        parser = SemgrepParser()
        assert "SEMGREP" in parser.get_scan_types()

    def test_Semgrep_parser_get_label_for_scan_types(self):
        parser = SemgrepParser()
        assert "Semgrep Scan" == parser.get_label_for_scan_types("Semgrep")

    def test_Semgrep_parser_get_description_for_scan_types(self):
        parser = SemgrepParser()
        assert parser.get_description_for_scan_types("Semgrep") is not None

    def test_Semgrep_parser_has_no_finding(self):
        testfile = open("tests/scans/semgrep/empty.json")
        parser = SemgrepParser()
        findings = list(parser.get_findings(testfile, None))
        assert 0 == len(findings)

    def test_Semgrep_parser_latest(self):
        testfile = open("tests/scans/semgrep/latest.json")
        parser = SemgrepParser()
        findings = parser.get_findings(testfile, None)
        assert findings is not None
        for finding in findings:
            check_finding(finding)

    def test_Semgrep_parser_report1(self):
        testfile = open("tests/scans/semgrep/report1.json")
        parser = SemgrepParser()
        findings = list(parser.get_findings(testfile, None))
        testfile.close()
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
        parser = SemgrepParser()
        findings = list(parser.get_findings(testfile, None))
        testfile.close()
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
        parser = SemgrepParser()
        with pytest.raises(ValueError):
            findings = list(parser.get_findings(testfile, None))

    def test_Semgrep_parser_report3(self):
        testfile = open("tests/scans/semgrep/report3.json")
        parser = SemgrepParser()
        findings = list(parser.get_findings(testfile, None))
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
