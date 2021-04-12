import datetime

import pytest
from dateutil.tz import tzutc

from vulnerabilities.tools.semgrep.parser import SemgrepParser


class TestSemgrepParser():

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
        findings = parser.get_findings(testfile, None)
        assert 0 == len(findings)

    def test_Semgrep_parser_latest(self):
        testfile = open("tests/scans/semgrep/latest.json")
        parser = SemgrepParser()
        findings = parser.get_findings(testfile, None)
        assert findings is not None

    def test_Semgrep_parser_report1(self):
        testfile = open("tests/scans/semgrep/report1.json")
        parser = SemgrepParser()
        findings = parser.get_findings(testfile, None)
        testfile.close()
        assert 3 == len(findings)
        finding = findings[1]
        assert "Using CBC with PKCS5Padding is susceptible to padding orcale attacks" == finding['title']
        assert "Low" == finding['severity']
        assert "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02195.java" == finding['file_path']
        assert 64 == finding['line']
        assert "java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle" == finding['vuln_id_from_tool']
        assert 696 == finding['cwe']

    def test_Semgrep_parser_report2(self):
        testfile = open("tests/scans/semgrep/report2.json")
        parser = SemgrepParser()
        findings = parser.get_findings(testfile, None)
        testfile.close()
        assert 3 == len(findings)
        finding = findings[1]
        assert "Detected MD5 hash algorithm which is considered insecure" == finding['title']
        assert "Low" == finding['severity']
        assert "scripts/semgrep/payload.py" == finding['file_path']
        assert 9 == finding['line']
        assert "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5" == finding['vuln_id_from_tool']
        assert 327 == finding['cwe']

    def test_Semgrep_parser_report_error1(self):
        testfile = open("tests/scans/semgrep/report_error1.json")
        parser = SemgrepParser()
        with pytest.raises(ValueError):
            findings = parser.get_findings(testfile, None)
