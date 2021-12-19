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

    def test_sarif_appendix_untracked(self):
        testfile = open("tests/scans/sarif/appendix_untracked.sarif")
        success, message, findings = parse(testfile)
        findings = list(findings)
        assert success
        assert 2 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "Medium" == finding["severity"]
        assert "CA1001" == finding["vuln_id_from_tool"]
        assert [] == finding["cwe"]

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
