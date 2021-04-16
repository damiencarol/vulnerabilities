import datetime

import pytest
from dateutil.tz import tzutc, tzoffset

from vulnerabilities.tools.cyclonedx.parser import parse
from utils import check_finding

class TestCyclonedxParser:
    def test_parse_grype(self):
        """Output of Anchore Grype"""
        testfile = open("tests/scans/cyclonedx/grype.latest.xml")
        findings = parse(testfile)
        assert type(findings) is list
        for finding in findings:
            check_finding(finding)

    def test_Cyclonedx_parser_report1(self):
        testfile = open("tests/scans/cyclonedx/spec1.xml")
        findings = list(parse(testfile))
        assert 2 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "Info" == finding["severity"]
        assert "com.fasterxml.jackson.core" == finding["component_vendor"]
        assert "jackson-databind" == finding["component_name"]
        assert "2.9.9" == finding["component_version"]
        finding = findings[1]
        assert "Critical" == finding["severity"]
        assert "com.fasterxml.jackson.core" == finding["component_vendor"]
        assert "jackson-databind" == finding["component_name"]
        assert "2.9.9" == finding["component_version"]
        assert 184 in finding["cwe"]
        assert 502 in finding["cwe"]
        assert "CVE-2018-7489" == finding["vuln_id_from_tool"]

    def test_Cyclonedx_parser_grype2(self):
        testfile = open("tests/scans/cyclonedx/grype_dd_1_14_1.xml")
        findings = list(parse(testfile))
        assert 619 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "Info" == finding["severity"]
        assert "Deprecated" == finding["component_name"]
        assert "1.2.12" == finding["component_version"]
        finding = findings[346]
        assert "Low" == finding["severity"]
        assert "libldap-2.4-2" == finding["component_name"]
        assert "2.4.47+dfsg-3+deb10u6" == finding["component_version"]
        assert "CVE-2017-17740" == finding["vuln_id_from_tool"]

    def test_Cyclonedx_parser_report_date(self):
        testfile = open("tests/scans/cyclonedx/report_date.xml")
        findings = list(parse(testfile))
        assert 2 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "date" in finding
        assert datetime.datetime(2009, 10, 10, 12, 0, tzinfo=tzoffset(None, -18000)) == finding["date"]

    def test_Cyclonedx_parser_report_date(self):
        testfile = open("tests/scans/cyclonedx/report_severity_none.xml")
        findings = list(parse(testfile))
        assert 2 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[1]
        assert "severity" in finding
        assert finding["severity"] is None

    def test_Cyclonedx_parse_report_error1(self):
        testfile = open("tests/scans/cyclonedx/report_error1.xml")
        with pytest.raises(ValueError):
            findings = list(parse(testfile))
