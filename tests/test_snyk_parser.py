import datetime

import pytest
from dateutil.tz import tzutc, tzoffset

from vulnerabilities.tools.snyk.parser import parse
from utils import check_finding


class TestSnykParser:

    def test_Snyk_parser_empty(self):
        """empty report"""
        testfile = open("tests/scans/snyk/empty.json")
        success, message, findings = list(parse(testfile))
        assert success
        assert 0 == len(findings)

    def test_Snyk_parser_report1(self):
        testfile = open("tests/scans/snyk/all_projects_issue4277.json")
        success, message, findings = list(parse(testfile))
        assert success
        assert 82 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "High" == finding["severity"]
        assert "nuget" == finding["component_vendor"]
        assert "Microsoft.AspNetCore" == finding["component_name"]
        assert "2.2.0" == finding["component_version"]
        assert 200 in finding["cwes"]
        assert "SNYK-DOTNET-MICROSOFTASPNETCORE-174184" == finding["vuln_id_from_tool"]
        finding = findings[1]
        assert "Medium" == finding["severity"]
        assert "nuget" == finding["component_vendor"]
        assert "Microsoft.AspNetCore.App" == finding["component_name"]
        assert "2.2.0" == finding["component_version"]
        assert 400 in finding["cwes"]
        assert "SNYK-DOTNET-MICROSOFTASPNETCOREAPP-72896" == finding["vuln_id_from_tool"]
        finding = findings[40]
        assert "High" == finding["severity"]
        assert "npm" == finding["component_vendor"]
        assert "lodash" == finding["component_name"]
        assert "4.17.11" == finding["component_version"]
        assert 78 in finding["cwes"]
        assert "SNYK-JS-LODASH-1040724" == finding["vuln_id_from_tool"]

    def test_Snyk_parser_dd(self):
        """Recent version of Snyk (2021-04-15)"""
        testfile = open("tests/scans/snyk/all_projects_dd.json")
        success, message, findings = list(parse(testfile))
        assert success
        assert 62 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "High" == finding["severity"]
        assert "pip" == finding["component_vendor"]
        assert "cryptography" == finding["component_name"]
        assert "3.4.6" == finding["component_version"]
        assert 208 in finding["cwes"]
        assert "SNYK-PYTHON-CRYPTOGRAPHY-1022152" == finding["vuln_id_from_tool"]
        finding = findings[1]
        assert "High" == finding["severity"]
        assert "pip" == finding["component_vendor"]
        assert "cryptography" == finding["component_name"]
        assert "3.4.6" == finding["component_version"]
        assert 208 in finding["cwes"]
        assert "SNYK-PYTHON-CRYPTOGRAPHY-1022152" == finding["vuln_id_from_tool"]
        finding = findings[50]
        assert "Medium" == finding["severity"]
        assert "pip" == finding["component_vendor"]
        assert "jinja2" == finding["component_name"]
        assert "2.11.1" == finding["component_version"]
        assert 400 in finding["cwes"]
        assert "SNYK-PYTHON-JINJA2-1012994" == finding["vuln_id_from_tool"]

    def test_Snyk_parser_one_project(self):
        """Report that have only one project"""
        testfile = open("tests/scans/snyk/single_project_many_vulns.json")
        success, message, findings = list(parse(testfile))
        assert success
        assert 41 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "Medium" == finding["severity"]
        assert "maven" == finding["component_vendor"]
        assert "com.beust:jcommander" == finding["component_name"]
        assert "1.72" == finding["component_version"]
        assert 494 in finding["cwes"]
        assert 829 in finding["cwes"]
        assert "SNYK-JAVA-COMBEUST-174815" == finding["vuln_id_from_tool"]

    def test_Snyk_parser_ko(self):
        """Report that is generated when Snyk failed"""
        testfile = open("tests/scans/snyk/report_ko1.json")
        success, message, findings = list(parse(testfile))
        assert not success  # error with Snyk

    def test_Snyk_parser_new_data(self):
        """"""
        testfile = open("tests/scans/snyk/KULwF8Hx.json")
        success, message, findings = list(parse(testfile))
        assert success
        assert 3 == len(findings)
        for finding in findings:
            check_finding(finding)
        finding = findings[0]
        assert "High" == finding["severity"]
        assert "sles:15.3" == finding["component_vendor"]
        assert "p11-kit-tools" == finding["component_name"]
        assert "0.23.2-4.8.3" == finding["component_version"]
        assert "SNYK-SLES153-P11KITTOOLS-2650307" == finding["vuln_id_from_tool"]
        finding = findings[1]
        assert "Low" == finding["severity"]
        assert "sles:15.3" == finding["component_vendor"]
        assert "permissions" == finding["component_name"]
        assert "20181225-23.6.1" == finding["component_version"]
        assert "SNYK-SLES153-PERMISSIONS-2648113" == finding["vuln_id_from_tool"]
