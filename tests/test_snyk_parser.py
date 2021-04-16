import datetime

import pytest
from dateutil.tz import tzutc, tzoffset

from vulnerabilities.tools.snyk.parser import parse
from utils import check_finding


class TestSnykParser:

    def test_Snyk_parser_report1(self):
        testfile = open("tests/scans/snyk/all_projects_issue4277.json")
        findings = list(parse(testfile))
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
        findings = list(parse(testfile))
        assert 62 == len(findings)
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
        findings = list(parse(testfile))
        assert 41 == len(findings)
        finding = findings[0]
        assert "Medium" == finding["severity"]
        assert "maven" == finding["component_vendor"]
        assert "com.beust:jcommander" == finding["component_name"]
        assert "1.72" == finding["component_version"]
        assert 494 in finding["cwes"]
        assert 829 in finding["cwes"]
        assert "SNYK-JAVA-COMBEUST-174815" == finding["vuln_id_from_tool"]
