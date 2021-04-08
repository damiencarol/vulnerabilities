import datetime
from vulnerabilities.tools.bandit.parser import BanditParser


class TestBanditParser():

    def test_bandit_parser_has_no_finding(self):
        testfile = open("tests/scans/bandit/empty.json")
        parser = BanditParser()
        findings = parser.get_findings(testfile, None)
        assert 0 == len(findings)

    def test_bandit_parser_latest(self):
        testfile = open("tests/scans/bandit/latest.json")
        parser = BanditParser()
        findings = parser.get_findings(testfile, None)
        assert findings is not None

    def test_bandit_parser_latest(self):
        testfile = open("tests/scans/bandit/report1.json")
        parser = BanditParser()
        findings = parser.get_findings(testfile, None)
        testfile.close()
        assert 1 == len(findings)
        finding = findings[0]
        assert "Medium" == finding['severity']
        assert datetime.datetime(2021, 4, 8, 12, 32, 49) == finding['date']  # "2021-04-08T12:32:49Z"
        assert "scripts/bandit/payload.py" == finding['file_path']
        assert 5 == finding['line']
