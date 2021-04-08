import datetime
from dateutil.tz import tzutc
from vulnerabilities.tools.bandit.parser import BanditParser


class TestBanditParser():

    def test_bandit_parser_get_scan_types(self):
        parser = BanditParser()
        assert "BANDIT" in parser.get_scan_types()

    def test_bandit_parser_get_label_for_scan_types(self):
        parser = BanditParser()
        assert "Bandit Scan" == parser.get_label_for_scan_types("BANDIT")

    def test_bandit_parser_get_description_for_scan_types(self):
        parser = BanditParser()
        assert parser.get_description_for_scan_types("BANDIT") is not None

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
        assert 4 == len(findings)
        finding = findings[1]
        assert "Use of insecure MD2, MD4, MD5, or SHA1 hash function." == finding['title']
        assert "Medium" == finding['severity']
        assert datetime.datetime(2021, 4, 8, 16, 18, 11, tzinfo=tzutc()) == finding['date']  # "2021-04-08T12:32:49Z"
        assert "scripts/bandit/payload.py" == finding['file_path']
        assert 5 == finding['line']
        assert "blacklist:B303" == finding['vuln_id_from_tool']
