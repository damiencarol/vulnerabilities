

def check_finding(finding):
    """This function test the contract that every finding needs to follow
    
    Each findings needs to have this attribute:
    * severity (<None>, "Info", "Low", "Medium", "High", "Critical", "Unknown")
    """

    assert "title" in finding
    assert "description" in finding
    assert "severity" in finding
    # if cves is in finding it's a list
    if "cves" in finding:
        assert type(finding["cves"]) is list
    # if cwes is in finding it's a list
    if "cwes" in finding:
        assert type(finding["cwes"]) is list
