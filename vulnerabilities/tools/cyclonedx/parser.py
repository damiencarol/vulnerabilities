import logging
import re

import dateutil
from cvss.cvss3 import CVSS3
from defusedxml import ElementTree

LOGGER = logging.getLogger(__name__)


def parse(file):
    nscan = ElementTree.parse(file)
    root = nscan.getroot()
    namespace = get_namespace(root)
    if not namespace.startswith("{http://cyclonedx.org/schema/bom/"):
        raise ValueError(
            f"This doesn't seem to be a valid CyclonDX BOM XML file. Namespace={namespace}"
        )
    ns = {
        "b": namespace.replace("{", "").replace(
            "}", ""
        ),  # we accept whatever the version
        "v": "http://cyclonedx.org/schema/ext/vulnerability/1.0",
    }
    # get report date
    report_date = None
    report_date_raw = root.findtext("b:metadata/b:timestamp", namespaces=ns)
    if report_date_raw:
        report_date = dateutil.parser.parse(report_date_raw)
    bom_refs = {}
    items = []
    for component in root.findall("b:components/b:component", namespaces=ns):
        component_vendor = component.findtext(f"{namespace}group")
        component_name = component.findtext(f"{namespace}name")
        component_version = component.findtext(f"{namespace}version")
        # add finding for the component
        manage_component(items, component, report_date, namespace)
        # save a ref
        if "bom-ref" in component.attrib:
            bom_refs[component.attrib["bom-ref"]] = {
                "vendor": component_vendor,
                "name": component_name,
                "version": component_version,
            }
        for vulnerability in component.findall(
            "v:vulnerabilities/v:vulnerability", namespaces=ns
        ):
            manage_vulnerability(
                items,
                vulnerability,
                ns,
                bom_refs,
                report_date=report_date,
                component_vendor=component_vendor,
                component_name=component_name,
                component_version=component_version,
            )
    # manage adhoc vulnerabilities
    for vulnerability in root.findall(
        "v:vulnerabilities/v:vulnerability", namespaces=ns
    ):
        manage_vulnerability(items, vulnerability, ns, bom_refs, report_date)

    return items


def get_cwes(node, namespaces):
    cwes = []
    for cwe in node.findall("v:cwes/v:cwe", namespaces):
        if cwe.text.isdigit():
            cwes.append(int(cwe.text))
    return cwes


def _get_cvssv3(node, namespaces):
    for rating in node.findall("v:ratings/v:rating", namespaces=namespaces):
        if "CVSSv3" == rating.findtext("v:method", namespaces=namespaces):
            raw_vector = rating.findtext("v:vector", namespaces=namespaces)
            if raw_vector is None or "" == raw_vector:
                return None
            if not raw_vector.startswith("CVSS:3"):
                raw_vector = "CVSS:3.1/" + raw_vector
            return CVSS3(raw_vector)
    return None


def manage_vulnerability(
    items,
    vulnerability,
    ns,
    bom_refs,
    report_date,
    component_vendor=None,
    component_name=None,
    component_version=None,
):
    ref = vulnerability.attrib["ref"]
    vuln_id = vulnerability.findtext("v:id", namespaces=ns)

    if component_name is None:
        bom = bom_refs[ref]
        component_vendor = bom["vendor"]
        component_name = bom["name"]
        component_version = bom["version"]

    # From the spec:
    # <xs:enumeration value="None"/>
    # <xs:enumeration value="Low"/>
    # <xs:enumeration value="Medium"/>
    # <xs:enumeration value="High"/>
    # <xs:enumeration value="Critical"/>
    # <xs:enumeration value="Unknown"/>
    severity = vulnerability.findtext("v:ratings/v:rating/v:severity", namespaces=ns)
    if "None" == severity:
        severity = None

    references = ""
    for adv in vulnerability.findall("v:advisories/v:advisory", namespaces=ns):
        references += f"{adv.text}\n"

    description = "\n".join(
        [
            f"**Ref:** {ref}",
            f"**Id:** {vuln_id}",
            f"**Severity:** {severity}",
        ]
    )

    finding = {
        "title": vuln_id,
        "description": description,
        "severity": severity,
        "references": references,
        "component_vendor": component_vendor,
        "vuln_id_from_tool": vuln_id,
    }
    if component_vendor:
        finding["component_vendor"] = component_vendor
    if component_name:
        finding["component_name"] = component_name
    if component_version:
        finding["component_version"] = component_version

    if report_date:
        finding["date"] = report_date

    # manage if the ID is a CVE
    if re.fullmatch("CVE-[0-9]+-[0-9]+", vuln_id):
        finding["cve"] = vuln_id

    # manage CVSS
    cvssv3 = _get_cvssv3(vulnerability, ns)
    if cvssv3:
        cvssv3.compute_base_score()
        finding["cvssv3"] = cvssv3.clean_vector()

    # if there is some CWE
    finding["cwe"] = get_cwes(vulnerability, ns)

    items.append(finding)


def manage_component(items, component_node, report_date, namespace):
    bom_ref = component_node.attrib.get("bom-ref")
    component_vendor = component_node.findtext(f"{namespace}group")
    component_name = component_node.findtext(f"{namespace}name")
    component_version = component_node.findtext(f"{namespace}version")
    description = "\n".join(
        [
            f"**Ref:** {bom_ref}",
            f"**Type:** {component_node.attrib.get('type')}",
            f"**Name:** {component_name}",
            f"**Version:** {component_version}",
        ]
    )

    finding = {
        "title": f"Component detected {component_name}:{component_version}",
        "description": description,
        "severity": "Info",
        "component_vendor": component_vendor,
        "component_name": component_name,
        "component_version": component_version,
    }

    if report_date:
        finding["date"] = report_date

    items.append(finding)


def get_namespace(element):
    """Extract namespace present in XML file."""
    m = re.match(r"\{.*\}", element.tag)
    return m.group(0) if m else ""
