"""
Importers for third-party security scanner reports and graph topologies:
- Trivy JSON vulnerability reports
- Nessus / OpenVAS CSV reports
"""
import csv
import io
import json
import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.app.models.database import (
    Asset, AssetType, Environment, NetworkZone,
    Vulnerability, VulnerabilitySeverity, AttackVector, AttackComplexity,
    PrivilegesRequired, UserInteraction, Finding, FindingStatus,
    Scenario,
)


def _map_cvss_severity(score: float) -> VulnerabilitySeverity:
    if score >= 9.0:
        return VulnerabilitySeverity.CRITICAL
    elif score >= 7.0:
        return VulnerabilitySeverity.HIGH
    elif score >= 4.0:
        return VulnerabilitySeverity.MEDIUM
    return VulnerabilitySeverity.LOW


def import_trivy_json(
    db: Session,
    scenario_id: str,
    raw_json_str: str,
    scenario_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Parses a Trivy vulnerability scan JSON output, creating assets and findings in the specified scenario.
    """
    data = json.loads(raw_json_str)
    
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        scenario = Scenario(
            id=scenario_id,
            name=scenario_name or f"Trivy Import - {scenario_id}",
            description="Imported from Trivy container/filesystem security scan."
        )
        db.add(scenario)
        db.flush()

    results = data.get("Results", [])
    if not results and isinstance(data, list):
        results = data

    created_assets = 0
    created_vulns = 0
    created_findings = 0

    for idx, target_block in enumerate(results):
        target_name = target_block.get("Target", f"target-{idx+1}")
        asset_id = f"{scenario_id}-trivy-asset-{idx+1}"
        
        asset = db.query(Asset).filter(Asset.id == asset_id, Asset.scenario_id == scenario_id).first()
        if not asset:
            asset = Asset(
                id=asset_id,
                name=target_name,
                type=AssetType.APP_SERVER,
                criticality=7.0,
                environment=Environment.PRODUCTION,
                network_zone=NetworkZone.APP_TIER,
                is_entry_point=(idx == 0),
                is_crown_jewel=False,
                owner="SecOps",
                scenario_id=scenario_id,
            )
            db.add(asset)
            db.flush()
            created_assets += 1

        vulnerabilities = target_block.get("Vulnerabilities") or []
        for v_data in vulnerabilities:
            cve_id = v_data.get("VulnerabilityID") or f"TRIVY-{uuid.uuid4().hex[:8]}"
            vuln_id = f"{scenario_id}-vuln-{cve_id}"
            
            cvss_score = 7.5
            cvss_data = v_data.get("CVSS", {})
            if "nvd" in cvss_data and "V3Score" in cvss_data["nvd"]:
                cvss_score = float(cvss_data["nvd"]["V3Score"])
            elif "redhat" in cvss_data and "V3Score" in cvss_data["redhat"]:
                cvss_score = float(cvss_data["redhat"]["V3Score"])

            severity = _map_cvss_severity(cvss_score)

            vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
            if not vuln:
                vuln = Vulnerability(
                    id=vuln_id,
                    cve_id=cve_id,
                    title=v_data.get("Title") or f"Vulnerability {cve_id}",
                    description=v_data.get("Description", "")[:500],
                    cvss_score=cvss_score,
                    severity=severity,
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.NONE,
                    user_interaction=UserInteraction.NONE,
                    known_exploited=False,
                    epss_score=0.1,
                    scenario_id=scenario_id,
                )
                db.add(vuln)
                db.flush()
                created_vulns += 1

            finding_id = f"{scenario_id}-finding-{asset_id}-{cve_id}"
            existing_finding = db.query(Finding).filter(Finding.id == finding_id, Finding.scenario_id == scenario_id).first()
            if not existing_finding:
                finding = Finding(
                    id=finding_id,
                    asset_id=asset.id,
                    vulnerability_id=vuln.id,
                    status=FindingStatus.ACTIVE,
                    scenario_id=scenario_id,
                )
                db.add(finding)
                created_findings += 1

    db.commit()
    return {
        "scenario_id": scenario_id,
        "assets_imported": created_assets,
        "vulnerabilities_imported": created_vulns,
        "findings_imported": created_findings,
        "message": f"Successfully parsed Trivy report for scenario '{scenario_id}'"
    }


def import_nessus_csv(
    db: Session,
    scenario_id: str,
    raw_csv_str: str,
    scenario_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Parses a Nessus/OpenVAS exported CSV report into assets, vulnerabilities, and findings.
    """
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        scenario = Scenario(
            id=scenario_id,
            name=scenario_name or f"Nessus Import - {scenario_id}",
            description="Imported from Nessus/OpenVAS vulnerability scanner CSV."
        )
        db.add(scenario)
        db.flush()

    reader = csv.DictReader(io.StringIO(raw_csv_str))
    
    created_assets = 0
    created_vulns = 0
    created_findings = 0
    seen_hosts: Dict[str, str] = {}

    for row in reader:
        host = row.get("Host") or row.get("IP Address") or row.get("host") or "unknown-host"
        cve = row.get("CVE") or row.get("Plugin ID") or f"NESSUS-{uuid.uuid4().hex[:6]}"
        vuln_name = row.get("Name") or row.get("Synopsis") or f"Issue {cve}"
        
        cvss_raw = row.get("CVSS v3.0 Base Score") or row.get("CVSS") or row.get("CVSS Score") or "5.0"
        try:
            cvss_score = float(cvss_raw)
        except ValueError:
            cvss_score = 5.0
            
        severity = _map_cvss_severity(cvss_score)

        if host not in seen_hosts:
            asset_id = f"{scenario_id}-host-{len(seen_hosts)+1}"
            asset = db.query(Asset).filter(Asset.id == asset_id, Asset.scenario_id == scenario_id).first()
            if not asset:
                asset = Asset(
                    id=asset_id,
                    name=host,
                    type=AssetType.WEB_SERVER if len(seen_hosts) == 0 else AssetType.APP_SERVER,
                    criticality=8.0 if len(seen_hosts) == 0 else 6.0,
                    environment=Environment.PRODUCTION,
                    network_zone=NetworkZone.DMZ if len(seen_hosts) == 0 else NetworkZone.APP_TIER,
                    is_entry_point=(len(seen_hosts) == 0),
                    is_crown_jewel=False,
                    owner="SecOps",
                    scenario_id=scenario_id,
                )
                db.add(asset)
                db.flush()
                created_assets += 1
            seen_hosts[host] = asset_id

        curr_asset_id = seen_hosts[host]
        vuln_id = f"{scenario_id}-vuln-{cve}"
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not vuln:
            vuln = Vulnerability(
                id=vuln_id,
                cve_id=cve,
                title=vuln_name[:200],
                description=(row.get("Description") or vuln_name)[:500],
                cvss_score=cvss_score,
                severity=severity,
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.LOW,
                privileges_required=PrivilegesRequired.NONE,
                user_interaction=UserInteraction.NONE,
                known_exploited=False,
                epss_score=0.08,
                scenario_id=scenario_id,
            )
            db.add(vuln)
            db.flush()
            created_vulns += 1

        finding_id = f"{scenario_id}-finding-{curr_asset_id}-{cve}"
        existing_finding = db.query(Finding).filter(Finding.id == finding_id, Finding.scenario_id == scenario_id).first()
        if not existing_finding:
            finding = Finding(
                id=finding_id,
                asset_id=curr_asset_id,
                vulnerability_id=vuln.id,
                status=FindingStatus.ACTIVE,
                scenario_id=scenario_id,
            )
            db.add(finding)
            created_findings += 1

    db.commit()
    return {
        "scenario_id": scenario_id,
        "assets_imported": created_assets,
        "vulnerabilities_imported": created_vulns,
        "findings_imported": created_findings,
        "message": f"Successfully parsed Nessus CSV for scenario '{scenario_id}'"
    }
