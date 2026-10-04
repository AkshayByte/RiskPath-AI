"""
Synthetic attack topology generator for stress-testing and large-scale scenarios (50-500 nodes).
"""
import random
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from backend.app.models.database import (
    Asset, AssetType, Environment, NetworkZone,
    Vulnerability, VulnerabilitySeverity, AttackVector, AttackComplexity,
    PrivilegesRequired, UserInteraction, Finding, FindingStatus,
    Edge, EdgeType, RemediationAction, RemediationActionType, Scenario,
)


def generate_synthetic_scenario(
    db: Session,
    scenario_id: str,
    name: str,
    asset_count: int = 50,
    entry_point_ratio: float = 0.1,
    crown_jewel_ratio: float = 0.08,
) -> Dict[str, Any]:
    """Generate a realistic, large-scale multi-tier network topology."""
    asset_count = max(10, min(500, asset_count))
    
    # Check if scenario exists and clean previous objects if replacing
    existing = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if existing:
        db.query(RemediationAction).filter(RemediationAction.scenario_id == scenario_id).delete()
        db.query(Edge).filter(Edge.scenario_id == scenario_id).delete()
        db.query(Finding).filter(Finding.scenario_id == scenario_id).delete()
        db.query(Vulnerability).filter(Vulnerability.scenario_id == scenario_id).delete()
        db.query(Asset).filter(Asset.scenario_id == scenario_id).delete()
        db.delete(existing)
        db.flush()

    scenario = Scenario(
        id=scenario_id,
        name=name or f"Synthetic Enterprise ({asset_count} Assets)",
        description=f"Automated synthetic benchmark scenario with {asset_count} nodes and multi-tier attack transitions."
    )
    db.add(scenario)

    zones = [NetworkZone.DMZ, NetworkZone.APP_TIER, NetworkZone.DB_TIER, NetworkZone.MANAGEMENT]
    types = [AssetType.WEB_SERVER, AssetType.APP_SERVER, AssetType.DATABASE, AssetType.API_GATEWAY, AssetType.WORKSTATION]
    
    num_entry = max(1, int(asset_count * entry_point_ratio))
    num_crown = max(1, int(asset_count * crown_jewel_ratio))

    # 1. Create Assets
    created_assets: List[Asset] = []
    for i in range(asset_count):
        is_entry = i < num_entry
        is_crown = not is_entry and (i >= asset_count - num_crown)
        zone = NetworkZone.DMZ if is_entry else (NetworkZone.DB_TIER if is_crown else random.choice(zones))
        a_type = AssetType.WEB_SERVER if is_entry else (AssetType.DATABASE if is_crown else random.choice(types))
        
        asset = Asset(
            id=f"{scenario_id}-asset-{i+1:03d}",
            name=f"Host-{i+1:03d} ({zone.value.upper()})",
            type=a_type,
            criticality=10.0 if is_crown else (8.0 if is_entry else round(random.uniform(4.0, 9.0), 1)),
            environment=Environment.PRODUCTION,
            network_zone=zone,
            is_entry_point=is_entry,
            is_crown_jewel=is_crown,
            owner=f"Team-{(i%5)+1}",
            ip_address=f"10.{(i//254)+1}.{i%254}.{random.randint(2, 250)}",
            scenario_id=scenario_id,
        )
        created_assets.append(asset)
    db.add_all(created_assets)

    # 2. Create Common CVE Vulnerabilities
    cve_templates = [
        ("CVE-2023-1001", "Remote Code Execution in Web Service", 9.8, VulnerabilitySeverity.CRITICAL, 0.88, True),
        ("CVE-2023-2002", "Privilege Escalation in Kernel Module", 8.4, VulnerabilitySeverity.HIGH, 0.65, True),
        ("CVE-2023-3003", "SQL Injection in Data Backend", 8.8, VulnerabilitySeverity.HIGH, 0.72, False),
        ("CVE-2024-4004", "Authentication Bypass in Session Broker", 9.1, VulnerabilitySeverity.CRITICAL, 0.81, True),
        ("CVE-2024-5005", "Buffer Overflow in Remote RPC", 7.8, VulnerabilitySeverity.HIGH, 0.45, False),
        ("CVE-2024-6006", "Cross-Site Scripting / Header Injection", 5.3, VulnerabilitySeverity.MEDIUM, 0.20, False),
    ]
    created_vulns: List[Vulnerability] = []
    for idx, (cve, title, cvss, sev, epss, kev) in enumerate(cve_templates):
        v = Vulnerability(
            id=f"{scenario_id}-vuln-{idx+1:02d}",
            cve_id=cve,
            title=title,
            description=f"Synthetic security defect: {title}",
            cvss_score=cvss,
            severity=sev,
            epss_score=epss,
            known_exploited=kev,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scenario_id=scenario_id,
        )
        created_vulns.append(v)
    db.add_all(created_vulns)

    # 3. Create Findings & Edges
    created_findings: List[Finding] = []
    created_edges: List[Edge] = []
    finding_counter = 1
    edge_counter = 1

    for asset in created_assets:
        # 60% chance asset has 1-2 findings
        if random.random() < 0.65 or asset.is_entry_point:
            num_f = 1 if not asset.is_entry_point else 2
            for _ in range(num_f):
                vuln = random.choice(created_vulns)
                fid = f"{scenario_id}-finding-{finding_counter:03d}"
                finding = Finding(
                    id=fid,
                    asset_id=asset.id,
                    vulnerability_id=vuln.id,
                    port=random.choice([80, 443, 8080, 22, 3306, 5432]),
                    service_name="tcp-service",
                    status=FindingStatus.ACTIVE,
                    scenario_id=scenario_id,
                )
                created_findings.append(finding)
                
                # Reach edge: Asset -> Finding
                edge_reach = Edge(
                    id=f"{scenario_id}-edge-{edge_counter:04d}",
                    source_id=asset.id,
                    target_id=fid,
                    edge_type=EdgeType.CAN_REACH,
                    port=finding.port,
                    protocol="TCP",
                    traversal_cost=round(random.uniform(0.8, 2.0), 1),
                    probability=round(random.uniform(0.7, 0.95), 2),
                    scenario_id=scenario_id,
                )
                created_edges.append(edge_reach)
                edge_counter += 1
                
                # Exploit edge from finding to random downstream asset in same or deeper zone
                downstream = [a for a in created_assets if a.id != asset.id]
                if downstream:
                    target_asset = random.choice(downstream)
                    edge_exploit = Edge(
                        id=f"{scenario_id}-edge-{edge_counter:04d}",
                        source_id=fid,
                        target_id=target_asset.id,
                        edge_type=EdgeType.EXPLOITS,
                        port=random.choice([8080, 443, 22, 5432]),
                        protocol="TCP",
                        traversal_cost=round(random.uniform(1.0, 3.0), 1),
                        probability=round(random.uniform(0.5, 0.85), 2),
                        finding_id=fid,
                        scenario_id=scenario_id,
                    )
                    created_edges.append(edge_exploit)
                    edge_counter += 1
                finding_counter += 1

    # Inter-asset lateral transitions (connect entry points toward crowns)
    for i in range(len(created_assets) - 1):
        if random.random() < 0.4:
            src = created_assets[i]
            dst = created_assets[i + 1]
            e = Edge(
                id=f"{scenario_id}-edge-{edge_counter:04d}",
                source_id=src.id,
                target_id=dst.id,
                edge_type=EdgeType.CAN_REACH,
                port=443,
                protocol="TCP",
                traversal_cost=round(random.uniform(1.5, 4.0), 1),
                probability=round(random.uniform(0.3, 0.7), 2),
                scenario_id=scenario_id,
            )
            created_edges.append(e)
            edge_counter += 1

    db.add_all(created_findings)
    db.add_all(created_edges)

    # 4. Create Remediation Actions for findings & high-cost edges
    created_actions: List[RemediationAction] = []
    for f in created_findings[:12]:
        act = RemediationAction(
            id=f"{scenario_id}-rem-{f.id}",
            title=f"Remediate {f.id} on {f.asset_id}",
            description=f"Patch and deploy verified fix for finding {f.id}",
            action_type=RemediationActionType.PATCH_VULNERABILITY,
            target_finding_id=f.id,
            estimated_cost=round(random.uniform(3.0, 8.0), 1),
            implementation_complexity="MEDIUM",
            downtime_required=random.choice([True, False]),
            scenario_id=scenario_id,
        )
        created_actions.append(act)
    db.add_all(created_actions)

    db.commit()

    return {
        "scenario_id": scenario_id,
        "name": name,
        "asset_count": len(created_assets),
        "finding_count": len(created_findings),
        "edge_count": len(created_edges),
        "remediation_action_count": len(created_actions),
        "entry_points": num_entry,
        "crown_jewels": num_crown,
    }
