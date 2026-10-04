"""
Synthetic attack topology generator for stress-testing and large-scale scenarios (10-500 nodes).
Fully deterministic and reproducible using isolated random.Random(seed).
"""

import random
from typing import Any

from sqlalchemy.orm import Session

from backend.app.models.database import (
    Asset,
    AssetType,
    AttackComplexity,
    AttackVector,
    Edge,
    EdgeType,
    Environment,
    Finding,
    FindingStatus,
    NetworkZone,
    PrivilegesRequired,
    RemediationAction,
    RemediationActionType,
    Scenario,
    UserInteraction,
    Vulnerability,
    VulnerabilitySeverity,
)


class ScenarioExistsError(ValueError):
    """Raised when trying to generate a scenario whose ID already exists and overwrite is False."""

    pass


def generate_synthetic_scenario(
    db: Session,
    scenario_id: str,
    name: str,
    asset_count: int = 50,
    entry_point_ratio: float = 0.1,
    crown_jewel_ratio: float = 0.08,
    seed: int = 42,
    overwrite: bool = True,
) -> dict[str, Any]:
    """
    Generate a realistic, large-scale multi-tier network topology.
    Deterministic and reproducible via isolated RNG instance.
    """
    asset_count = max(10, min(500, asset_count))
    rng = random.Random(seed)

    existing = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if existing:
        if not overwrite:
            raise ScenarioExistsError(f"Scenario with ID '{scenario_id}' already exists.")
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
        description=f"Automated synthetic benchmark scenario with {asset_count} nodes, seed={seed}.",
    )
    db.add(scenario)

    zones = [NetworkZone.DMZ, NetworkZone.APP_TIER, NetworkZone.DB_TIER, NetworkZone.MANAGEMENT]
    types = [
        AssetType.WEB_SERVER,
        AssetType.APP_SERVER,
        AssetType.DATABASE,
        AssetType.API_GATEWAY,
        AssetType.WORKSTATION,
    ]

    num_entry = max(1, round(asset_count * entry_point_ratio))
    num_crown = max(1, round(asset_count * crown_jewel_ratio))

    # Guarantee at least some intermediate nodes
    if num_entry + num_crown >= asset_count:
        num_entry = max(1, asset_count // 4)
        num_crown = max(1, asset_count // 4)

    # 1. Create Assets
    created_assets: list[Asset] = []
    for i in range(asset_count):
        is_entry = i < num_entry
        is_crown = not is_entry and (i >= asset_count - num_crown)
        zone = NetworkZone.DMZ if is_entry else (NetworkZone.DB_TIER if is_crown else rng.choice(zones))
        a_type = AssetType.WEB_SERVER if is_entry else (AssetType.DATABASE if is_crown else rng.choice(types))

        asset = Asset(
            id=f"{scenario_id}-asset-{i + 1:03d}",
            name=f"Host-{i + 1:03d} ({zone.value.upper()})",
            type=a_type,
            criticality=10.0 if is_crown else (8.0 if is_entry else round(rng.uniform(4.0, 9.0), 1)),
            environment=Environment.PRODUCTION,
            network_zone=zone,
            is_entry_point=is_entry,
            is_crown_jewel=is_crown,
            owner="SecOps",
            ip_address=f"10.{10 + (i // 254)}.{1 + (i % 254)}.{i % 250 + 1}",
            description=f"Auto-generated tier asset {i + 1}",
            scenario_id=scenario_id,
        )
        created_assets.append(asset)
    db.add_all(created_assets)
    db.flush()

    # 2. Create Common Vulnerability Pool
    vuln_pool: list[Vulnerability] = []
    cve_templates = [
        ("CVE-2024-3094", "XZ Utils Backdoor RCE", 10.0, VulnerabilitySeverity.CRITICAL, True, 0.95),
        ("CVE-2023-38606", "Kernel Privilege Escalation", 8.8, VulnerabilitySeverity.HIGH, True, 0.75),
        ("CVE-2023-44487", "HTTP/2 Rapid Reset DoS", 7.5, VulnerabilitySeverity.HIGH, False, 0.40),
        ("CVE-2023-22515", "Confluence Broken Access Control", 9.8, VulnerabilitySeverity.CRITICAL, True, 0.88),
        ("CVE-2023-3519", "NetScaler Gateway RCE", 9.8, VulnerabilitySeverity.CRITICAL, True, 0.92),
        ("CVE-2024-21762", "FortiOS SSL-VPN RCE", 9.8, VulnerabilitySeverity.CRITICAL, True, 0.89),
        ("CVE-2023-27997", "Fortinet Heap Buffer Overflow", 9.8, VulnerabilitySeverity.CRITICAL, True, 0.90),
        ("CVE-2023-34362", "MOVEit SQL Injection", 9.8, VulnerabilitySeverity.CRITICAL, True, 0.93),
    ]
    for idx, (cve, title, cvss, sev, kev, epss) in enumerate(cve_templates):
        v = Vulnerability(
            id=f"{scenario_id}-vuln-{idx + 1:02d}",
            cve_id=cve,
            title=title,
            description=f"Simulated weakness modeled after {cve}",
            cvss_score=cvss,
            severity=sev,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            known_exploited=kev,
            epss_score=epss,
            scenario_id=scenario_id,
        )
        vuln_pool.append(v)
    db.add_all(vuln_pool)
    db.flush()

    # 3. Assign Findings to Assets & Construct Topology Edges
    created_findings: list[Finding] = []
    created_edges: list[Edge] = []
    edge_counter = 1
    finding_counter = 1

    for asset in created_assets:
        # 60% chance host has 1-2 vulnerabilities
        if rng.random() < 0.65 or asset.is_entry_point:
            num_v = rng.randint(1, 2)
            assigned_vulns = rng.sample(vuln_pool, num_v)
            for v in assigned_vulns:
                fid = f"{scenario_id}-finding-{finding_counter:03d}"
                f = Finding(
                    id=fid,
                    asset_id=asset.id,
                    vulnerability_id=v.id,
                    port=443 if asset.is_entry_point else 8080,
                    service_name="https" if asset.is_entry_point else "app-service",
                    status=FindingStatus.ACTIVE,
                    scenario_id=scenario_id,
                )
                created_findings.append(f)
                finding_counter += 1

    # Connect nodes into multi-tier paths: entry -> intermediate -> crown
    entry_nodes = [a for a in created_assets if a.is_entry_point]
    crown_nodes = [a for a in created_assets if a.is_crown_jewel]
    middle_nodes = [a for a in created_assets if not a.is_entry_point and not a.is_crown_jewel]

    # Entry to intermediate edges
    for entry in entry_nodes:
        targets = rng.sample(middle_nodes, min(len(middle_nodes), rng.randint(2, 4)))
        for t in targets:
            e = Edge(
                id=f"{scenario_id}-edge-{edge_counter:04d}",
                source_id=entry.id,
                target_id=t.id,
                edge_type=EdgeType.CAN_REACH,
                port=443,
                protocol="tcp",
                traversal_cost=round(rng.uniform(1.0, 3.0), 1),
                probability=round(rng.uniform(0.6, 0.9), 2),
                scenario_id=scenario_id,
            )
            created_edges.append(e)
            edge_counter += 1

    # Lateral movement between middle nodes
    for m in middle_nodes:
        peers = [n for n in middle_nodes if n.id != m.id]
        if peers and rng.random() < 0.4:
            targets = rng.sample(peers, min(len(peers), rng.randint(1, 2)))
            for t in targets:
                e = Edge(
                    id=f"{scenario_id}-edge-{edge_counter:04d}",
                    source_id=m.id,
                    target_id=t.id,
                    edge_type=EdgeType.LATERAL_MOVEMENT,
                    port=22,
                    protocol="ssh",
                    traversal_cost=round(rng.uniform(1.5, 4.0), 1),
                    probability=round(rng.uniform(0.4, 0.8), 2),
                    scenario_id=scenario_id,
                )
                created_edges.append(e)
                edge_counter += 1

    # Middle to crown jewel edges
    for crown in crown_nodes:
        sources = rng.sample(middle_nodes, min(len(middle_nodes), rng.randint(2, 3)))
        for s in sources:
            e = Edge(
                id=f"{scenario_id}-edge-{edge_counter:04d}",
                source_id=s.id,
                target_id=crown.id,
                edge_type=EdgeType.TRUSTED_ACCESS,
                port=5432,
                protocol="database",
                traversal_cost=round(rng.uniform(2.0, 5.0), 1),
                probability=round(rng.uniform(0.3, 0.7), 2),
                scenario_id=scenario_id,
            )
            created_edges.append(e)
            edge_counter += 1

    db.add_all(created_findings)
    db.add_all(created_edges)
    db.flush()

    # 4. Create Remediation Actions for findings & high-cost edges
    created_actions: list[RemediationAction] = []
    for f in created_findings[:12]:
        act = RemediationAction(
            id=f"{scenario_id}-rem-{f.id}",
            title=f"Remediate {f.id} on {f.asset_id}",
            description=f"Patch and deploy verified fix for finding {f.id}",
            action_type=RemediationActionType.PATCH_VULNERABILITY,
            target_finding_id=f.id,
            estimated_cost=round(rng.uniform(3.0, 8.0), 1),
            implementation_complexity="MEDIUM",
            downtime_required=rng.choice([True, False]),
            scenario_id=scenario_id,
        )
        created_actions.append(act)
    db.add_all(created_actions)

    return {
        "scenario_id": scenario_id,
        "name": name,
        "asset_count": len(created_assets),
        "finding_count": len(created_findings),
        "edge_count": len(created_edges),
        "remediation_action_count": len(created_actions),
        "entry_points": num_entry,
        "crown_jewels": num_crown,
        "seed": seed,
    }
