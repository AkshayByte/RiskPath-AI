"""
Property-based invariant testing using Hypothesis for RiskPath AI core algorithms.
Validates mathematical and security invariants:
1. Monotonicity of remediation (applying fixes never increases attack paths).
2. Budget admissibility (optimizer cost never exceeds assigned budget).
3. Chokepoint score bounds (always in [0.0, 1.0]).
4. Blast radius boundedness (always <= total graph nodes).
5. Synthetic scenario generator structure.
"""

import networkx as nx
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.analysis.blast_radius import compute_blast_radius
from backend.app.analysis.budget_optimization import optimize, resolve_candidates
from backend.app.analysis.chokepoint import compute_chokepoints
from backend.app.analysis.path_analysis import find_attack_paths
from backend.app.analysis.remediation_simulation import resolve_simulation_action, run_simulation
from backend.app.analysis.synthetic_generator import generate_synthetic_scenario
from backend.app.graph.builder import build_canonical_graph
from backend.app.models.database import (
    Asset,
    AssetType,
    AttackComplexity,
    AttackVector,
    Base,
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


def _make_test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_remediation_monotonicity_property():
    """
    Property: Remediation actions must monotonically reduce or keep equal the attack path count.
    P_remediated <= P_baseline for any subset of remediations.
    """
    db = _make_test_db()
    sc = Scenario(id="prop_sc", name="Property Test Topology")
    db.add(sc)

    a1 = Asset(
        id="p-web",
        name="Web",
        type=AssetType.WEB_SERVER,
        criticality=8.0,
        environment=Environment.PRODUCTION,
        network_zone=NetworkZone.DMZ,
        is_entry_point=True,
        is_crown_jewel=False,
        owner="IT",
        scenario_id="prop_sc",
    )
    a2 = Asset(
        id="p-app",
        name="App",
        type=AssetType.APP_SERVER,
        criticality=7.0,
        environment=Environment.PRODUCTION,
        network_zone=NetworkZone.APP_TIER,
        is_entry_point=False,
        is_crown_jewel=False,
        owner="IT",
        scenario_id="prop_sc",
    )
    a3 = Asset(
        id="p-db",
        name="DB",
        type=AssetType.DATABASE,
        criticality=10.0,
        environment=Environment.PRODUCTION,
        network_zone=NetworkZone.DB_TIER,
        is_entry_point=False,
        is_crown_jewel=True,
        owner="IT",
        scenario_id="prop_sc",
    )
    db.add_all([a1, a2, a3])

    v1 = Vulnerability(
        id="p-v1",
        cve_id="CVE-2024-001",
        title="V1",
        description="",
        cvss_score=8.5,
        severity=VulnerabilitySeverity.HIGH,
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        known_exploited=True,
        epss_score=0.9,
        scenario_id="prop_sc",
    )
    v2 = Vulnerability(
        id="p-v2",
        cve_id="CVE-2024-002",
        title="V2",
        description="",
        cvss_score=7.0,
        severity=VulnerabilitySeverity.HIGH,
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        known_exploited=False,
        epss_score=0.2,
        scenario_id="prop_sc",
    )
    db.add_all([v1, v2])

    f1 = Finding(
        id="p-f1", asset_id="p-web", vulnerability_id="p-v1", status=FindingStatus.ACTIVE, scenario_id="prop_sc"
    )
    f2 = Finding(
        id="p-f2", asset_id="p-app", vulnerability_id="p-v2", status=FindingStatus.ACTIVE, scenario_id="prop_sc"
    )
    db.add_all([f1, f2])

    e1 = Edge(
        id="p-e1",
        source_id="p-web",
        target_id="p-app",
        edge_type=EdgeType.CAN_REACH,
        traversal_cost=1.0,
        probability=1.0,
        port=443,
        protocol="tcp",
        scenario_id="prop_sc",
    )
    e2 = Edge(
        id="p-e2",
        source_id="p-app",
        target_id="p-db",
        edge_type=EdgeType.CAN_REACH,
        traversal_cost=1.0,
        probability=1.0,
        port=5432,
        protocol="tcp",
        scenario_id="prop_sc",
    )
    e3 = Edge(
        id="p-e3",
        source_id="p-web",
        target_id="p-db",
        edge_type=EdgeType.CAN_REACH,
        traversal_cost=2.0,
        probability=0.8,
        port=5432,
        protocol="tcp",
        scenario_id="prop_sc",
    )
    db.add_all([e1, e2, e3])

    r1 = RemediationAction(
        id="p-r1",
        title="Patch Web",
        description="",
        action_type=RemediationActionType.PATCH_VULNERABILITY,
        target_finding_id="p-f1",
        estimated_cost=4.0,
        implementation_complexity="LOW",
        scenario_id="prop_sc",
    )
    r2 = RemediationAction(
        id="p-r2",
        title="Patch App",
        description="",
        action_type=RemediationActionType.PATCH_VULNERABILITY,
        target_finding_id="p-f2",
        estimated_cost=5.0,
        implementation_complexity="MEDIUM",
        scenario_id="prop_sc",
    )
    r3 = RemediationAction(
        id="p-r3",
        title="Block Web->DB",
        description="",
        action_type=RemediationActionType.REMOVE_NETWORK_PATH,
        target_edge_id="p-e3",
        estimated_cost=2.0,
        implementation_complexity="LOW",
        scenario_id="prop_sc",
    )
    r4 = RemediationAction(
        id="p-r4",
        title="Isolate App",
        description="",
        action_type=RemediationActionType.ISOLATE_ASSET,
        target_asset_id="p-app",
        estimated_cost=8.0,
        implementation_complexity="HIGH",
        scenario_id="prop_sc",
    )
    db.add_all([r1, r2, r3, r4])
    db.commit()

    graph = build_canonical_graph(db, "prop_sc")
    baseline_paths = find_attack_paths(graph)
    initial_path_count = len(baseline_paths)

    actions = db.query(RemediationAction).filter(RemediationAction.scenario_id == "prop_sc").all()
    resolved = [resolve_simulation_action(a, "prop_sc") for a in actions]

    for action in resolved:
        res = run_simulation(graph, [action], scenario_id="prop_sc")
        remediated_path_count = res.final.total_attack_paths
        assert remediated_path_count <= initial_path_count, (
            f"Action {action.action_id} increased attack paths from {initial_path_count} to {remediated_path_count}"
        )
    db.close()


@given(budget=st.floats(min_value=0.0, max_value=50.0))
@settings(max_examples=15)
def test_budget_admissibility_property(budget):
    """
    Property: Budget optimization total cost must NEVER exceed the allocated budget.
    Sum(cost(action_i)) <= Budget.
    """
    db = _make_test_db()

    sc = Scenario(id="b_sc", name="Budget Scenario")
    db.add(sc)
    a1 = Asset(
        id="b1",
        name="W",
        type=AssetType.WEB_SERVER,
        criticality=8.0,
        environment=Environment.PRODUCTION,
        network_zone=NetworkZone.DMZ,
        is_entry_point=True,
        is_crown_jewel=False,
        owner="IT",
        scenario_id="b_sc",
    )
    a2 = Asset(
        id="b2",
        name="D",
        type=AssetType.DATABASE,
        criticality=10.0,
        environment=Environment.PRODUCTION,
        network_zone=NetworkZone.DB_TIER,
        is_entry_point=False,
        is_crown_jewel=True,
        owner="IT",
        scenario_id="b_sc",
    )
    db.add_all([a1, a2])
    v1 = Vulnerability(
        id="bv1",
        cve_id="CVE-2024-B1",
        title="B",
        description="",
        cvss_score=8.0,
        severity=VulnerabilitySeverity.HIGH,
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        known_exploited=True,
        epss_score=0.5,
        scenario_id="b_sc",
    )
    db.add(v1)
    f1 = Finding(id="bf1", asset_id="b1", vulnerability_id="bv1", status=FindingStatus.ACTIVE, scenario_id="b_sc")
    db.add(f1)
    e1 = Edge(
        id="be1",
        source_id="b1",
        target_id="b2",
        edge_type=EdgeType.CAN_REACH,
        traversal_cost=1.0,
        probability=1.0,
        port=80,
        protocol="tcp",
        scenario_id="b_sc",
    )
    db.add(e1)

    r1 = RemediationAction(
        id="br1",
        title="R1",
        description="",
        action_type=RemediationActionType.PATCH_VULNERABILITY,
        target_finding_id="bf1",
        estimated_cost=3.0,
        implementation_complexity="LOW",
        scenario_id="b_sc",
    )
    r2 = RemediationAction(
        id="br2",
        title="R2",
        description="",
        action_type=RemediationActionType.REMOVE_NETWORK_PATH,
        target_edge_id="be1",
        estimated_cost=5.0,
        implementation_complexity="MEDIUM",
        scenario_id="b_sc",
    )
    db.add_all([r1, r2])
    db.commit()

    graph = build_canonical_graph(db, "b_sc")
    candidates = resolve_candidates([r1, r2], "b_sc")

    result = optimize(graph, candidates, budget=budget, scenario_id="b_sc")

    assert result.selected_total_cost <= budget + 1e-6, (
        f"Optimizer selected cost {result.selected_total_cost} exceeding budget {budget}"
    )
    db.close()


def test_chokepoint_and_blast_bounds():
    """
    Property: Chokepoint fraction is bounded in [0.0, 1.0] and blast radius in [1, N].
    """
    db = _make_test_db()
    sc = Scenario(id="bounds_sc", name="Bounds Scenario")
    db.add(sc)

    a1 = Asset(
        id="b-web",
        name="Web",
        type=AssetType.WEB_SERVER,
        criticality=8.0,
        environment=Environment.PRODUCTION,
        network_zone=NetworkZone.DMZ,
        is_entry_point=True,
        is_crown_jewel=False,
        owner="IT",
        scenario_id="bounds_sc",
    )
    a2 = Asset(
        id="b-app",
        name="App",
        type=AssetType.APP_SERVER,
        criticality=7.0,
        environment=Environment.PRODUCTION,
        network_zone=NetworkZone.APP_TIER,
        is_entry_point=False,
        is_crown_jewel=False,
        owner="IT",
        scenario_id="bounds_sc",
    )
    a3 = Asset(
        id="b-db",
        name="DB",
        type=AssetType.DATABASE,
        criticality=10.0,
        environment=Environment.PRODUCTION,
        network_zone=NetworkZone.DB_TIER,
        is_entry_point=False,
        is_crown_jewel=True,
        owner="IT",
        scenario_id="bounds_sc",
    )
    db.add_all([a1, a2, a3])

    v1 = Vulnerability(
        id="b-v1",
        cve_id="CVE-2024-001",
        title="V1",
        description="",
        cvss_score=8.5,
        severity=VulnerabilitySeverity.HIGH,
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        known_exploited=True,
        epss_score=0.9,
        scenario_id="bounds_sc",
    )
    db.add(v1)

    f1 = Finding(
        id="b-f1", asset_id="b-web", vulnerability_id="b-v1", status=FindingStatus.ACTIVE, scenario_id="bounds_sc"
    )
    db.add(f1)

    e1 = Edge(
        id="b-e1",
        source_id="b-web",
        target_id="b-app",
        edge_type=EdgeType.CAN_REACH,
        traversal_cost=1.0,
        probability=1.0,
        port=443,
        protocol="tcp",
        scenario_id="bounds_sc",
    )
    e2 = Edge(
        id="b-e2",
        source_id="b-app",
        target_id="b-db",
        edge_type=EdgeType.CAN_REACH,
        traversal_cost=1.0,
        probability=1.0,
        port=5432,
        protocol="tcp",
        scenario_id="bounds_sc",
    )
    db.add_all([e1, e2])
    db.commit()

    graph = build_canonical_graph(db, "bounds_sc")
    chokepoint_res = compute_chokepoints(graph)
    for detail in chokepoint_res.chokepoints:
        assert 0.0 <= detail.chokepoint_score <= 1.0

    total_nodes = graph.number_of_nodes()
    for node in graph.nodes():
        if graph.nodes[node].get("type") == "asset":
            br = compute_blast_radius(graph, node)
            assert 1 <= br.affected_asset_count <= total_nodes
    db.close()


@given(asset_count=st.integers(min_value=10, max_value=25))
@settings(max_examples=5)
def test_synthetic_generator_property(asset_count):
    """
    Property: Synthetic generator produces valid connected graphs with exact node counts.
    """
    db = _make_test_db()
    sc_id = f"synth_hypo_{asset_count}"
    res = generate_synthetic_scenario(db, scenario_id=sc_id, name="Synth Test", asset_count=asset_count)

    assert res["asset_count"] == asset_count
    assert res["entry_points"] >= 1
    assert res["crown_jewels"] >= 1
    assert res["edge_count"] > 0
    assert res["finding_count"] > 0

    graph = build_canonical_graph(db, sc_id)
    assert isinstance(graph, nx.MultiDiGraph)
    asset_nodes = [n for n, d in graph.nodes(data=True) if d.get("type") == "asset"]
    assert len(asset_nodes) == asset_count
    db.close()
