from backend.app.core.database import SessionLocal
from backend.app.models.database import *


def _remediation_seed_rows():
    """Deterministic demo remediation actions on existing seed entities.

    MVP types only (simulatable). IDs are fixed; ensure_remediation_seed_data
    is idempotent so re-running never duplicates rows.
    """
    return [
        RemediationAction(
            id="rem-patch-finding-01",
            title="Patch RCE on Public Web Server",
            description="Apply vendor patch for CVE-2023-12345 on asset-web-01",
            action_type=RemediationActionType.PATCH_VULNERABILITY,
            target_finding_id="finding-01",
            estimated_cost=5.0,
            implementation_complexity="LOW",
            downtime_required=False,
            scenario_id="basic_test_scenario",
        ),
        RemediationAction(
            id="rem-patch-finding-02",
            title="Patch SQL injection on Application Server",
            description="Apply vendor patch for CVE-2023-67890 on asset-app-01",
            action_type=RemediationActionType.PATCH_VULNERABILITY,
            target_finding_id="finding-02",
            estimated_cost=6.0,
            implementation_complexity="MEDIUM",
            downtime_required=True,
            scenario_id="basic_test_scenario",
        ),
        RemediationAction(
            id="rem-remove-direct-db-path",
            title="Remove direct web-to-database network path",
            description="Block direct TCP 1433 reachability from asset-web-01 to asset-db-01",
            action_type=RemediationActionType.REMOVE_NETWORK_PATH,
            target_edge_id="edge-direct-web-to-db",
            estimated_cost=3.0,
            implementation_complexity="LOW",
            downtime_required=False,
            scenario_id="basic_test_scenario",
        ),
        RemediationAction(
            id="rem-isolate-app-server",
            title="Isolate Application Server",
            description="Remove asset-app-01 from the network pending rebuild",
            action_type=RemediationActionType.ISOLATE_ASSET,
            target_asset_id="asset-app-01",
            estimated_cost=8.0,
            implementation_complexity="HIGH",
            downtime_required=True,
            scenario_id="basic_test_scenario",
        ),
    ]


def ensure_remediation_seed_data(db):
    """Idempotently insert demo remediation actions (no duplicates)."""
    for row in _remediation_seed_rows():
        exists = (
            db.query(RemediationAction)
            .filter(RemediationAction.id == row.id)
            .first()
        )
        if exists is None:
            db.add(row)

def create_seed_data():
    db = SessionLocal()
    try:
        # Check if we already have data
        if db.query(Scenario).first():
            # Backfill demo remediation actions idempotently; never duplicates.
            ensure_remediation_seed_data(db)
            db.commit()
            return
        
        # Create a basic scenario
        scenario = Scenario(
            id="basic_test_scenario",
            name="Basic Test Scenario",
            description="A simple test scenario for validating the canonical graph"
        )
        db.add(scenario)
        
        # Create assets
        web_server = Asset(
            id="asset-web-01",
            name="Public Web Server",
            type=AssetType.WEB_SERVER,
            criticality=8.0,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.DMZ,
            is_entry_point=True,
            is_crown_jewel=False,
            owner="IT Team",
            ip_address="203.0.113.1",
            scenario_id="basic_test_scenario",
        )
        
        app_server = Asset(
            id="asset-app-01",
            name="Application Server",
            type=AssetType.APP_SERVER,
            criticality=9.0,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.APP_TIER,
            is_entry_point=False,
            is_crown_jewel=False,
            owner="IT Team",
            ip_address="10.0.1.10",
            scenario_id="basic_test_scenario",
        )
        
        database_server = Asset(
            id="asset-db-01",
            name="Primary Database",
            type=AssetType.DATABASE,
            criticality=10.0,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.DB_TIER,
            is_entry_point=False,
            is_crown_jewel=True,
            owner="DBA Team",
            ip_address="10.0.2.10",
            scenario_id="basic_test_scenario",
        )
        
        db.add_all([web_server, app_server, database_server])
        
        # Create vulnerabilities
        vuln1 = Vulnerability(
            id="vuln-cve-2023-12345",
            cve_id="CVE-2023-12345",
            title="Remote Code Execution in Web Server",
            description="A critical remote code execution vulnerability in the web server software",
            cvss_score=9.8,
            severity=VulnerabilitySeverity.CRITICAL,
            epss_score=0.85,
            known_exploited=True,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scenario_id="basic_test_scenario",
        )
        
        vuln2 = Vulnerability(
            id="vuln-cve-2023-67890",
            cve_id="CVE-2023-67890",
            title="SQL Injection in Application Server",
            description="An SQL injection vulnerability in the application server",
            cvss_score=8.2,
            severity=VulnerabilitySeverity.HIGH,
            epss_score=0.65,
            known_exploited=False,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scenario_id="basic_test_scenario",
        )
        
        db.add_all([vuln1, vuln2])
        
        # Create findings
        finding1 = Finding(
            id="finding-01",
            asset_id="asset-web-01",
            vulnerability_id="vuln-cve-2023-12345",
            port=443,
            service_name="HTTPS",
            status=FindingStatus.ACTIVE,
            scenario_id="basic_test_scenario",
        )
        
        finding2 = Finding(
            id="finding-02",
            asset_id="asset-app-01",
            vulnerability_id="vuln-cve-2023-67890",
            port=8080,
            service_name="HTTP",
            status=FindingStatus.ACTIVE,
            scenario_id="basic_test_scenario",
        )
        
        db.add_all([finding1, finding2])
        
        # Create edges (attack transitions)
        edge1 = Edge(
            id="edge-web-to-finding1",
            source_id="asset-web-01",
            target_id="finding-01",
            edge_type=EdgeType.CAN_REACH,
            port=443,
            protocol="TCP",
            traversal_cost=1.0,
            probability=0.9,
            scenario_id="basic_test_scenario",
        )
        
        edge2 = Edge(
            id="edge-finding1-to-app",
            source_id="finding-01",
            target_id="asset-app-01",
            edge_type=EdgeType.EXPLOITS,
            port=8080,
            protocol="TCP",
            traversal_cost=2.0,
            probability=0.7,
            finding_id="finding-01",
            scenario_id="basic_test_scenario",
        )
        
        edge3 = Edge(
            id="edge-app-to-finding2",
            source_id="asset-app-01",
            target_id="finding-02",
            edge_type=EdgeType.CAN_REACH,
            port=8080,
            protocol="TCP",
            traversal_cost=1.0,
            probability=0.8,
            scenario_id="basic_test_scenario",
        )
        
        edge4 = Edge(
            id="edge-finding2-to-db",
            source_id="finding-02",
            target_id="asset-db-01",
            edge_type=EdgeType.EXPLOITS,
            port=1433,
            protocol="TCP",
            traversal_cost=2.5,
            probability=0.6,
            finding_id="finding-02",
            scenario_id="basic_test_scenario",
        )
        
        edge5 = Edge(
            id="edge-direct-web-to-db",
            source_id="asset-web-01",
            target_id="asset-db-01",
            edge_type=EdgeType.CAN_REACH,
            port=1433,
            protocol="TCP",
            traversal_cost=3.0,
            probability=0.3,
            scenario_id="basic_test_scenario",
        )
        
        db.add_all([edge1, edge2, edge3, edge4, edge5])

        # Create Enterprise Hybrid Cloud Scenario
        enterprise_scenario = Scenario(
            id="enterprise_cloud_hybrid_scenario",
            name="Enterprise Hybrid Cloud Topology",
            description="Multi-tier cloud-hybrid architecture with API gateway, microservices, identity provider, crown-jewel customer database, and cloud backup vault."
        )
        db.add(enterprise_scenario)

        # Enterprise Assets
        ent_api_gw = Asset(
            id="ent-asset-api-gw",
            name="Public API Gateway",
            type=AssetType.API_GATEWAY,
            criticality=8.5,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.DMZ,
            is_entry_point=True,
            is_crown_jewel=False,
            owner="Platform Team",
            ip_address="198.51.100.1",
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_dmz_web = Asset(
            id="ent-asset-dmz-web",
            name="Customer Portal Web Tier",
            type=AssetType.WEB_SERVER,
            criticality=8.0,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.DMZ,
            is_entry_point=True,
            is_crown_jewel=False,
            owner="Web Team",
            ip_address="198.51.100.2",
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_k8s_node = Asset(
            id="ent-asset-k8s-node",
            name="Core Kubernetes Cluster Node",
            type=AssetType.APP_SERVER,
            criticality=9.0,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.APP_TIER,
            is_entry_point=False,
            is_crown_jewel=False,
            owner="DevOps Team",
            ip_address="10.100.1.50",
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_auth_idp = Asset(
            id="ent-asset-auth-idp",
            name="Enterprise IAM / Identity Provider",
            type=AssetType.IDENTITY_PROVIDER,
            criticality=9.5,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.MANAGEMENT,
            is_entry_point=False,
            is_crown_jewel=False,
            owner="SecOps Team",
            ip_address="10.100.0.10",
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_core_db = Asset(
            id="ent-asset-core-db",
            name="Primary Customer Financial Database",
            type=AssetType.DATABASE,
            criticality=10.0,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.DB_TIER,
            is_entry_point=False,
            is_crown_jewel=True,
            owner="Data Engineering",
            ip_address="10.100.2.10",
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_cloud_vault = Asset(
            id="ent-asset-cloud-vault",
            name="Encrypted Cloud S3 Data Vault",
            type=AssetType.CLOUD_STORAGE,
            criticality=10.0,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.DB_TIER,
            is_entry_point=False,
            is_crown_jewel=True,
            owner="Security Compliance",
            ip_address="10.100.2.99",
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        db.add_all([ent_api_gw, ent_dmz_web, ent_k8s_node, ent_auth_idp, ent_core_db, ent_cloud_vault])

        # Enterprise Vulnerabilities
        ent_vuln_log4j = Vulnerability(
            id="ent-vuln-cve-2021-44228",
            cve_id="CVE-2021-44228",
            title="Log4Shell Remote Code Execution",
            description="Unauthenticated remote code execution via JNDI lookup in Apache Log4j2",
            cvss_score=10.0,
            severity=VulnerabilitySeverity.CRITICAL,
            epss_score=0.97,
            known_exploited=True,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_vuln_spring = Vulnerability(
            id="ent-vuln-cve-2022-22965",
            cve_id="CVE-2022-22965",
            title="Spring4Shell RCE in Spring Framework",
            description="Remote code execution in Spring Framework via Data Binding parameter passing",
            cvss_score=9.8,
            severity=VulnerabilitySeverity.CRITICAL,
            epss_score=0.91,
            known_exploited=True,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_vuln_idp_bypass = Vulnerability(
            id="ent-vuln-cve-2023-48795",
            cve_id="CVE-2023-48795",
            title="Terrapin SSH / IAM Channel Integrity Attack",
            description="Prefix truncation vulnerability allowing session downgrade and authentication bypass",
            cvss_score=8.5,
            severity=VulnerabilitySeverity.HIGH,
            epss_score=0.62,
            known_exploited=False,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_vuln_db_rce = Vulnerability(
            id="ent-vuln-cve-2023-39417",
            cve_id="CVE-2023-39417",
            title="PostgreSQL Extension SQL Injection / RCE",
            description="Quote character injection during extension script execution leading to superuser elevation",
            cvss_score=9.1,
            severity=VulnerabilitySeverity.CRITICAL,
            epss_score=0.74,
            known_exploited=False,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        db.add_all([ent_vuln_log4j, ent_vuln_spring, ent_vuln_idp_bypass, ent_vuln_db_rce])

        # Enterprise Findings
        ent_finding_gw = Finding(
            id="ent-finding-gw-log4j",
            asset_id="ent-asset-api-gw",
            vulnerability_id="ent-vuln-cve-2021-44228",
            port=8443,
            service_name="API-Gateway",
            status=FindingStatus.ACTIVE,
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_finding_web = Finding(
            id="ent-finding-web-spring",
            asset_id="ent-asset-dmz-web",
            vulnerability_id="ent-vuln-cve-2022-22965",
            port=443,
            service_name="Web-Portal",
            status=FindingStatus.ACTIVE,
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_finding_k8s = Finding(
            id="ent-finding-k8s-log4j",
            asset_id="ent-asset-k8s-node",
            vulnerability_id="ent-vuln-cve-2021-44228",
            port=8080,
            service_name="K8s-Microservice",
            status=FindingStatus.ACTIVE,
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_finding_idp = Finding(
            id="ent-finding-idp-bypass",
            asset_id="ent-asset-auth-idp",
            vulnerability_id="ent-vuln-cve-2023-48795",
            port=22,
            service_name="IAM-Control",
            status=FindingStatus.ACTIVE,
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        ent_finding_db = Finding(
            id="ent-finding-db-rce",
            asset_id="ent-asset-core-db",
            vulnerability_id="ent-vuln-cve-2023-39417",
            port=5432,
            service_name="PostgreSQL",
            status=FindingStatus.ACTIVE,
            scenario_id="enterprise_cloud_hybrid_scenario",
        )
        db.add_all([ent_finding_gw, ent_finding_web, ent_finding_k8s, ent_finding_idp, ent_finding_db])

        # Enterprise Edges (Multi-Hop Attack Graph)
        ent_edges = [
            Edge(
                id="ent-edge-gw-to-f1",
                source_id="ent-asset-api-gw",
                target_id="ent-finding-gw-log4j",
                edge_type=EdgeType.CAN_REACH,
                port=8443,
                protocol="TCP",
                traversal_cost=1.0,
                probability=0.95,
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            Edge(
                id="ent-edge-f1-to-k8s",
                source_id="ent-finding-gw-log4j",
                target_id="ent-asset-k8s-node",
                edge_type=EdgeType.EXPLOITS,
                port=8080,
                protocol="TCP",
                traversal_cost=1.5,
                probability=0.85,
                finding_id="ent-finding-gw-log4j",
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            Edge(
                id="ent-edge-web-to-f2",
                source_id="ent-asset-dmz-web",
                target_id="ent-finding-web-spring",
                edge_type=EdgeType.CAN_REACH,
                port=443,
                protocol="TCP",
                traversal_cost=1.0,
                probability=0.9,
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            Edge(
                id="ent-edge-f2-to-k8s",
                source_id="ent-finding-web-spring",
                target_id="ent-asset-k8s-node",
                edge_type=EdgeType.EXPLOITS,
                port=8080,
                protocol="TCP",
                traversal_cost=2.0,
                probability=0.75,
                finding_id="ent-finding-web-spring",
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            Edge(
                id="ent-edge-k8s-to-f3",
                source_id="ent-asset-k8s-node",
                target_id="ent-finding-k8s-log4j",
                edge_type=EdgeType.CAN_REACH,
                port=8080,
                protocol="TCP",
                traversal_cost=1.0,
                probability=0.85,
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            Edge(
                id="ent-edge-f3-to-idp",
                source_id="ent-finding-k8s-log4j",
                target_id="ent-asset-auth-idp",
                edge_type=EdgeType.EXPLOITS,
                port=22,
                protocol="TCP",
                traversal_cost=2.0,
                probability=0.7,
                finding_id="ent-finding-k8s-log4j",
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            Edge(
                id="ent-edge-idp-to-f4",
                source_id="ent-asset-auth-idp",
                target_id="ent-finding-idp-bypass",
                edge_type=EdgeType.CAN_REACH,
                port=22,
                protocol="TCP",
                traversal_cost=1.0,
                probability=0.8,
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            Edge(
                id="ent-edge-f4-to-db",
                source_id="ent-finding-idp-bypass",
                target_id="ent-asset-core-db",
                edge_type=EdgeType.EXPLOITS,
                port=5432,
                protocol="TCP",
                traversal_cost=2.5,
                probability=0.65,
                finding_id="ent-finding-idp-bypass",
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            Edge(
                id="ent-edge-f4-to-vault",
                source_id="ent-finding-idp-bypass",
                target_id="ent-asset-cloud-vault",
                edge_type=EdgeType.EXPLOITS,
                port=443,
                protocol="TCP",
                traversal_cost=2.0,
                probability=0.7,
                finding_id="ent-finding-idp-bypass",
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            Edge(
                id="ent-edge-k8s-direct-to-db",
                source_id="ent-asset-k8s-node",
                target_id="ent-asset-core-db",
                edge_type=EdgeType.CAN_REACH,
                port=5432,
                protocol="TCP",
                traversal_cost=3.5,
                probability=0.4,
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
        ]
        db.add_all(ent_edges)

        # Enterprise Remediation Actions
        ent_actions = [
            RemediationAction(
                id="ent-rem-patch-gw-log4j",
                title="Upgrade API Gateway Log4j Dependency",
                description="Patch Log4Shell vulnerability on API Gateway to eliminate public exploit path",
                action_type=RemediationActionType.PATCH_VULNERABILITY,
                target_finding_id="ent-finding-gw-log4j",
                estimated_cost=4.0,
                implementation_complexity="LOW",
                downtime_required=False,
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            RemediationAction(
                id="ent-rem-patch-web-spring",
                title="Patch Spring Framework on DMZ Web Tier",
                description="Apply vendor patch for Spring4Shell RCE on customer portal servers",
                action_type=RemediationActionType.PATCH_VULNERABILITY,
                target_finding_id="ent-finding-web-spring",
                estimated_cost=5.0,
                implementation_complexity="MEDIUM",
                downtime_required=True,
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            RemediationAction(
                id="ent-rem-isolate-idp",
                title="Emergency Isolation of IAM Control Node",
                description="Isolate Identity Provider management plane pending credential rotation and key rebuild",
                action_type=RemediationActionType.ISOLATE_ASSET,
                target_asset_id="ent-asset-auth-idp",
                estimated_cost=8.0,
                implementation_complexity="HIGH",
                downtime_required=True,
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            RemediationAction(
                id="ent-rem-block-k8s-direct-db",
                title="Network Policy: Block Direct K8s to Financial DB",
                description="Enforce mTLS and network security group rule preventing direct database access from Kubernetes pods",
                action_type=RemediationActionType.REMOVE_NETWORK_PATH,
                target_edge_id="ent-edge-k8s-direct-to-db",
                estimated_cost=3.0,
                implementation_complexity="LOW",
                downtime_required=False,
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
            RemediationAction(
                id="ent-rem-patch-k8s-log4j",
                title="Patch Container Images on Kubernetes Cluster",
                description="Rebuild microservice base images with secure logging libraries",
                action_type=RemediationActionType.PATCH_VULNERABILITY,
                target_finding_id="ent-finding-k8s-log4j",
                estimated_cost=6.0,
                implementation_complexity="MEDIUM",
                downtime_required=False,
                scenario_id="enterprise_cloud_hybrid_scenario",
            ),
        ]
        for act in ent_actions:
            db.add(act)

        ensure_remediation_seed_data(db)
        
        db.commit()
        print("Seed data created successfully!")
        
    except Exception as e:
        db.rollback()
        print(f"Error creating seed data: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    create_seed_data()
