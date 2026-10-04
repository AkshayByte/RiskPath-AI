import json
import uuid
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_synthetic_scenario_generation():
    sc_id = f"test_synth_{uuid.uuid4().hex[:6]}"
    response = client.post(
        "/api/scenarios/generate-synthetic",
        json={
            "scenario_id": sc_id,
            "name": "API Synth Graph",
            "asset_count": 20,
            "entry_point_ratio": 0.1,
            "crown_jewel_ratio": 0.1
        }
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["scenario_id"] == sc_id
    assert data["asset_count"] == 20
    assert data["entry_points"] >= 1
    assert data["crown_jewels"] >= 1


def test_benchmark_endpoint():
    sc_id = f"test_bench_{uuid.uuid4().hex[:6]}"
    # First generate synthetic scenario
    gen_res = client.post(
        "/api/scenarios/generate-synthetic",
        json={
            "scenario_id": sc_id,
            "name": "Benchmark Graph",
            "asset_count": 15,
            "entry_point_ratio": 0.15,
            "crown_jewel_ratio": 0.15
        }
    )
    assert gen_res.status_code == 200, gen_res.text

    response = client.get(f"/api/scenarios/{sc_id}/benchmark?budget=20.0")
    assert response.status_code == 200, response.text
    data = response.json()
    assert "cvss_strategy" in data
    assert "context_aware_strategy" in data
    assert "comparison" in data
    assert data["scenario_id"] == sc_id


def test_trivy_import_endpoint():
    sc_id = f"test_trivy_{uuid.uuid4().hex[:6]}"
    sample_trivy = {
        "SchemaVersion": 2,
        "ArtifactName": "nginx:latest",
        "Results": [
            {
                "Target": "nginx:latest (debian 12.0)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1111",
                        "PkgName": "libssl3",
                        "InstalledVersion": "3.0.9-1",
                        "FixedVersion": "3.0.9-1+deb12u1",
                        "Title": "Buffer overflow in OpenSSL",
                        "Description": "Memory corruption flaw in TLS handshake",
                        "Severity": "HIGH",
                        "CVSS": {
                            "nvd": {
                                "V3Score": 8.8
                            }
                        }
                    }
                ]
            }
        ]
    }
    response = client.post(
        f"/api/scenarios/{sc_id}/import/trivy",
        json={
            "content": json.dumps(sample_trivy),
            "scenario_name": "Trivy Test Import"
        }
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["assets_imported"] == 1
    assert data["vulnerabilities_imported"] == 1
    assert data["findings_imported"] == 1


def test_nessus_csv_import_endpoint():
    sc_id = f"test_nessus_{uuid.uuid4().hex[:6]}"
    sample_nessus = """Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Name,Synopsis
10110,CVE-2023-9999,9.8,Critical,192.168.1.50,Apache RCE Vulnerability,Remote code execution vulnerability in Apache server
10111,CVE-2023-8888,7.5,High,192.168.1.50,SSH Weak Ciphers,SSH server allows weak ciphers
"""
    response = client.post(
        f"/api/scenarios/{sc_id}/import/nessus",
        json={
            "content": sample_nessus,
            "scenario_name": "Nessus Test Import"
        }
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["assets_imported"] == 1
    assert data["vulnerabilities_imported"] == 2
    assert data["findings_imported"] == 2
