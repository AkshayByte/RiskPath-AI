"""Canonical security graph endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.graph.builder import build_canonical_graph
from backend.app.graph.validators import validate_graph

router = APIRouter(prefix="/api/scenarios/{scenario_id}/graph", tags=["Graph"])


@router.get("")
async def get_scenario_graph(scenario_id: str, db: Session = Depends(get_db)):
    """
    Get the canonical security graph for a scenario in Cytoscape-compatible format.
    """
    graph = build_canonical_graph(db, scenario_id)
    
    nodes = []
    edges = []
    
    for node_id, node_data in graph.nodes(data=True):
        cyto_node = {
            "data": {
                "id": node_id,
                **{k: v for k, v in node_data.items() if k != 'type'}
            }
        }
        nodes.append(cyto_node)
    
    for source, target, edge_data in graph.edges(data=True):
        cyto_edge = {
            "data": {
                "id": edge_data.get('edge_id', f"{source}-{target}"),
                "source": source,
                "target": target,
                **{k: v for k, v in edge_data.items() if k not in ['source_id', 'target_id', 'type']}
            }
        }
        edges.append(cyto_edge)
    
    elements = {
        "nodes": nodes,
        "edges": edges
    }
    
    cypher_data = {
        "elements": elements,
        "metadata": {
            "scenario_id": scenario_id,
            "node_count": graph.number_of_nodes(),
            "edge_count": graph.number_of_edges(),
            "builder_stats": {}
        }
    }
    
    return cypher_data


@router.post("/validate")
async def validate_scenario_graph(scenario_id: str, db: Session = Depends(get_db)):
    """
    Validate the canonical security graph for a scenario.
    """
    try:
        graph = build_canonical_graph(db, scenario_id)
        is_valid, errors = validate_graph(graph)
        
        if is_valid:
            return {"valid": True, "message": "Graph is valid"}
        else:
            return {"valid": False, "errors": errors}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to validate graph: {str(e)}"
        )
