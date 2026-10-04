import { useState } from 'react';
import { Network, RefreshCw, Layers } from 'lucide-react';
import { useScenario } from '../../context/ScenarioContext';
import { useScenarioGraph } from './useScenarioGraph';
import { CytoscapeCanvas, EMPTY_HIGHLIGHT } from './CytoscapeCanvas';
import { SelectionDetails } from './SelectionDetails';
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingSpinner,
  PageHeader,
  StatCard,
} from '../../components/ui';

export function GraphPage() {
  const { selectedScenario } = useScenario();
  const scenarioId = selectedScenario?.id;
  const { data: graphData, isLoading, error, retry } = useScenarioGraph(scenarioId);

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  if (!selectedScenario) {
    return (
      <div className="space-y-6">
        <PageHeader title="Security Graph" />
        <Card>
          <CardBody>
            <EmptyState
              title="No Scenario Selected"
              description="Select a scenario from the header dropdown to view the canonical security graph."
            />
          </CardBody>
        </Card>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Security Graph" />
        <div className="flex items-center justify-center min-h-[400px]">
          <LoadingSpinner size="lg" />
        </div>
      </div>
    );
  }

  if (error || !graphData) {
    return (
      <div className="space-y-6">
        <PageHeader title="Security Graph" />
        <Card>
          <CardBody>
            <ErrorState
              title="Failed to Load Security Graph"
              description={error || 'Unknown error occurred'}
              action={
                <Button variant="primary" onClick={retry}>
                  Retry
                </Button>
              }
            />
          </CardBody>
        </Card>
      </div>
    );
  }

  const nodeCount = graphData.metadata?.node_count ?? graphData.elements.nodes.length;
  const edgeCount = graphData.metadata?.edge_count ?? graphData.elements.edges.length;
  const assetNodes = graphData.elements.nodes.filter((n) => n.data.type === 'asset' || n.data.asset_type);
  const findingNodes = graphData.elements.nodes.filter((n) => n.data.type === 'finding' || n.data.vulnerability_id);
  const entryPointNodes = graphData.elements.nodes.filter((n) => n.data.is_entry_point);
  const crownJewelNodes = graphData.elements.nodes.filter((n) => n.data.is_crown_jewel);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Graph"
        description={`Canonical multi-hop attack topology for ${selectedScenario.name}`}
        actions={
          <>
            <Badge variant="info">
              {nodeCount} nodes · {edgeCount} edges
            </Badge>
            <Button variant="secondary" size="sm" onClick={retry}>
              <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
              Refresh Graph
            </Button>
          </>
        }
      />

      {/* Graph Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Nodes"
          value={nodeCount}
          hint={`${assetNodes.length} assets · ${findingNodes.length} findings`}
          icon={<Network className="w-4 h-4" />}
        />
        <StatCard
          label="Attack Edges"
          value={edgeCount}
          hint="Directed transitions"
          icon={<Layers className="w-4 h-4" />}
        />
        <StatCard
          label="Entry Points"
          value={entryPointNodes.length}
          hint="Attacker initial access"
          tone="warning"
        />
        <StatCard
          label="Crown Jewels"
          value={crownJewelNodes.length}
          hint="High-value target assets"
          tone="danger"
        />
      </div>

      {/* Main Canvas & Inspector Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        <div className="lg:col-span-2">
          <Card className="overflow-hidden">
            <CardHeader>
              <div className="flex items-center justify-between">
                <h2 className="section-title">Interactive Topology Visualizer</h2>
                <span className="text-xs text-[var(--color-text-muted)]">
                  Click a node or edge to inspect details
                </span>
              </div>
            </CardHeader>
            <CardBody className="p-0">
              <CytoscapeCanvas
                graph={graphData}
                highlight={EMPTY_HIGHLIGHT}
                selectedNodeId={selectedNodeId}
                selectedEdgeId={selectedEdgeId}
                onNodeSelect={(id) => {
                  setSelectedNodeId(id);
                  if (id) setSelectedEdgeId(null);
                }}
                onEdgeSelect={(id) => {
                  setSelectedEdgeId(id);
                  if (id) setSelectedNodeId(null);
                }}
                height={620}
              />
            </CardBody>
          </Card>
        </div>

        {/* Node/Edge Inspector Sidebar */}
        <div>
          {selectedNodeId || selectedEdgeId ? (
            <SelectionDetails
              graph={graphData}
              nodeId={selectedNodeId}
              edgeId={selectedEdgeId}
              onClose={() => {
                setSelectedNodeId(null);
                setSelectedEdgeId(null);
              }}
            />
          ) : (
            <Card>
              <CardHeader>
                <h2 className="section-title">Element Inspector</h2>
              </CardHeader>
              <CardBody>
                <p className="text-sm text-[var(--color-text-muted)]">
                  Select any asset, finding, or edge in the graph canvas to inspect its properties, network attributes, CVSS metrics, and reachability.
                </p>
              </CardBody>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
