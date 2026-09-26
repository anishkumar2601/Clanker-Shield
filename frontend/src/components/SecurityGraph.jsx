import React, { useMemo, useState } from "react";
import { EmptyState } from "./common.jsx";
import { NetworkIcon } from "../icons.jsx";

const COLUMN_ORDER = ["route", "evidence", "finding", "auth", "database", "configuration", "impact"];
const KIND_LABEL = { route: "Routes", evidence: "Observed evidence", finding: "Findings", auth: "Authentication", database: "Database", configuration: "Configuration", impact: "Potential impact" };
const KIND_COLOR = { route: "var(--cyan)", evidence: "var(--green)", finding: "var(--red)", auth: "var(--purple)", database: "var(--cyan)", configuration: "var(--amber)", impact: "var(--ink-2)" };

export default function SecurityGraph({ graph, onSelectFinding }) {
  const [hovered, setHovered] = useState(null);

  const layout = useMemo(() => {
    if (!graph || !graph.nodes?.length) return null;
    const columns = { route: [], evidence: [], finding: [], auth: [], database: [], configuration: [], impact: [] };
    for (const n of graph.nodes) (columns[n.kind] || columns.finding).push(n);

    const activeColumns = COLUMN_ORDER.filter((k) => columns[k].length > 0);
    const colWidth = 900 / Math.max(activeColumns.length, 1);
    const positions = {};
    activeColumns.forEach((kind, ci) => {
      const nodes = columns[kind];
      const rowHeight = Math.max(360 / Math.max(nodes.length, 1), 46);
      nodes.forEach((n, ri) => {
        positions[n.id] = {
          x: colWidth * ci + colWidth / 2,
          y: rowHeight * ri + rowHeight / 2 + 20,
          kind,
          node: n,
        };
      });
    });
    return { positions, width: colWidth * activeColumns.length, height: 400, activeColumns };
  }, [graph]);

  if (!layout) {
    return <EmptyState icon={<NetworkIcon size={22} />} title="No graph yet" detail="Run a scan to build the security graph." />;
  }

  return (
    <div className="security-graph">
      <svg viewBox={`0 0 ${layout.width} ${layout.height}`} className="graph-svg" role="img" aria-label="Security graph">
        {graph.edges.map((edge, i) => {
          const from = layout.positions[edge.from];
          const to = layout.positions[edge.to];
          if (!from || !to) return null;
          const dim = hovered && hovered !== edge.from && hovered !== edge.to;
          return (
            <g key={i}>
              <title>{`${edge.evidence_status || "INFERRED"}: ${edge.reason || edge.label || "relationship"}${edge.file ? ` · ${edge.file}:${edge.line}` : ""}`}</title>
              <path
                d={`M${from.x},${from.y} C${(from.x + to.x) / 2},${from.y} ${(from.x + to.x) / 2},${to.y} ${to.x},${to.y}`}
                className={`graph-edge graph-edge-${String(edge.evidence_status || "inferred").toLowerCase()} ${dim ? "graph-edge-dim" : ""}`}
              />
            </g>
          );
        })}
        {Object.values(layout.positions).map(({ x, y, kind, node }) => (
          <g
            key={node.id}
            transform={`translate(${x},${y})`}
            className="graph-node"
            onMouseEnter={() => setHovered(node.id)}
            onMouseLeave={() => setHovered(null)}
            onClick={() => kind === "finding" && onSelectFinding?.(node)}
            style={{ cursor: kind === "finding" ? "pointer" : "default" }}
          >
            <circle r={kind === "finding" ? 7 : 9} fill={KIND_COLOR[kind]} opacity={kind === "finding" && node.severity !== "critical" && node.severity !== "high" ? 0.55 : 0.95} />
            <text y={22} textAnchor="middle" className="graph-node-label">
              {node.label.length > 20 ? node.label.slice(0, 19) + "…" : node.label}
            </text>
          </g>
        ))}
      </svg>
      <div className="graph-legend">
        {layout.activeColumns.map((kind) => (
          <span key={kind} className="graph-legend-item">
            <span className="graph-legend-dot" style={{ background: KIND_COLOR[kind] }} />
            {KIND_LABEL[kind]}
          </span>
        ))}
      </div>
    </div>
  );
}
