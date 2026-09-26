import React, { useState } from "react";
import { FolderIcon, FileTextIcon, ChevronRightIcon, ChevronDownIcon, DatabaseIcon, LockIcon } from "../icons.jsx";
import { EmptyState } from "./common.jsx";

function TreeNode({ name, node, depth }) {
  const [open, setOpen] = useState(depth < 1);
  const folders = Object.keys(node).filter((k) => k !== "__files__");
  const files = node.__files__ || [];
  const hasChildren = folders.length > 0 || files.length > 0;

  return (
    <div className="tree-node" style={{ marginLeft: depth === 0 ? 0 : 14 }}>
      {name && (
        <button className="tree-node-label" onClick={() => setOpen((v) => !v)}>
          {hasChildren ? (open ? <ChevronDownIcon size={12} /> : <ChevronRightIcon size={12} />) : <span style={{ width: 12 }} />}
          <FolderIcon size={13} /> {name}
        </button>
      )}
      {(open || !name) && (
        <div>
          {folders.sort().map((f) => <TreeNode key={f} name={f} node={node[f]} depth={depth + 1} />)}
          {files.sort().map((f) => (
            <div key={f} className="tree-file" style={{ marginLeft: (depth + 1) * 14 }}>
              <FileTextIcon size={12} /> {f}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function RepositoryInventory({ inventory, structure }) {
  if (!inventory) return <EmptyState title="No inventory yet" />;

  const chips = [
    ...inventory.frameworks.map((f) => ({ label: f, tone: "cyan" })),
    ...inventory.datastores.map((f) => ({ label: f, tone: "purple", icon: <DatabaseIcon size={11} /> })),
  ];

  return (
    <div className="inventory-panel">
      <div className="inventory-summary">
        <div className="inventory-stat"><span className="ai-panel-label">Total files</span><span className="ai-panel-strong">{inventory.total_files}</span></div>
        <div className="inventory-stat"><span className="ai-panel-label">API routes</span><span className="ai-panel-strong">{inventory.api_routes.length}</span></div>
        <div className="inventory-stat"><span className="ai-panel-label">Sensitive files</span><span className="ai-panel-strong">{inventory.sensitive_files.length}</span></div>
        <div className="inventory-stat"><span className="ai-panel-label">Auth-related files</span><span className="ai-panel-strong">{inventory.auth_files.length}</span></div>
      </div>

      {chips.length > 0 && (
        <div className="inventory-chips">
          {chips.map((c, i) => (
            <span key={i} className={`inventory-chip tone-${c.tone}`}>{c.icon} {c.label}</span>
          ))}
        </div>
      )}

      {inventory.api_routes.length > 0 && (
        <div className="inventory-routes">
          <span className="ai-panel-label">Detected routes</span>
          {inventory.api_routes.slice(0, 8).map((r, i) => (
            <div key={i} className="inventory-route">
              <span className="route-method">{r.method}</span>
              <code>{r.path}</code>
              <span className="route-file">{r.file}</span>
            </div>
          ))}
        </div>
      )}

      {inventory.env_files.length > 0 && (
        <div className="inventory-warning">
          <LockIcon size={13} /> {inventory.env_files.length} environment file(s) detected — verify these aren't committed with real secrets.
        </div>
      )}

      <div className="inventory-tree-wrap">
        <span className="ai-panel-label">Detected file structure</span>
        {structure ? <TreeNode name="" node={structure.tree} depth={0} /> : <EmptyState title="Loading structure…" />}
      </div>
    </div>
  );
}
