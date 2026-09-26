// Small, dependency-free SVG icon set. Every icon accepts `size` and
// standard SVG props (className, style) so it can inherit color via
// `currentColor` and be styled from CSS.
import React from "react";

const base = (props) => ({
  width: props.size || 18,
  height: props.size || 18,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: props.strokeWidth || 1.8,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  ...props,
});

export const ShieldIcon = (p) => (
  <svg {...base(p)}><path d="M12 3l7 3v6c0 4.6-3 8.4-7 9-4-.6-7-4.4-7-9V6l7-3z" /></svg>
);
export const ShieldCheckIcon = (p) => (
  <svg {...base(p)}><path d="M12 3l7 3v6c0 4.6-3 8.4-7 9-4-.6-7-4.4-7-9V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>
);
export const AlertTriangleIcon = (p) => (
  <svg {...base(p)}><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" /><path d="M12 9v4" /><path d="M12 17h.01" /></svg>
);
export const AlertOctagonIcon = (p) => (
  <svg {...base(p)}><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86L7.86 2z" /><path d="M12 8v5" /><path d="M12 16h.01" /></svg>
);
export const BugIcon = (p) => (
  <svg {...base(p)}><rect x="8" y="7" width="8" height="12" rx="4" /><path d="M8 12H4M20 12h-4M9 7 7 4M15 7l2-3M9 18l-2 3M15 18l2 3M12 7V4" /></svg>
);
export const LockIcon = (p) => (
  <svg {...base(p)}><rect x="4" y="11" width="16" height="9" rx="2" /><path d="M8 11V7a4 4 0 018 0v4" /></svg>
);
export const UnlockIcon = (p) => (
  <svg {...base(p)}><rect x="4" y="11" width="16" height="9" rx="2" /><path d="M8 11V7a4 4 0 017.5-2" /></svg>
);
export const DatabaseIcon = (p) => (
  <svg {...base(p)}><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5" /><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" /></svg>
);
export const FileTextIcon = (p) => (
  <svg {...base(p)}><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><path d="M14 2v6h6" /><path d="M9 13h6M9 17h6M9 9h1" /></svg>
);
export const UploadIcon = (p) => (
  <svg {...base(p)}><path d="M12 16V4M7 9l5-5 5 5" /><path d="M4 16v3a2 2 0 002 2h12a2 2 0 002-2v-3" /></svg>
);
export const RefreshIcon = (p) => (
  <svg {...base(p)}><path d="M21 12a9 9 0 10-2.6 6.4" /><path d="M21 5v6h-6" /></svg>
);
export const SearchIcon = (p) => (
  <svg {...base(p)}><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" /></svg>
);
export const ChevronRightIcon = (p) => (
  <svg {...base(p)}><path d="M9 18l6-6-6-6" /></svg>
);
export const ChevronDownIcon = (p) => (
  <svg {...base(p)}><path d="M6 9l6 6 6-6" /></svg>
);
export const XIcon = (p) => (
  <svg {...base(p)}><path d="M18 6L6 18M6 6l12 12" /></svg>
);
export const SparkleIcon = (p) => (
  <svg {...base(p)}><path d="M12 3l1.6 4.9L18.5 9l-4.9 1.6L12 15.5l-1.6-4.9L5.5 9l4.9-1.6L12 3z" /><path d="M19 15l.7 2.1L22 18l-2.3.9L19 21l-.7-2.1L16 18l2.3-.9L19 15z" /></svg>
);
export const NetworkIcon = (p) => (
  <svg {...base(p)}><circle cx="12" cy="5" r="2.2" /><circle cx="5" cy="19" r="2.2" /><circle cx="19" cy="19" r="2.2" /><path d="M12 7.2V12M12 12L6.6 17.2M12 12l5.4 5.2" /></svg>
);
export const LayersIcon = (p) => (
  <svg {...base(p)}><path d="M12 3l9 5-9 5-9-5 9-5z" /><path d="M3 13l9 5 9-5" /></svg>
);
export const CpuIcon = (p) => (
  <svg {...base(p)}><rect x="7" y="7" width="10" height="10" rx="2" /><rect x="2" y="10" width="3" height="4" /><rect x="19" y="10" width="3" height="4" /><rect x="10" y="2" width="4" height="3" /><rect x="10" y="19" width="4" height="3" /></svg>
);
export const ClipboardIcon = (p) => (
  <svg {...base(p)}><rect x="6" y="4" width="12" height="17" rx="2" /><rect x="9" y="2" width="6" height="4" rx="1" /><path d="M9 11h6M9 15h6" /></svg>
);
export const ArrowUpRightIcon = (p) => (
  <svg {...base(p)}><path d="M7 17L17 7M8 7h9v9" /></svg>
);
export const CheckIcon = (p) => (
  <svg {...base(p)}><path d="M5 13l4 4L19 7" /></svg>
);
export const SendIcon = (p) => (
  <svg {...base(p)}><path d="M22 2L11 13" /><path d="M22 2l-7 20-4-9-9-4 20-7z" /></svg>
);
export const FolderIcon = (p) => (
  <svg {...base(p)}><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" /></svg>
);
export const MenuIcon = (p) => (
  <svg {...base(p)}><path d="M4 7h16M4 12h16M4 17h16" /></svg>
);
export const GaugeIcon = (p) => (
  <svg {...base(p)}><path d="M4.5 19a9 9 0 1115 0" /><path d="M12 12l3-3" /></svg>
);
export const KeyIcon = (p) => (
  <svg {...base(p)}><circle cx="8" cy="14" r="4" /><path d="M11 11l9-9M17 5l2 2M14 8l2 2" /></svg>
);
