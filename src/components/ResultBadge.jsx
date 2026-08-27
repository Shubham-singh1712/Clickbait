import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
} from "lucide-react";

function ResultBadge({ status }) {
  const normalized =
    status?.toUpperCase() || "UNVERIFIED";

  if (normalized === "VERIFIED") {
    return (
      <div className="result-badge verified">
        <CheckCircle2 size={22} />
        VERIFIED
      </div>
    );
  }

  if (
    normalized === "HIGH_RISK" ||
    normalized === "HIGH RISK"
  ) {
    return (
      <div className="result-badge high-risk">
        <XCircle size={22} />
        HIGH RISK
      </div>
    );
  }

  return (
    <div className="result-badge unverified">
      <AlertTriangle size={22} />
      UNVERIFIED
    </div>
  );
}

export default ResultBadge;