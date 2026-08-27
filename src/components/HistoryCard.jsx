import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
} from "lucide-react";

function HistoryCard({ item }) {
  const status =
    item.verification_status?.toUpperCase();

  const verified =
    status === "VERIFIED";

  const highRisk =
    status === "HIGH_RISK" ||
    status === "HIGH RISK";

  const Icon = verified
    ? CheckCircle2
    : highRisk
    ? XCircle
    : AlertTriangle;

  const statusClass = verified
    ? "history-verified"
    : highRisk
    ? "history-danger"
    : "history-warning";

  return (
    <div className="history-card">

      <div className={`history-icon ${statusClass}`}>
        <Icon size={21} />
      </div>

      <div className="history-main">
        <strong>
          {item.claimed_issuer ||
            "Unknown Communication"}
        </strong>

        <span>
          {item.explanation ||
            "Verification completed."}
        </span>

        <small>
          <Clock size={13} />

          {item.createdAt
            ? new Date(
                item.createdAt
              ).toLocaleString()
            : "Recently"}
        </small>
      </div>

      <div className={`history-status ${statusClass}`}>
        {verified
          ? "VERIFIED"
          : highRisk
          ? "HIGH RISK"
          : "UNVERIFIED"}
      </div>

    </div>
  );
}

export default HistoryCard;