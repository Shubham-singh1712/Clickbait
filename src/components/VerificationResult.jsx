import {
  Check,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  KeyRound,
  Database,
} from "lucide-react";

import ResultBadge from "./ResultBadge";

function VerificationResult({ result }) {
  if (!result) {
    return null;
  }

  const status =
    result.verification_status?.toUpperCase();

  const highRisk =
    status === "HIGH_RISK" ||
    status === "HIGH RISK";

  const verified =
    status === "VERIFIED";

  const indicators =
    result.indicators || [];

  return (
    <div className="result-container">

      <div
        className={`result-hero ${
          verified
            ? "result-verified"
            : highRisk
            ? "result-danger"
            : "result-warning"
        }`}
      >
        <div className="result-icon-large">
          {verified ? (
            <ShieldCheck size={42} />
          ) : highRisk ? (
            <ShieldAlert size={42} />
          ) : (
            <AlertTriangle size={42} />
          )}
        </div>

        <ResultBadge status={status} />

        <h1>
          {verified
            ? "Authentic Communication"
            : highRisk
            ? "Potentially Malicious Communication"
            : "Communication Could Not Be Confirmed"}
        </h1>

        <p>
          {result.explanation}
        </p>
      </div>

      <div className="result-grid">

        <div className="result-card">
          <div className="result-card-heading">
            <KeyRound size={19} />
            Issuer
          </div>

          <strong>
            {result.claimed_issuer || "Unknown"}
          </strong>
        </div>

        <div className="result-card">
          <div className="result-card-heading">
            <ShieldCheck size={19} />
            Signature
          </div>

          <strong>
            {result.signature_valid
              ? "Valid"
              : "Not Valid / Missing"}
          </strong>
        </div>

        <div className="result-card">
          <div className="result-card-heading">
            <Database size={19} />
            Integrity
          </div>

          <strong>
            {result.integrity_valid
              ? "Valid"
              : "Cannot Confirm"}
          </strong>
        </div>

        <div className="result-card">
          <div className="result-card-heading">
            <Clock size={19} />
            Notice Status
          </div>

          <strong>
            {result.notice_status || "UNKNOWN"}
          </strong>
        </div>

      </div>

      {indicators.length > 0 && (
        <div className="threat-card">
          <div className="section-title">
            <ShieldAlert size={21} />
            Threat Indicators
          </div>

          <div className="indicator-list">
            {indicators.map((indicator, index) => (
              <div
                className="indicator"
                key={`${indicator}-${index}`}
              >
                <span className="indicator-dot" />
                {indicator}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="recommendation-card">
        <div className="section-title">
          <AlertTriangle size={21} />
          Recommended Action
        </div>

        <p>
          {result.recommended_action ||
            "Verify the communication directly with the claimed institution before taking action."}
        </p>
      </div>

      {verified && (
        <div className="success-note">
          <Check size={18} />
          This communication passed the available
          verification checks.
        </div>
      )}

      {highRisk && (
        <div className="danger-note">
          <ShieldAlert size={18} />
          Do not click suspicious links or provide
          passwords, OTPs or financial information.
        </div>
      )}

    </div>
  );
}

export default VerificationResult;