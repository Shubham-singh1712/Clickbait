import {
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Activity,
  ArrowRight,
} from "lucide-react";

import { Link } from "react-router-dom";

import {
  useVerification,
} from "../context/VerificationContext";

function Dashboard() {
  const { history } = useVerification();

  const verifiedCount =
    history.filter(
      (item) =>
        item.verification_status ===
        "VERIFIED"
    ).length;

  const unverifiedCount =
    history.filter(
      (item) =>
        item.verification_status ===
        "UNVERIFIED"
    ).length;

  const highRiskCount =
    history.filter(
      (item) =>
        item.verification_status ===
          "HIGH_RISK" ||
        item.verification_status ===
          "HIGH RISK"
    ).length;

  return (
    <div className="page">

      <div className="page-header">

        <div className="orange-label">
          STUDENT SECURITY
        </div>

        <h1>
          Security Dashboard
        </h1>

        <p>
          A quick overview of your recent
          communication verification activity.
        </p>

      </div>

      <div className="stats-grid">

        <div className="stat-card stat-green">
          <div className="stat-icon">
            <CheckCircle2 />
          </div>

          <span>
            Verified
          </span>

          <strong>
            {verifiedCount}
          </strong>
        </div>

        <div className="stat-card stat-yellow">
          <div className="stat-icon">
            <AlertTriangle />
          </div>

          <span>
            Unverified
          </span>

          <strong>
            {unverifiedCount}
          </strong>
        </div>

        <div className="stat-card stat-red">
          <div className="stat-icon">
            <ShieldAlert />
          </div>

          <span>
            High Risk
          </span>

          <strong>
            {highRiskCount}
          </strong>
        </div>

        <div className="stat-card stat-orange">
          <div className="stat-icon">
            <Activity />
          </div>

          <span>
            Total Checks
          </span>

          <strong>
            {history.length}
          </strong>
        </div>

      </div>

      <div className="dashboard-grid">

        <div className="dashboard-card">

          <div className="dashboard-card-title">
            <h2>
              Security Principle
            </h2>
          </div>

          <p>
            CLICKBAIT treats cryptographic
            verification as the primary
            authenticity mechanism.
          </p>

          <p>
            AI risk analysis acts as a secondary
            layer when a communication is
            unverified or suspicious.
          </p>

          <div className="principle-box">
            <strong>
              Don't Guess. Verify.
            </strong>

            <span>
              Authenticity should be established
              through verifiable evidence.
            </span>
          </div>

        </div>

        <div className="dashboard-card">

          <div className="dashboard-card-title">
            <h2>
              Quick Actions
            </h2>
          </div>

          <Link
            to="/verify"
            className="quick-action"
          >
            <span>
              Verify a communication
            </span>

            <ArrowRight size={18} />
          </Link>

          <Link
            to="/history"
            className="quick-action"
          >
            <span>
              View verification history
            </span>

            <ArrowRight size={18} />
          </Link>

        </div>

      </div>

    </div>
  );
}

export default Dashboard;