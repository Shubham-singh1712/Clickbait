import { Link } from "react-router-dom";
import {
  ShieldCheck,
  ScanSearch,
  LockKeyhole,
  FileWarning,
  ArrowRight,
  CheckCircle2,
} from "lucide-react";

function Home() {
  return (
    <div className="page home-page">

      <section className="hero">

        <div className="hero-badge">
          <span className="pulse-dot" />
          STUDENT SECURITY PLATFORM
        </div>

        <h1>
          Verify Before
          <br />
          <span>You Trust.</span>
        </h1>

        <p className="hero-description">
          CLICKBAIT helps students determine whether
          internships, scholarships, exam circulars,
          fee notices and other digital communications
          can be trusted.
        </p>

        <div className="hero-actions">
          <Link
            to="/verify"
            className="primary-button"
          >
            Start Verification
            <ArrowRight size={19} />
          </Link>

          <Link
            to="/dashboard"
            className="secondary-button"
          >
            View Dashboard
          </Link>
        </div>

        <div className="trust-points">

          <div>
            <CheckCircle2 size={17} />
            Cryptographic verification
          </div>

          <div>
            <CheckCircle2 size={17} />
            AI-assisted risk analysis
          </div>

          <div>
            <CheckCircle2 size={17} />
            Privacy-first design
          </div>

        </div>

      </section>

      <section className="features-section">

        <div className="section-header">
          <span className="orange-label">
            HOW IT WORKS
          </span>

          <h2>
            One place to check suspicious
            communications.
          </h2>
        </div>

        <div className="feature-grid">

          <div className="feature-card">
            <div className="feature-icon">
              <ScanSearch />
            </div>

            <h3>
              Submit
            </h3>

            <p>
              Paste a message, enter a URL or
              upload a screenshot.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <LockKeyhole />
            </div>

            <h3>
              Verify
            </h3>

            <p>
              The system checks institutional
              authenticity and integrity.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <FileWarning />
            </div>

            <h3>
              Understand
            </h3>

            <p>
              Receive a clear result and
              actionable security guidance.
            </p>
          </div>

        </div>

      </section>

      <section className="status-section">

        <div className="status-card green-card">
          <div className="status-symbol">
            <ShieldCheck />
          </div>

          <div>
            <strong>VERIFIED</strong>
            <span>
              Authentic communication
            </span>
          </div>
        </div>

        <div className="status-card yellow-card">
          <div className="status-symbol">
            <ShieldCheck />
          </div>

          <div>
            <strong>UNVERIFIED</strong>
            <span>
              Could not be confirmed
            </span>
          </div>
        </div>

        <div className="status-card red-card">
          <div className="status-symbol">
            <FileWarning />
          </div>

          <div>
            <strong>HIGH RISK</strong>
            <span>
              Potentially malicious
            </span>
          </div>
        </div>

      </section>

    </div>
  );
}

export default Home;