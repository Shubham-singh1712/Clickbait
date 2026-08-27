import { Link, useLocation } from "react-router-dom";
import {
  ArrowLeft,
  RotateCcw,
} from "lucide-react";

import VerificationResult from "../components/VerificationResult";

import {
  useVerification,
} from "../context/VerificationContext";

function Result() {
  const location = useLocation();

  const {
    result: contextResult,
  } = useVerification();

  const result =
    location.state?.result ||
    contextResult;

  if (!result) {
    return (
      <div className="empty-page">

        <h1>
          No Verification Result
        </h1>

        <p>
          Start by submitting a communication
          for verification.
        </p>

        <Link
          to="/verify"
          className="primary-button"
        >
          Start Verification
        </Link>

      </div>
    );
  }

  return (
    <div className="page result-page">

      <div className="result-navigation">

        <Link
          to="/verify"
          className="back-link"
        >
          <ArrowLeft size={17} />
          Verify Another
        </Link>

        <Link
          to="/history"
          className="secondary-button small"
        >
          <RotateCcw size={16} />
          View History
        </Link>

      </div>

      <VerificationResult
        result={result}
      />

    </div>
  );
}

export default Result;