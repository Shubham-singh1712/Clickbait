import { useNavigate } from "react-router-dom";
import {
  ShieldCheck,
  Lock,
  ScanSearch,
} from "lucide-react";

import VerificationInput from "../components/VerificationInput";

import {
  useVerification,
} from "../context/VerificationContext";

import {
  verifyNotice,
  verifyScreenshot,
} from "../services/api";

function Verify() {
  const navigate = useNavigate();

  const {
    loading,
    setLoading,
    addHistory,
  } = useVerification();

  const handleVerify = async ({
    type,
    payload,
    file,
  }) => {
    setLoading(true);

    try {
      let response;

      if (type === "screenshot") {
        response =
          await verifyScreenshot(file);
      } else {
        response =
          await verifyNotice(payload);
      }

      const result = addHistory(response);

      navigate("/result", {
        state: {
          result,
        },
      });
    } catch (error) {
      const result = addHistory({
        verification_status: "UNVERIFIED",
        risk_level: "UNKNOWN",
        claimed_issuer: "Verification Service",
        signature_valid: false,
        integrity_valid: false,
        notice_status: "ERROR",
        indicators: [
          "Verification service unavailable",
        ],
        explanation:
          error.message ||
          "The verification service could not process the request.",
        recommended_action:
          "Try again or verify the communication directly with the institution.",
      });

      navigate("/result", {
        state: {
          result,
        },
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page verify-page">

      <div className="verify-heading">

        <div className="hero-badge">
          <span className="pulse-dot" />
          SECURE VERIFICATION
        </div>

        <h1>
          Check a Communication
        </h1>

        <p>
          Submit the communication using
          any of the options below.
        </p>

      </div>

      <VerificationInput
        onVerify={handleVerify}
        loading={loading}
      />

      <div className="privacy-strip">

        <Lock size={19} />

        <div>
          <strong>
            Privacy-first verification
          </strong>

          <span>
            Student personal information should
            never be placed on the blockchain
            registry.
          </span>
        </div>

      </div>

      <div className="verification-note">

        <ScanSearch size={20} />

        <p>
          CLICKBAIT uses cryptographic verification
          as the primary authenticity mechanism.
          AI risk analysis is a secondary layer for
          suspicious or unverified content.
        </p>

      </div>

    </div>
  );
}

export default Verify;