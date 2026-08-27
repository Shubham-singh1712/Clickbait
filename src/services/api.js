const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "";

const DEMO_MODE =
  import.meta.env.VITE_DEMO_MODE !== "false";

async function parseResponse(response) {
  const contentType =
    response.headers.get("content-type") || "";

  const data = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    throw new Error(
      data?.message ||
      data?.error ||
      "Verification request failed."
    );
  }

  return data;
}

export async function verifyNotice(payload) {
  if (DEMO_MODE || !API_BASE_URL) {
    return demoVerify(payload);
  }

  const response = await fetch(
    `${API_BASE_URL}/api/verify`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }
  );

  return parseResponse(response);
}

export async function verifyScreenshot(file) {
  if (DEMO_MODE || !API_BASE_URL) {
    return demoScreenshotVerify(file);
  }

  const formData = new FormData();

  formData.append("screenshot", file);

  const response = await fetch(
    `${API_BASE_URL}/api/verify/screenshot`,
    {
      method: "POST",
      body: formData,
    }
  );

  return parseResponse(response);
}

function demoVerify(payload) {
  return new Promise((resolve) => {
    setTimeout(() => {
      const text = (
        payload?.text ||
        payload?.url ||
        ""
      ).toLowerCase();

      if (
        text.includes("urgent") ||
        text.includes("password") ||
        text.includes("credential") ||
        text.includes("bit.ly") ||
        text.includes("processing fee") ||
        text.includes("click immediately")
      ) {
        resolve({
          verification_status: "HIGH_RISK",
          risk_level: "HIGH",
          claimed_issuer: "Unknown / Claimed Institution",
          signature_valid: false,
          integrity_valid: false,
          notice_status: "UNKNOWN",
          indicators: [
            "Suspicious urgency or pressure",
            "Potential credential request",
            "Unrecognized or suspicious link",
          ],
          explanation:
            "The communication contains patterns commonly associated with social engineering or phishing.",
          recommended_action:
            "Do NOT click suspicious links or enter passwords or financial information.",
        });

        return;
      }

      if (
        text.includes("unverified") ||
        text.includes("unknown")
      ) {
        resolve({
          verification_status: "UNVERIFIED",
          risk_level: "MEDIUM",
          claimed_issuer: "Unknown",
          signature_valid: false,
          integrity_valid: false,
          notice_status: "UNKNOWN",
          indicators: [
            "Issuer could not be confirmed",
          ],
          explanation:
            "The communication could not be cryptographically linked to a trusted issuer.",
          recommended_action:
            "Confirm the notice directly with the claimed institution.",
        });

        return;
      }

      resolve({
        verification_status: "VERIFIED",
        risk_level: "LOW",
        claimed_issuer: "KIIT Placement Cell",
        signature_valid: true,
        integrity_valid: true,
        notice_status: "ACTIVE",
        indicators: [],
        explanation:
          "The notice appears to be associated with a trusted institutional issuer.",
        recommended_action:
          "The communication passed the available verification checks.",
      });
    }, 1500);
  });
}

function demoScreenshotVerify(file) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        verification_status: "UNVERIFIED",
        risk_level: "MEDIUM",
        claimed_issuer: "Screenshot Notice",
        signature_valid: false,
        integrity_valid: false,
        notice_status: "UNKNOWN",
        indicators: [
          "Screenshot requires issuer verification",
          "No trusted signature detected",
        ],
        explanation:
          `The uploaded screenshot "${file?.name || "image"}" could not be confirmed against the trusted issuer registry in demo mode.`,
        recommended_action:
          "Verify the notice with the claimed institution before taking action.",
      });
    }, 1800);
  });
}