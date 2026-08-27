import { createContext, useContext, useEffect, useState } from "react";

const VerificationContext = createContext();

export function VerificationProvider({ children }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("clickbait_history")) || [];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    localStorage.setItem(
      "clickbait_history",
      JSON.stringify(history)
    );
  }, [history]);

  const addHistory = (verificationResult) => {
    const newRecord = {
      ...verificationResult,
      id: Date.now(),
      createdAt: new Date().toISOString(),
    };

    setHistory((previous) => [
      newRecord,
      ...previous,
    ].slice(0, 30));

    setResult(newRecord);

    return newRecord;
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem("clickbait_history");
  };

  return (
    <VerificationContext.Provider
      value={{
        result,
        setResult,
        loading,
        setLoading,
        history,
        addHistory,
        clearHistory,
      }}
    >
      {children}
    </VerificationContext.Provider>
  );
}

export function useVerification() {
  return useContext(VerificationContext);
}