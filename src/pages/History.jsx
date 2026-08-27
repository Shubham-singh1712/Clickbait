import {
  History as HistoryIcon,
  Trash2,
  ShieldCheck,
} from "lucide-react";

import HistoryCard from "../components/HistoryCard";

import {
  useVerification,
} from "../context/VerificationContext";

function History() {
  const {
    history,
    clearHistory,
  } = useVerification();

  return (
    <div className="page">

      <div className="page-header-row">

        <div>
          <div className="orange-label">
            ACTIVITY
          </div>

          <h1>
            Verification History
          </h1>

          <p>
            Review your recent communication
            verification checks.
          </p>
        </div>

        {history.length > 0 && (
          <button
            className="danger-outline-button"
            onClick={clearHistory}
          >
            <Trash2 size={17} />
            Clear History
          </button>
        )}

      </div>

      {history.length === 0 ? (
        <div className="empty-state">

          <div className="empty-icon">
            <HistoryIcon size={35} />
          </div>

          <h2>
            No verification history
          </h2>

          <p>
            Your verification activity will
            appear here.
          </p>

        </div>
      ) : (
        <div className="history-list">
          {history.map((item) => (
            <HistoryCard
              key={item.id}
              item={item}
            />
          ))}
        </div>
      )}

      <div className="history-tip">
        <ShieldCheck size={19} />

        <span>
          History is stored locally in your
          browser for this frontend demo.
        </span>
      </div>

    </div>
  );
}

export default History;