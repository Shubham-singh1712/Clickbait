import { Routes, Route, Navigate } from "react-router-dom";

import Navbar from "./components/Navbar";

import Home from "./pages/Home";
import Verify from "./pages/Verify";
import Result from "./pages/Result";
import History from "./pages/History";
import Dashboard from "./pages/Dashboard";

function App() {
  return (
    <div className="app">
      <Navbar />

      <main className="main-content">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/verify" element={<Verify />} />
          <Route path="/result" element={<Result />} />
          <Route path="/history" element={<History />} />
          <Route path="/dashboard" element={<Dashboard />} />

          <Route
            path="*"
            element={<Navigate to="/" replace />}
          />
        </Routes>
      </main>

      <footer className="footer">
        <div>
          <strong>CLICKBAIT</strong>
          <span> — Don't Guess. Verify.</span>
        </div>

        <p>
          Student Communication Verification Platform
        </p>
      </footer>
    </div>
  );
}

export default App;