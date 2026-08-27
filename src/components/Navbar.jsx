import { Link, NavLink } from "react-router-dom";
import {
  ShieldCheck,
  LayoutDashboard,
  History,
  Search,
} from "lucide-react";

function Navbar() {
  return (
    <header className="navbar">
      <Link to="/" className="brand">
        <div className="brand-icon">
          <ShieldCheck size={24} />
        </div>

        <div>
          <div className="brand-name">
            CLICKBAIT
          </div>

          <div className="brand-tagline">
            Don't Guess. Verify.
          </div>
        </div>
      </Link>

      <nav className="nav-links">
        <NavLink
          to="/"
          className={({ isActive }) =>
            `nav-link ${isActive ? "active" : ""}`
          }
        >
          <Search size={17} />
          Verify
        </NavLink>

        <NavLink
          to="/dashboard"
          className={({ isActive }) =>
            `nav-link ${isActive ? "active" : ""}`
          }
        >
          <LayoutDashboard size={17} />
          Dashboard
        </NavLink>

        <NavLink
          to="/history"
          className={({ isActive }) =>
            `nav-link ${isActive ? "active" : ""}`
          }
        >
          <History size={17} />
          History
        </NavLink>
      </nav>
    </header>
  );
}

export default Navbar;