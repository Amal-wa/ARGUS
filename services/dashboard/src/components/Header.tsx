import { useAuth } from "../context/AuthContext";

interface HeaderProps {
  isLive: boolean;
  onOpenAudit: () => void;
}

export function Header({ isLive, onOpenAudit }: HeaderProps) {
  const { logout } = useAuth();

  return (
    <header className="header">
      <div className="header__brand">
        <span className="header__eye" aria-hidden="true">
          ◎
        </span>
        <span className="header__wordmark">ARGUS.</span>
        <span className="header__sublabel">Pwn &amp; Patch</span>
      </div>
      <div className="header__actions">
        <span className="live-indicator">
          <span className={`live-dot ${isLive ? "" : "live-dot--down"}`} />
          {isLive ? "Live" : "Reconnecting"}
        </span>
        <button className="btn" onClick={onOpenAudit}>
          Audit log
        </button>
        <button className="btn btn--danger" onClick={logout}>
          Log out
        </button>
      </div>
    </header>
  );
}
