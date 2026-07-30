import { AuthProvider, useAuth } from "./context/AuthContext";
import { Dashboard } from "./components/Dashboard";
import { LoginScreen } from "./components/LoginScreen";

function Root() {
  const { isAuthenticated, isInitializing } = useAuth();

  // Never flash the login screen while the silent-restore /auth/refresh
  // attempt is still in flight -- that's the bug this whole flow exists to
  // fix (a page reload used to always show the login screen for an instant,
  // even when the session was about to come back).
  if (isInitializing) {
    return (
      <div className="app-loading" role="status" aria-live="polite">
        Restoring session…
      </div>
    );
  }

  return isAuthenticated ? <Dashboard /> : <LoginScreen />;
}

export default function App() {
  return (
    <AuthProvider>
      <Root />
    </AuthProvider>
  );
}
