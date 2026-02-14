import { Shield, Activity, AlertTriangle } from 'lucide-react';
import { Outlet, NavLink } from 'react-router-dom';

export function Layout() {
  return (
    <div className="flex min-h-screen">
      <aside className="w-56 flex-shrink-0 bg-[var(--ids-surface)] border-r border-[var(--ids-border)] flex flex-col">
        <div className="p-6 border-b border-[var(--ids-border)]">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-[var(--ids-accent)]" />
            <div>
              <h1 className="font-bold text-lg text-[var(--ids-text)]">IDS Panel</h1>
              <p className="text-xs text-[var(--ids-text-muted)]">Control & Monitor</p>
            </div>
          </div>
        </div>
        <nav className="flex-1 p-4">
          <NavLink
            to="/"
            className={({ isActive }) =>
              `flex items-center gap-2 px-3 py-2 rounded-lg mt-1 first:mt-0 font-medium ${
                isActive
                  ? 'text-[var(--ids-accent)] bg-[var(--ids-accent)]/10'
                  : 'text-[var(--ids-text-muted)] hover:bg-[var(--ids-border)]/50 hover:text-[var(--ids-text)]'
              }`
            }
          >
            <Activity size={18} />
            Dashboard
          </NavLink>
          <NavLink
            to="/alerts"
            className={({ isActive }) =>
              `flex items-center gap-2 px-3 py-2 rounded-lg mt-1 font-medium ${
                isActive
                  ? 'text-[var(--ids-accent)] bg-[var(--ids-accent)]/10'
                  : 'text-[var(--ids-text-muted)] hover:bg-[var(--ids-border)]/50 hover:text-[var(--ids-text)]'
              }`
            }
          >
            <AlertTriangle size={18} />
            Alerts
          </NavLink>
        </nav>
        <div className="p-4 border-t border-[var(--ids-border)]">
          <div className="text-xs text-[var(--ids-text-muted)]">
            <div className="font-medium text-[var(--ids-text)]">Status</div>
            <div className="flex items-center gap-1.5 mt-1">
              <span className="w-2 h-2 rounded-full bg-[var(--ids-accent)] animate-pulse" />
              Monitoring active
            </div>
          </div>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <header className="sticky top-0 z-10 bg-[var(--ids-bg)]/95 backdrop-blur border-b border-[var(--ids-border)] px-8 py-4">
          <h2 className="text-xl font-semibold text-[var(--ids-text)]">
            Intrusion Detection System
          </h2>
          <p className="text-sm text-[var(--ids-text-muted)] mt-0.5">
            Real-time network traffic analysis and alert visualization
          </p>
        </header>
        <div className="p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
