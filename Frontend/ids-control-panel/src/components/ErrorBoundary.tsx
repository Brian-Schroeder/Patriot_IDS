import { Component, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback ?? (
          <div className="min-h-[400px] flex flex-col items-center justify-center p-8 bg-[var(--ids-surface)] rounded-xl border border-[var(--ids-border)]">
            <h3 className="text-lg font-semibold text-[var(--ids-danger)] mb-2">Something went wrong</h3>
            <p className="text-sm text-[var(--ids-text-muted)] mb-4 max-w-md text-center">
              {this.state.error?.message ?? 'An unexpected error occurred'}
            </p>
            <button
              type="button"
              onClick={() => this.setState({ hasError: false })}
              className="px-4 py-2 rounded-lg bg-[var(--ids-accent)]/20 text-[var(--ids-accent)] hover:bg-[var(--ids-accent)]/30"
            >
              Try again
            </button>
          </div>
        )
      );
    }
    return this.props.children;
  }
}
