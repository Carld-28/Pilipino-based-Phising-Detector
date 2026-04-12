import URLScanner from '@/components/url-scanner';
import MessageScanner from '@/components/message-scanner';
import VoiceScanner from '@/components/voice-scanner';
import ScanHistory from '@/components/scan-history';

export const metadata = {
  title: 'Phishing Detection AI',
  description: 'AI-powered phishing detection system for Philippine scams',
};

export default function Home() {
  return (
    <main className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b border-border bg-card/95 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-primary flex items-center justify-center">
                <svg
                  className="w-6 h-6 text-primary-foreground"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" />
                </svg>
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">PhishGuard</h1>
                <p className="text-sm text-muted-foreground">AI Phishing Detection System</p>
              </div>
            </div>

            <div className="text-right hidden sm:block">
              <p className="text-xs text-muted-foreground">Protecting Philippine Users</p>
              <p className="text-sm font-medium text-foreground">From Phishing Scams</p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Info Section */}
        <div className="mb-8 p-4 bg-card border border-border rounded-lg">
          <h2 className="text-lg font-semibold text-foreground mb-2">Welcome to PhishGuard</h2>
          <p className="text-sm text-muted-foreground">
            A comprehensive AI-powered phishing detection system designed to protect you from
            malicious links, deceptive messages, and fraudulent calls. Analyze URLs, text messages,
            and voice calls to identify phishing attempts targeting Philippine users.
          </p>
        </div>

        {/* Scanner Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <URLScanner />
          <MessageScanner />
        </div>

        {/* Voice Scanner - Full Width */}
        <div className="mb-8">
          <VoiceScanner />
        </div>

        {/* Scan History */}
        <div className="mb-8">
          <ScanHistory />
        </div>

        {/* Footer Info */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-8">
          <div className="p-4 bg-card border border-border rounded-lg">
            <h3 className="font-semibold text-foreground mb-1 flex items-center gap-2">
              <span className="text-primary">🛡️</span> Secure Analysis
            </h3>
            <p className="text-sm text-muted-foreground">
              All scans are analyzed using advanced AI models trained on real phishing patterns.
            </p>
          </div>

          <div className="p-4 bg-card border border-border rounded-lg">
            <h3 className="font-semibold text-foreground mb-1 flex items-center gap-2">
              <span className="text-primary">🇵🇭</span> PH-Focused
            </h3>
            <p className="text-sm text-muted-foreground">
              Detects scams targeting Philippine financial services and popular payment apps.
            </p>
          </div>

          <div className="p-4 bg-card border border-border rounded-lg">
            <h3 className="font-semibold text-foreground mb-1 flex items-center gap-2">
              <span className="text-primary">⚡</span> Real-Time
            </h3>
            <p className="text-sm text-muted-foreground">
              Instant analysis with detailed threat reports and risk scores for immediate action.
            </p>
          </div>
        </div>

        {/* Safety Tips */}
        <div className="mt-8 p-6 bg-secondary/20 border border-border rounded-lg">
          <h3 className="font-semibold text-foreground mb-3">Safety Tips:</h3>
          <ul className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm text-foreground">
            <li className="flex gap-2">
              <span className="text-accent">✓</span> Never click links from unknown sources
            </li>
            <li className="flex gap-2">
              <span className="text-accent">✓</span> Verify caller identity before sharing info
            </li>
            <li className="flex gap-2">
              <span className="text-accent">✓</span> Check domain names carefully for typos
            </li>
            <li className="flex gap-2">
              <span className="text-accent">✓</span> Banks never ask for passwords via message
            </li>
            <li className="flex gap-2">
              <span className="text-accent">✓</span> Use official apps for banking transactions
            </li>
            <li className="flex gap-2">
              <span className="text-accent">✓</span> Report suspicious activity immediately
            </li>
          </ul>
        </div>
      </div>
    </main>
  );
}
