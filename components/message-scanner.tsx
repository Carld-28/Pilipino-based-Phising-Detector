'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { scanMessage, ScanResult } from '@/lib/api-client';
import RiskBadge from './risk-badge';
import ThreatList from './threat-list';

export default function MessageScanner() {
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!message.trim()) {
      setError('Please enter a message');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const scanResult = await scanMessage(message);
      setResult(scanResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to scan message');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="border-border">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <svg
            className="w-5 h-5 text-primary"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"
            />
          </svg>
          Message Scanner
        </CardTitle>
        <CardDescription>Analyze text messages and SMS for phishing patterns</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Textarea
          placeholder="Paste the message you want to analyze..."
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          disabled={loading}
          className="bg-input min-h-24"
        />

        <Button
          onClick={handleScan}
          disabled={loading}
          className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
        >
          {loading ? 'Scanning...' : 'Analyze Message'}
        </Button>

        {error && <div className="text-destructive text-sm">{error}</div>}

        {result && (
          <div className="space-y-3 mt-4 pt-4 border-t border-border">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Risk Level:</span>
              <RiskBadge level={result.risk_level} />
            </div>

            <div className="space-y-1">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Risk Score:</span>
                <span className="font-semibold">{(result.risk_score * 100).toFixed(0)}%</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div
                  className={`h-2 rounded-full transition-all ${
                    result.risk_score >= 0.7
                      ? 'bg-destructive'
                      : result.risk_score >= 0.4
                        ? 'bg-accent'
                        : 'bg-primary'
                  }`}
                  style={{ width: `${result.risk_score * 100}%` }}
                />
              </div>
            </div>

            {result.threats && result.threats.length > 0 && (
              <ThreatList threats={result.threats} />
            )}

            <div className="bg-secondary/50 p-3 rounded-lg text-sm">
              <p className="text-foreground">{result.explanation}</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
