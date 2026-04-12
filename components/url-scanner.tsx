'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { scanURL, ScanResult } from '@/lib/api-client';
import RiskBadge from './risk-badge';
import ThreatList from './threat-list';

export default function URLScanner() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const scanResult = await scanURL(url);
      setResult(scanResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to scan URL');
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
              d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.658 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"
            />
          </svg>
          URL Scanner
        </CardTitle>
        <CardDescription>Analyze URLs for phishing indicators</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Input
            placeholder="Enter URL (e.g., https://example.com)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleScan()}
            disabled={loading}
            className="bg-input"
          />
          <Button
            onClick={handleScan}
            disabled={loading}
            className="bg-primary hover:bg-primary/90 text-primary-foreground"
          >
            {loading ? 'Scanning...' : 'Scan'}
          </Button>
        </div>

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
