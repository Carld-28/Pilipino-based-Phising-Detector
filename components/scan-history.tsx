'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useEffect, useState } from 'react';
import { getScans } from '@/lib/api-client';

interface Scan {
  _id: string;
  type: string;
  input?: string;
  filename?: string;
  result: {
    risk_level: string;
    risk_score: number;
  };
  timestamp: string;
}

export default function ScanHistory() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const data = await getScans(10);
        setScans(data.scans || []);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load scans');
      } finally {
        setLoading(false);
      }
    };

    fetchScans();
    const interval = setInterval(fetchScans, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'HIGH':
        return 'bg-destructive text-destructive-foreground';
      case 'MEDIUM':
        return 'bg-accent text-accent-foreground';
      case 'LOW':
        return 'bg-primary text-primary-foreground';
      default:
        return 'bg-muted text-muted-foreground';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'url':
        return '🔗';
      case 'message':
        return '💬';
      case 'voice':
        return '🎤';
      default:
        return '📋';
    }
  };

  return (
    <Card className="border-border">
      <CardHeader>
        <CardTitle>Scan History</CardTitle>
        <CardDescription>Recent phishing detection scans</CardDescription>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="text-center py-8 text-muted-foreground">Loading scans...</div>
        ) : error ? (
          <div className="text-center py-8 text-destructive">{error}</div>
        ) : scans.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">No scans yet</div>
        ) : (
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {scans.map((scan) => (
              <div
                key={scan._id}
                className="flex items-center justify-between p-3 bg-card border border-border rounded-lg hover:bg-card/80 transition-colors"
              >
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <span className="text-lg">{getTypeIcon(scan.type)}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">
                      {scan.input || scan.filename || `${scan.type} scan`}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(scan.timestamp).toLocaleTimeString()}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <div className="text-right">
                    <p className="text-xs text-muted-foreground">
                      {(scan.result.risk_score * 100).toFixed(0)}%
                    </p>
                  </div>
                  <Badge className={getRiskColor(scan.result.risk_level)}>
                    {scan.result.risk_level}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
