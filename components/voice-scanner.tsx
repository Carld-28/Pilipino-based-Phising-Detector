'use client';

import { useState, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { scanVoice, ScanResult } from '@/lib/api-client';
import RiskBadge from './risk-badge';
import ThreatList from './threat-list';

export default function VoiceScanner() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [recording, setRecording] = useState(false);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<Blob[]>([]);

  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mediaRecorder = new MediaRecorder(stream);
      mediaRecorderRef.current = mediaRecorder;
      chunksRef.current = [];

      mediaRecorder.ondataavailable = (e) => {
        chunksRef.current.push(e.data);
      };

      mediaRecorder.onstop = async () => {
        const audioBlob = new Blob(chunksRef.current, { type: 'audio/wav' });
        const audioFile = new File([audioBlob], 'recording.wav', { type: 'audio/wav' });
        await handleVoiceScan(audioFile);
        stream.getTracks().forEach((track) => track.stop());
      };

      mediaRecorder.start();
      setRecording(true);
      setError('');
    } catch (err) {
      setError('Microphone access denied');
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && recording) {
      mediaRecorderRef.current.stop();
      setRecording(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleVoiceScan(file);
    }
  };

  const handleVoiceScan = async (audioFile: File) => {
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const scanResult = await scanVoice(audioFile);
      setResult(scanResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to scan voice');
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
              d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4"
            />
          </svg>
          Voice Scanner
        </CardTitle>
        <CardDescription>Analyze voice calls and audio for phishing indicators</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-3">
          {recording ? (
            <Button
              onClick={stopRecording}
              className="w-full bg-destructive hover:bg-destructive/90 text-destructive-foreground"
            >
              Stop Recording
            </Button>
          ) : (
            <Button
              onClick={startRecording}
              disabled={loading}
              className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
            >
              Start Recording
            </Button>
          )}

          <div className="relative">
            <Button
              asChild
              variant="outline"
              className="w-full"
              disabled={loading || recording}
            >
              <label className="cursor-pointer">
                Upload Audio File
                <input
                  type="file"
                  accept="audio/*"
                  onChange={handleFileUpload}
                  disabled={loading || recording}
                  className="hidden"
                />
              </label>
            </Button>
          </div>
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

            {result.transcript && (
              <div className="bg-card border border-border p-3 rounded-lg text-sm">
                <p className="text-muted-foreground text-xs mb-1">Transcript:</p>
                <p className="text-foreground italic">{result.transcript}</p>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
