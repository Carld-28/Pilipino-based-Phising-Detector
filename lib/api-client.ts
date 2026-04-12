const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface ScanResult {
  is_phishing: boolean;
  risk_score: number;
  risk_level: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' | 'ERROR';
  threats: string[];
  explanation: string;
  timestamp: string;
  transcript?: string;
}

export async function scanURL(url: string): Promise<ScanResult> {
  const response = await fetch(`${API_BASE_URL}/scan-url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) throw new Error('Failed to scan URL');
  return response.json();
}

export async function scanMessage(message: string): Promise<ScanResult> {
  const response = await fetch(`${API_BASE_URL}/scan-message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message }),
  });

  if (!response.ok) throw new Error('Failed to scan message');
  return response.json();
}

export async function scanVoice(audioFile: File): Promise<ScanResult> {
  const formData = new FormData();
  formData.append('file', audioFile);

  const response = await fetch(`${API_BASE_URL}/scan-voice`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) throw new Error('Failed to scan voice');
  return response.json();
}

export async function getScans(limit: number = 50): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/scans?limit=${limit}`);

  if (!response.ok) throw new Error('Failed to fetch scans');
  return response.json();
}
