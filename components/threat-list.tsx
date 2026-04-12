'use client';

interface ThreatListProps {
  threats: string[];
}

export default function ThreatList({ threats }: ThreatListProps) {
  return (
    <div className="space-y-2">
      <p className="text-sm font-medium text-foreground">Detected Threats:</p>
      <ul className="space-y-1">
        {threats.map((threat, index) => (
          <li key={index} className="text-sm text-foreground flex items-start gap-2">
            <span className="text-accent mt-0.5">•</span>
            <span>{threat}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
