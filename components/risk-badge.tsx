'use client';

import { Badge } from '@/components/ui/badge';

interface RiskBadgeProps {
  level: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' | 'ERROR';
}

export default function RiskBadge({ level }: RiskBadgeProps) {
  const getColor = () => {
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

  return <Badge className={getColor()}>{level}</Badge>;
}
