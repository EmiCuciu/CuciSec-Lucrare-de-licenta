export interface Rule {
    id: number;
    ip_src: string | null;
    port: number | null;
    protocol: string | null;
    action: string;
    description: string | null;
    enabled: number;
    zone: string;
}

export interface LogEntry {
  id: number;
  timestamp: string;
  ip_src: string;
  ip_dst: string;
  port_src: number;
  port_dst: number;
  protocol: string;
  action_taken: string;
  details: string;
}

export interface BlacklistEntry {
  id: number;
  ip: string;
  reason: string;
  timestamp: string;
}

export interface Stats {
  total_logs: number;
  accepted: number;
  dropped: number;
  banned_ips: number;
  flood_counters: Record<string, number>;
  recent_bans: { ip: string; reason: string; timestamp: string }[];
}

export interface LogCount {
  minute: string;
  accepted: number;
  dropped: number;
}