export type AttackType = 'normal' | 'brute_force' | 'port_scan' | 'ddos' | 'bot_activity' | 'suspicious_login' | 'scraping';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';
export type EventStatus = 'blocked' | 'detected' | 'mitigated';
export type SessionMode = 'simulation' | 'live' | 'hybrid';

export interface MitreInfo {
  tactic: string;
  tactic_id: string;
  technique: string;
  technique_id: string;
  sub_technique: string | null;
  sub_id: string | null;
  description: string;
  severity: string;
  mitre_url: string;
}

export interface PredictionInfo {
  predicted_attack: AttackType;
  probability: number;
  eta_minutes: number;
  likely_source_ip: string;
  likely_source_coords?: [number, number];
  based_on: AttackType;
  pattern_count: number;
  confidence: 'HIGH' | 'MEDIUM';
  recommendation: string;
  timestamp?: string;
}

export interface NormalizedEvent {
  event_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  attack_type: AttackType;
  risk_level: RiskLevel;
  bot_score: number;
  classification: string;
  reputation_score: number;
  country: string;
  status: EventStatus;
  prediction_hint: string;
  bytes?: number;
  protocol?: string;
  port?: number;
  map_coords?: { lat: number; lng: number };
  mitre?: MitreInfo;
}

export interface SecurityMetric {
  name: string;
  value: number;
  change: number;
  trend: 'up' | 'down' | 'stable';
}

export interface NetworkTraffic {
  time: string;
  inbound: number;
  outbound: number;
}

export interface Vulnerability {
  id: string;
  cve: string;
  score: number;
  description: string;
  affectedSystem: string;
  remediation: string;
}

export interface IPDetails {
  ip: string;
  country: string;
  city: string;
  isp: string;
  asn: string;
  abuse_score: number;
  risk_level: RiskLevel;
  open_ports: number[];
  tags: string[];
  map_coords: { lat: number; lng: number };
}

export interface AppConfig {
  mode: string;
  refresh_interval: number;
  sensitivity: number;
  auto_block_threshold: number;
  auto_block_critical: boolean;
  show_predictions: boolean;
  dark_mode: boolean;
  animations: boolean;
  abuseipdb_key: string;
  shodan_key: string;
  gemini_key: string;
  auto_explain_high: boolean;
  show_ai_alerts: boolean;
  show_ai_modal: boolean;
}
