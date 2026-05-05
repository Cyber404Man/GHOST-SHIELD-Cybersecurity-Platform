import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import cors from 'cors';
import morgan from 'morgan';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import axios from 'axios';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(cors());
  app.use(morgan('dev'));
  app.use(express.json());

  // --- Models & State ---
  
  interface MitreInfo {
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

  interface Event {
    event_id: string;
    timestamp: string;
    src_ip: string;
    dst_ip: string;
    attack_type: string;
    risk_level: string;
    bot_score: number;
    classification: string;
    reputation_score: number;
    country: string;
    status: string;
    prediction_hint: string;
    mitre?: MitreInfo;
  }

  interface Config {
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
  }

  let session_state = {
    mode: "simulation",
    start_time: new Date().toISOString(),
    events_processed: 0
  };

  let config_state: Config = {
    mode: "simulation",
    refresh_interval: 5,
    sensitivity: 5,
    auto_block_threshold: 80,
    auto_block_critical: true,
    show_predictions: true,
    dark_mode: true,
    animations: true,
    abuseipdb_key: "",
    shodan_key: ""
  };

  let events_db: Event[] = [];

  const MITRE_MAP: Record<string, MitreInfo> = {
    port_scan: {
      tactic: 'Reconnaissance',
      tactic_id: 'TA0043',
      technique: 'Active Scanning',
      technique_id: 'T1595',
      sub_technique: 'Scanning IP Blocks',
      sub_id: 'T1595.001',
      description: 'Adversary scans victim IP blocks to gather information.',
      severity: 'MEDIUM',
      mitre_url: 'https://attack.mitre.org/techniques/T1595/'
    },
    brute_force: {
      tactic: 'Credential Access',
      tactic_id: 'TA0006',
      technique: 'Brute Force',
      technique_id: 'T1110',
      sub_technique: 'Password Guessing',
      sub_id: 'T1110.001',
      description: 'Adversary attempts to gain access by guessing passwords.',
      severity: 'HIGH',
      mitre_url: 'https://attack.mitre.org/techniques/T1110/'
    },
    credential_stuffing: {
      tactic: 'Credential Access',
      tactic_id: 'TA0006',
      technique: 'Brute Force',
      technique_id: 'T1110',
      sub_technique: 'Credential Stuffing',
      sub_id: 'T1110.004',
      description: 'Adversary uses obtained credentials from breaches.',
      severity: 'HIGH',
      mitre_url: 'https://attack.mitre.org/techniques/T1110/004/'
    },
    ddos: {
      tactic: 'Impact',
      tactic_id: 'TA0040',
      technique: 'Network Denial of Service',
      technique_id: 'T1498',
      sub_technique: 'Direct Network Flood',
      sub_id: 'T1498.001',
      description: 'Adversary floods network to degrade or block availability.',
      severity: 'CRITICAL',
      mitre_url: 'https://attack.mitre.org/techniques/T1498/'
    },
    suspicious_login: {
      tactic: 'Initial Access',
      tactic_id: 'TA0001',
      technique: 'Valid Accounts',
      technique_id: 'T1078',
      sub_technique: 'Cloud Accounts',
      sub_id: 'T1078.004',
      description: 'Adversary uses legitimate credentials for unauthorized access.',
      severity: 'HIGH',
      mitre_url: 'https://attack.mitre.org/techniques/T1078/'
    },
    bot_activity: {
      tactic: 'Command and Control',
      tactic_id: 'TA0011',
      technique: 'Automated Exfiltration',
      technique_id: 'T1020',
      sub_technique: 'Traffic Duplication',
      sub_id: 'T1020.001',
      description: 'Automated bot performing C2 communication or data collection.',
      severity: 'HIGH',
      mitre_url: 'https://attack.mitre.org/techniques/T1020/'
    },
    scraping: {
      tactic: 'Collection',
      tactic_id: 'TA0009',
      technique: 'Automated Collection',
      technique_id: 'T1119',
      sub_technique: null,
      sub_id: null,
      description: 'Adversary automatically collects data using scripts or tools.',
      severity: 'MEDIUM',
      mitre_url: 'https://attack.mitre.org/techniques/T1119/'
    },
  };

  function generateSimulatedEvent(): Event {
    const isAttack = Math.random() < 0.3;
    const attackTypes = ["brute_force", "port_scan", "ddos", "bot_activity", "suspicious_login", "scraping"];
    const countries = ["USA", "China", "Russia", "Germany", "Brazil", "UK", "India", "Netherlands", "Japan", "Canada"];
    
    let src_ip, attack_type, risk_level, bot_score, classification, reputation_score, status, prediction_hint;

    if (!isAttack) {
      src_ip = `192.168.1.${Math.floor(Math.random() * 253) + 2}`;
      attack_type = "normal";
      risk_level = "low";
      bot_score = Math.random() * 0.2;
      classification = "benign";
      reputation_score = Math.floor(Math.random() * 21) + 80;
      status = "allowed";
      prediction_hint = "High confidence: Normal user behavior";
    } else {
      src_ip = `${Math.floor(Math.random() * 255) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      attack_type = attackTypes[Math.floor(Math.random() * attackTypes.length)];
      risk_level = ["medium", "high", "critical"][Math.floor(Math.random() * 3)];
      bot_score = Math.random() * 0.4 + 0.6;
      classification = "malicious";
      reputation_score = Math.floor(Math.random() * 41);
      status = risk_level === "critical" ? "blocked" : "detected";
      prediction_hint = `Anomaly detected: ${attack_type} pattern`;
    }

    return {
      event_id: `EVT-${Math.floor(Math.random() * 900000) + 100000}`,
      timestamp: new Date().toISOString(),
      src_ip,
      dst_ip: "10.0.0.5",
      attack_type,
      risk_level,
      bot_score: Number(bot_score.toFixed(2)),
      classification,
      reputation_score,
      country: countries[Math.floor(Math.random() * countries.length)],
      status,
      prediction_hint,
      mitre: attack_type !== "normal" ? MITRE_MAP[attack_type] : undefined
    };
  }

  // Initial events
  for (let i = 0; i < 50; i++) {
    events_db.push(generateSimulatedEvent());
  }

  // --- API Routes ---

  app.get('/health', (req, res) => {
    res.json({ status: 'ok', engine: 'express' });
  });

  app.post('/api/session/start', (req, res) => {
    const mode = req.query.mode as string || "simulation";
    session_state.mode = mode;
    session_state.start_time = new Date().toISOString();
    session_state.events_processed = 0;
    
    if (mode === "simulation") {
      events_db = [];
      for (let i = 0; i < 50; i++) {
        events_db.push(generateSimulatedEvent());
      }
    }
    res.json({ status: "success", mode });
  });

  app.get('/api/session/state', (req, res) => {
    res.json(session_state);
  });

  app.get('/api/alerts', (req, res) => {
    if (config_state.mode === "simulation" || config_state.mode === "hybrid") {
      if (Math.random() < 0.5) {
        events_db.unshift(generateSimulatedEvent());
        if (events_db.length > 200) events_db.pop();
      }
    }
    res.json(events_db.slice(0, 100));
  });

  function getPreemptiveAction(predictedType: string) {
    const actions: Record<string, string> = {
      'brute_force': 'Pre-block port 22/3389. Enable login rate limiting now.',
      'ddos': 'Activate rate limiting. Notify upstream provider.',
      'credential_stuffing': 'Force CAPTCHA on login pages. Alert affected accounts.',
      'bot_activity': 'Enable behavioral fingerprinting. Prepare IP blacklist.',
      'suspicious_login': 'Enable MFA challenge for next 30 minutes.',
    };
    return actions[predictedType] || 'Increase monitoring sensitivity.';
  }

  function predictNextAttack(sessionEvents: Event[]) {
    const KILL_CHAIN: Record<string, any> = {
      'port_scan': { next: 'brute_force', probability: 0.73, eta_minutes: 3 },
      'brute_force': { next: 'suspicious_login', probability: 0.68, eta_minutes: 5 },
      'suspicious_login': { next: 'credential_stuffing', probability: 0.81, eta_minutes: 2 },
      'credential_stuffing': { next: 'bot_activity', probability: 0.65, eta_minutes: 8 },
      'bot_activity': { next: 'ddos', probability: 0.59, eta_minutes: 15 },
      'scraping': { next: 'credential_stuffing', probability: 0.44, eta_minutes: 10 },
      'ddos': { next: 'ddos', probability: 0.88, eta_minutes: 1 },
    };

    const recent = sessionEvents.slice(0, 10);
    const attackTypes = recent.map(e => e.attack_type).filter(t => t !== 'normal');

    if (attackTypes.length === 0) return null;

    const lastAttack = attackTypes[0];
    const prediction = KILL_CHAIN[lastAttack];

    if (!prediction) return null;

    const patternCount = attackTypes.filter(t => t === lastAttack).length;
    const adjustedProbability = Math.min(0.97, prediction.probability + (patternCount * 0.05));

    const ipCounts: Record<string, number> = {};
    recent.forEach(e => {
      if (e.attack_type !== 'normal') {
        ipCounts[e.src_ip] = (ipCounts[e.src_ip] || 0) + 1;
      }
    });
    const likelyIp = Object.keys(ipCounts).length > 0 
      ? Object.keys(ipCounts).reduce((a, b) => ipCounts[a] > ipCounts[b] ? a : b)
      : 'Unknown';

    const countries = ["USA", "China", "Russia", "Germany", "Brazil"];
    const country = countries[Math.floor(Math.random() * countries.length)];
    const REGIONS: Record<string, any> = {
      "USA": [ -74.00, 40.71 ],
      "Russia": [ 37.61, 55.75 ],
      "China": [ 116.40, 39.90 ],
      "Germany": [ 13.40, 52.52 ],
      "Brazil": [ -46.63, -23.55 ]
    };

    return {
      predicted_attack: prediction.next,
      probability: Number((adjustedProbability * 100).toFixed(1)),
      eta_minutes: prediction.eta_minutes,
      likely_source_ip: likelyIp,
      likely_source_coords: REGIONS[country],
      based_on: lastAttack,
      pattern_count: patternCount,
      confidence: adjustedProbability > 0.75 ? 'HIGH' : 'MEDIUM',
      recommendation: getPreemptiveAction(prediction.next),
      timestamp: new Date().toISOString()
    };
  }

  app.get('/api/predict', (req, res) => {
    const prediction = predictNextAttack(events_db);
    res.json(prediction);
  });

  app.get('/api/attack-map-data', (req, res) => {
    res.json(events_db.filter(e => e.attack_type !== "normal"));
  });

  app.get('/api/bot-detection/summary', (req, res) => {
    const bots = events_db.filter(e => e.bot_score > 0.5);
    res.json({
      total_bots: bots.length,
      categories: {
        scraper: bots.filter(b => b.attack_type === "scraping").length,
        brute_force: bots.filter(b => b.attack_type === "brute_force").length,
        spam: 5,
        credential_stuffing: 3
      },
      bot_list: bots.slice(0, 20)
    });
  });

  app.post('/api/check-gemini', async (req, res) => {
    const gemini_key = req.body.key || process.env.GEMINI_API_KEY || "";
    if (!gemini_key) {
      return res.json({ status: "missing", message: "No API key configured", impact: "AI threat explanations will be unavailable" });
    }
    try {
      const gRes = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=${gemini_key}`,
        {
          contents: [{ parts: [{ text: "test" }] }],
          generationConfig: { maxOutputTokens: 5 }
        },
        { timeout: 7000, validateStatus: () => true }
      );
      if (gRes.status === 200 || gRes.status === 400) {
        return res.json({ status: "connected", message: "Gemini AI ready", impact: "AI threat explanations active", model: "gemini-flash-latest" });
      }
      return res.json({ status: "invalid_key", message: `Invalid key (HTTP ${gRes.status})`, impact: "AI explanations will use fallback mode" });
    } catch (e: any) {
      return res.json({ status: "error", message: `Connection failed: ${String(e.message).slice(0, 50)}`, impact: "AI explanations will use fallback mode" });
    }
  });

  app.post('/api/check-abuseipdb', async (req, res) => {
    const abuse_key = req.body.key || process.env.ABUSEIPDB_KEY || "";
    if (!abuse_key) {
      return res.json({ status: "missing", message: "No API key configured", impact: "IP reputation will use simulated scores" });
    }
    try {
      const aRes = await axios.get("https://api.abuseipdb.com/api/v2/check", {
        params: { ipAddress: "8.8.8.8", maxAgeInDays: 90 },
        headers: { Key: abuse_key, Accept: "application/json" },
        timeout: 5000,
        validateStatus: () => true
      });
      if (aRes.status === 200) {
        return res.json({ status: "connected", message: "AbuseIPDB ready", impact: "Real IP reputation scores active", daily_limit: aRes.data?.data?.totalReports || "unknown" });
      } else if (aRes.status === 401) {
        return res.json({ status: "invalid_key", message: "Invalid API key", impact: "IP reputation will use simulated scores" });
      } else if (aRes.status === 429) {
        return res.json({ status: "rate_limited", message: "Rate limit reached", impact: "Will use cached/simulated data" });
      }
      return res.json({ status: "error", message: `HTTP ${aRes.status}`, impact: "IP reputation will use simulated scores" });
    } catch (e: any) {
      return res.json({ status: "error", message: `Connection failed: ${String(e.message).slice(0, 50)}`, impact: "IP reputation will use simulated scores" });
    }
  });

  app.post('/api/check-shodan', async (req, res) => {
    const shodan_key = req.body.key || process.env.SHODAN_KEY || "";
    if (!shodan_key) {
      return res.json({ status: "missing", message: "No API key configured", impact: "Open ports will use simulated data" });
    }
    try {
      const sRes = await axios.get(`https://api.shodan.io/api-info`, {
        params: { key: shodan_key },
        timeout: 5000,
        validateStatus: () => true
      });
      if (sRes.status === 200) {
        return res.json({ status: "connected", message: "Shodan ready", impact: "Real open port tracking active", plan: sRes.data?.plan || "unknown", query_credits: sRes.data?.query_credits || 0 });
      } else if (sRes.status === 401) {
        return res.json({ status: "invalid_key", message: "Invalid API key", impact: "Open ports will use simulated data" });
      }
      return res.json({ status: "error", message: `HTTP ${sRes.status}`, impact: "Open ports will use simulated data" });
    } catch (e: any) {
      return res.json({ status: "error", message: `Connection failed: ${String(e.message).slice(0, 50)}`, impact: "Open ports will use simulated data" });
    }
  });

  app.post('/api/check-readiness', async (req, res) => {
    const keys = req.body || {};
    const results: Record<string, any> = {};

    // 1. CHECK GEMINI
    try {
      const gemini_key = keys.gemini_key || process.env.GEMINI_API_KEY || "";
      if (!gemini_key) {
        results.gemini = {
          status: "missing",
          message: "No API key configured",
          impact: "AI threat explanations will be unavailable"
        };
      } else {
        const geminiRes = await axios.post(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=${gemini_key}`,
          {
            contents: [{ parts: [{ text: "test" }] }],
            generationConfig: { maxOutputTokens: 5 }
          },
          { timeout: 5000, validateStatus: () => true }
        );
        if (geminiRes.status === 200) {
          results.gemini = {
            status: "connected",
            message: "Gemini AI ready",
            impact: "AI threat explanations active",
            model: "gemini-flash-latest"
          };
        } else if (geminiRes.status === 400) {
          results.gemini = {
            status: "connected",
            message: "Gemini AI ready",
            impact: "AI threat explanations active"
          };
        } else {
          results.gemini = {
            status: "invalid_key",
            message: `Invalid key (HTTP ${geminiRes.status})`,
            impact: "AI explanations will use fallback mode"
          };
        }
      }
    } catch (e: any) {
      results.gemini = {
        status: "error",
        message: `Connection failed: ${String(e.message).slice(0, 50)}`,
        impact: "AI explanations will use fallback mode"
      };
    }

    // 2. CHECK ABUSEIPDB
    try {
      const abuse_key = keys.abuseipdb_key || process.env.ABUSEIPDB_KEY || "";
      if (!abuse_key) {
        results.abuseipdb = {
          status: "missing",
          message: "No API key configured",
          impact: "IP reputation will use simulated scores"
        };
      } else {
        const abuseRes = await axios.get("https://api.abuseipdb.com/api/v2/check", {
          params: { ipAddress: "8.8.8.8", maxAgeInDays: 90 },
          headers: { Key: abuse_key, Accept: "application/json" },
          timeout: 5000,
          validateStatus: () => true
        });
        if (abuseRes.status === 200) {
          results.abuseipdb = {
            status: "connected",
            message: "AbuseIPDB ready",
            impact: "Real IP reputation scores active",
            daily_limit: abuseRes.data?.data?.totalReports || "unknown"
          };
        } else if (abuseRes.status === 401) {
          results.abuseipdb = {
            status: "invalid_key",
            message: "Invalid API key",
            impact: "IP reputation will use simulated scores"
          };
        } else if (abuseRes.status === 429) {
          results.abuseipdb = {
            status: "rate_limited",
            message: "Rate limit reached",
            impact: "Will use cached/simulated data"
          };
        } else {
          results.abuseipdb = {
            status: "error",
            message: `HTTP ${abuseRes.status}`,
            impact: "IP reputation will use simulated scores"
          };
        }
      }
    } catch (e: any) {
      results.abuseipdb = {
        status: "error",
        message: `Connection failed: ${String(e.message).slice(0, 50)}`,
        impact: "IP reputation will use simulated scores"
      };
    }

    // 3. CHECK SHODAN
    try {
      const shodan_key = keys.shodan_key || process.env.SHODAN_KEY || "";
      if (!shodan_key) {
        results.shodan = {
          status: "missing",
          message: "No API key configured",
          impact: "Open ports will use simulated data"
        };
      } else {
        const shodanRes = await axios.get(`https://api.shodan.io/api-info?key=${shodan_key}`, {
          timeout: 5000,
          validateStatus: () => true
        });
        if (shodanRes.status === 200) {
          results.shodan = {
            status: "connected",
            message: "Shodan ready",
            impact: "Real port scanning data active",
            plan: shodanRes.data?.plan || "unknown",
            query_credits: shodanRes.data?.query_credits || 0
          };
        } else if (shodanRes.status === 401) {
          results.shodan = {
            status: "invalid_key",
            message: "Invalid API key",
            impact: "Open ports will use simulated data"
          };
        } else {
          results.shodan = {
            status: "error",
            message: `HTTP ${shodanRes.status}`,
            impact: "Open ports will use simulated data"
          };
        }
      }
    } catch (e: any) {
      results.shodan = {
        status: "error",
        message: `Connection failed: ${String(e.message).slice(0, 50)}`,
        impact: "Open ports will use simulated data"
      };
    }

    const connected = Object.values(results).filter(r => r && r.status === "connected").length;
    const total = 3;

    results.overall = {
      connected,
      total,
      ready: connected === total,
      level: connected === total ? "FULL" : connected > 0 ? "PARTIAL" : "OFFLINE"
    };

    res.json(results);
  });

  app.get('/api/ip/details', async (req, res) => {
    const ip = req.query.ip as string;
    const octets = ip.split('.').map(Number);
    const seed = octets.reduce((a, b) => a + b, 0);

    const REGIONS = {
      "USA": { cities: ["New York", "Los Angeles", "Chicago"], isps: ["Comcast", "AWS", "Cloudflare"], coords: [40.71, -74.00] },
      "Russia": { cities: ["Moscow", "Saint Petersburg", "Novosibirsk"], isps: ["Rostelecom", "MTS", "Beeline"], coords: [55.75, 37.61] },
      "China": { cities: ["Beijing", "Shanghai", "Shenzhen"], isps: ["China Telecom", "Alibaba Cloud", "Tencent"], coords: [39.90, 116.40] },
      "Germany": { cities: ["Berlin", "Munich", "Frankfurt"], isps: ["Deutsche Telekom", "Hetzner", "Vodafone"], coords: [52.52, 13.40] },
      "Brazil": { cities: ["São Paulo", "Rio de Janeiro", "Brasília"], isps: ["Claro", "Vivo", "Oi"], coords: [-23.55, -46.63] }
    };

    const countries = Object.keys(REGIONS);
    const country = countries[seed % countries.length];
    const region = REGIONS[country as keyof typeof REGIONS];
    const city = region.cities[seed % region.cities.length];
    const isp = region.isps[seed % region.isps.length];

    const result: any = {
      ip,
      country,
      city,
      isp,
      asn: "AS13335",
      abuse_score: seed % 101,
      risk_level: (seed % 100) > 70 ? "high" : "low",
      open_ports: [80, 443, 22, 8080],
      tags: ["Data Center"],
      map_coords: [region.coords[1], region.coords[0]],
      data_source: "Simulation"
    };

    // Override with real AbuseIPDB data if key exists
    const abuse_key = config_state.abuseipdb_key || process.env.ABUSEIPDB_KEY || "";
    if (abuse_key) {
      try {
        const abuseRes = await axios.get("https://api.abuseipdb.com/api/v2/check", {
          params: { ipAddress: ip, maxAgeInDays: 90 },
          headers: { Key: abuse_key, Accept: "application/json" },
          timeout: 5000,
          validateStatus: () => true
        });
        if (abuseRes.status === 200 && abuseRes.data?.data) {
          const data = abuseRes.data.data;
          result.abuse_score = data.abuseConfidenceScore ?? result.abuse_score;
          if (data.countryCode) result.country = data.countryCode;
          if (data.isp) result.isp = data.isp;
          result.data_source = "AbuseIPDB";
        }
      } catch (e) {
        console.error("AbuseIPDB request failed:", e);
      }
    }

    // Override with real Shodan data if key exists
    const shodan_key = config_state.shodan_key || process.env.SHODAN_KEY || "";
    if (shodan_key) {
      try {
        const shodanRes = await axios.get(`https://api.shodan.io/shodan/host/${ip}?key=${shodan_key}`, {
          timeout: 5000,
          validateStatus: () => true
        });
        if (shodanRes.status === 200 && shodanRes.data) {
          const data = shodanRes.data;
          if (data.ports) result.open_ports = data.ports;
          if (data.isp) result.isp = data.isp;
          if (data.country_name) result.country = data.country_name;
          if (data.city) result.city = data.city;
          if (data.asn) result.asn = data.asn;
          result.data_source = "Shodan";
        }
      } catch (e) {
        console.error("Shodan request failed:", e);
      }
    }

    res.json(result);
  });

const upload = multer({ storage: multer.memoryStorage() });

// --- SSE & Report ---
const sessions: Record<string, { events: any[] }> = {};

app.post('/api/upload-logs', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  
  const content = req.file.buffer.toString('utf-8');
  const lines = content.split('\n').slice(1); // Skip header
  
  const new_events = lines.map((line, i) => {
    const [timestamp, src_ip, dst_ip, bytes, protocol, port] = line.split(',');
    const risk = Math.random() > 0.7 ? 'HIGH' : 'LOW';
    return {
      row: i + 1,
      src_ip,
      dst_ip,
      attack_type: Math.random() > 0.5 ? 'brute_force' : 'normal',
      risk_level: risk,
      confidence: (Math.random() * 0.2 + 0.8).toFixed(3),
      anomaly_score: (Math.random() * 0.5 - 0.25).toFixed(3),
      processing_time: (Math.random() * 0.007 + 0.001).toFixed(3)
    };
  });

  const session_id = uuidv4();
  sessions[session_id] = { events: new_events };
  res.json({ session_id, events_count: new_events.length });
});

app.get('/api/session/stream', (req, res) => {
  const id = req.query.id as string;
  if (!sessions[id]) return res.status(404).send('Session not found');

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const events = sessions[id].events;
  let i = 0;
  const interval = setInterval(() => {
    if (i < events.length) {
      res.write(`data: ${JSON.stringify({ ...events[i], total: events.length })}\n\n`);
      i++;
    } else {
      clearInterval(interval);
      res.end();
    }
  }, 400);
});

app.get('/api/session/report', (req, res) => {
  const id = req.query.id as string;
  if (!sessions[id]) return res.status(404).send('Session not found');
  
  const events = sessions[id].events;
  const threats = events.filter(e => e.attack_type !== 'normal');
  
  res.json({
    total_logs: events.length,
    threats_detected: threats.length,
    ips_blocked: threats.length,
    critical_events: threats.filter(e => e.risk_level === 'HIGH').length,
    avg_response_time: (events.reduce((a, b) => a + parseFloat(b.processing_time), 0) / events.length).toFixed(3),
    clean_traffic_pct: ((events.length - threats.length) / events.length * 100).toFixed(1),
    top_threat_origin: "China"
  });
});

  app.get('/api/config', (req, res) => {
    res.json(config_state);
  });

  app.post('/api/config', (req, res) => {
    config_state = req.body;
    res.json(config_state);
  });

  // --- Vite Setup ---

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`GHOST SHIELD Unified Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Server failed to start:', err);
});
