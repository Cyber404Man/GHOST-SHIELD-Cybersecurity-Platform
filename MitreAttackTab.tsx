import React, { useMemo } from 'react';
import { motion } from 'motion/react';
import { Shield, ExternalLink, Info, AlertTriangle, CheckCircle } from 'lucide-react';
import { useSentinelStore } from '../store';
import { cn } from '../utils';

const TACTIC_COLORS: Record<string, string> = {
  'Reconnaissance': '#378ADD',
  'Credential Access': '#E24B4A',
  'Initial Access': '#EF9F27',
  'Command and Control': '#7F77DD',
  'Impact': '#E24B4A',
  'Collection': '#1D9E75',
  'Discovery': '#888780',
};

export const MITRE_MAP: Record<string, any> = {
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
    description: 'Adversary attempts to gain access to accounts by guessing passwords.',
    severity: 'HIGH',
    mitre_url: 'https://attack.mitre.org/techniques/T1110/'
  },
  ddos: {
    tactic: 'Impact',
    tactic_id: 'TA0040',
    technique: 'Network Denial of Service',
    technique_id: 'T1498',
    sub_technique: 'Direct Network Flood',
    sub_id: 'T1498.001',
    description: 'Adversary floods the network with traffic to deny service.',
    severity: 'CRITICAL',
    mitre_url: 'https://attack.mitre.org/techniques/T1498/'
  },
  bot_activity: {
    tactic: 'Command and Control',
    tactic_id: 'TA0011',
    technique: 'Application Layer Protocol',
    technique_id: 'T1071',
    sub_technique: 'Web Protocols',
    sub_id: 'T1071.001',
    description: 'Adversary uses web protocols to communicate with infected systems.',
    severity: 'HIGH',
    mitre_url: 'https://attack.mitre.org/techniques/T1071/'
  },
  suspicious_login: {
    tactic: 'Initial Access',
    tactic_id: 'TA0001',
    technique: 'Valid Accounts',
    technique_id: 'T1078',
    sub_technique: 'Cloud Accounts',
    sub_id: 'T1078.004',
    description: 'Adversary uses valid credentials to gain initial access.',
    severity: 'HIGH',
    mitre_url: 'https://attack.mitre.org/techniques/T1078/'
  },
  scraping: {
    tactic: 'Collection',
    tactic_id: 'TA0009',
    technique: 'Data from Information Repositories',
    technique_id: 'T1213',
    sub_technique: 'Web-based Repositories',
    sub_id: 'T1213.002',
    description: 'Adversary scrapes data from web-based information repositories.',
    severity: 'MEDIUM',
    mitre_url: 'https://attack.mitre.org/techniques/T1213/'
  }
};

export const MitreAttackTab: React.FC = () => {
  const { events } = useSentinelStore();

  const mitreEvents = useMemo(() => events.filter(e => e.mitre), [events]);

  const tacticStats = useMemo(() => {
    const stats: Record<string, { count: number; tactic_id: string }> = {};
    mitreEvents.forEach(e => {
      if (e.mitre) {
        if (!stats[e.mitre.tactic]) {
          stats[e.mitre.tactic] = { count: 0, tactic_id: e.mitre.tactic_id };
        }
        stats[e.mitre.tactic].count++;
      }
    });
    return Object.entries(stats).map(([name, { count, tactic_id }]) => ({ name, count, tactic_id }));
  }, [mitreEvents]);

  const maxCount = Math.max(...tacticStats.map(s => s.count), 1);

  return (
    <div className="space-y-8 p-6">
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h2 className="text-2xl font-mono font-bold text-text-main tracking-widest uppercase">MITRE ATT&CK Mapping</h2>
          <p className="text-gray-500 font-mono text-xs">Real-time mapping of detected threats to the official MITRE framework.</p>
        </div>
        <div className="px-4 py-2 bg-cyan-500/10 border border-cyan-500/30 rounded flex items-center gap-2">
          <Shield size={16} className="text-cyan-400" />
          <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-widest">{mitreEvents.length} Mapped Events</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Tactic Heatmap */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-card-bg border border-border-strong rounded-lg p-6">
            <h3 className="text-sm font-mono font-bold text-text-main uppercase tracking-widest mb-6 flex items-center gap-2">
              <div className="w-1 h-4 bg-cyan-500" /> Tactics Observed
            </h3>
            
            <div className="space-y-4">
              {tacticStats.length === 0 ? (
                <div className="text-center py-12 text-gray-600 font-mono text-sm italic">
                  No tactics observed in current session.
                </div>
              ) : (
                tacticStats.sort((a, b) => b.count - a.count).map((tactic, i) => (
                  <motion.div 
                    key={tactic.name}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.1 }}
                    className="space-y-2"
                  >
                    <div className="flex justify-between items-center text-xs font-mono">
                      <div className="flex items-center gap-2">
                        <span className="text-text-muted">{tactic.tactic_id}</span>
                        <span className="text-text-main font-bold">{tactic.name}</span>
                      </div>
                      <span className="text-cyan-400">{tactic.count} events</span>
                    </div>
                    <div className="h-4 bg-gray-800 rounded overflow-hidden relative">
                      <motion.div 
                        initial={{ width: 0 }}
                        animate={{ width: `${(tactic.count / maxCount) * 100}%` }}
                        style={{ backgroundColor: TACTIC_COLORS[tactic.name] || '#888780' }}
                        className="h-full rounded-r shadow-[0_0_10px_rgba(0,0,0,0.5)]"
                      />
                    </div>
                  </motion.div>
                ))
              )}
            </div>
          </div>

          <div className="bg-card-bg border border-border-strong rounded-lg p-6">
            <h3 className="text-sm font-mono font-bold text-text-main uppercase tracking-widest mb-6 flex items-center gap-2">
              <div className="w-1 h-4 bg-purple-500" /> Recent Techniques
            </h3>
            
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-[10px]">
                <thead>
                  <tr className="text-gray-500 border-b border-border-strong">
                    <th className="pb-3 font-medium uppercase tracking-widest">ID</th>
                    <th className="pb-3 font-medium uppercase tracking-widest">Technique</th>
                    <th className="pb-3 font-medium uppercase tracking-widest">Tactic</th>
                    <th className="pb-3 font-medium uppercase tracking-widest">Severity</th>
                    <th className="pb-3 font-medium uppercase tracking-widest">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/50">
                  {mitreEvents.slice(0, 10).map((event, i) => (
                    <tr key={event.event_id} className="hover:bg-black/5 dark:hover:bg-white/5 transition-colors group">
                      <td className="py-3 text-cyan-400 font-bold relative group/tooltip cursor-help">
                        {event.mitre?.technique_id}
                        
                        {/* Tooltip */}
                        <div className="absolute z-50 left-0 bottom-full mb-2 hidden group-hover/tooltip:block w-64 p-3 bg-gray-900 border border-gray-700 rounded shadow-xl pointer-events-none">
                          <div className="text-text-main font-bold text-xs mb-1">{event.mitre?.technique}</div>
                          <div className="text-cyan-400 text-[10px] mb-2">{event.mitre?.tactic}</div>
                          <div className="text-text-muted text-[10px] whitespace-normal leading-relaxed">{event.mitre?.description}</div>
                        </div>
                      </td>
                      <td className="py-3 text-text-main">{event.mitre?.technique}</td>
                      <td className="py-3">
                        <span 
                          style={{ color: TACTIC_COLORS[event.mitre?.tactic || ''] }}
                          className="px-2 py-0.5 rounded bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10"
                        >
                          {event.mitre?.tactic}
                        </span>
                      </td>
                      <td className="py-3">
                        <span className={cn(
                          "px-2 py-0.5 rounded",
                          event.risk_level === 'critical' ? "bg-red-500/20 text-red-400" :
                          event.risk_level === 'high' ? "bg-orange-500/20 text-orange-400" :
                          "bg-yellow-500/20 text-yellow-400"
                        )}>
                          {event.risk_level.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-3">
                        <a 
                          href={event.mitre?.mitre_url} 
                          target="_blank" 
                          rel="noreferrer"
                          className="text-gray-500 hover:text-cyan-400 transition-colors"
                        >
                          <ExternalLink size={12} />
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Info Sidebar */}
        <div className="space-y-6">
          <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-lg p-6 space-y-4">
            <div className="flex items-center gap-2 text-cyan-400">
              <Info size={16} />
              <h4 className="text-xs font-mono font-bold uppercase">Framework Intelligence</h4>
            </div>
            <p className="text-[10px] text-text-muted leading-relaxed">
              The MITRE ATT&CK® framework is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
            </p>
            <p className="text-[10px] text-text-muted leading-relaxed">
              GHOST SHIELD uses this mapping to provide standardized context for every threat, enabling faster incident response and better cross-team communication.
            </p>
            <a 
              href="https://attack.mitre.org/" 
              target="_blank" 
              rel="noreferrer"
              className="inline-flex items-center gap-2 text-[10px] text-cyan-400 hover:underline font-mono uppercase"
            >
              Explore Framework <ExternalLink size={10} />
            </a>
          </div>

          <div className="bg-card-bg border border-border-strong rounded-lg p-6 space-y-4">
            <h4 className="text-xs font-mono font-bold text-text-main uppercase tracking-widest">Tactic Definitions</h4>
            <div className="space-y-4">
              <div className="space-y-1">
                <div className="text-[9px] font-bold uppercase" style={{ color: TACTIC_COLORS['Reconnaissance'] }}>Reconnaissance</div>
                <p className="text-[9px] text-gray-500 leading-relaxed">Gathering information to plan future adversary operations.</p>
              </div>
              <div className="space-y-1">
                <div className="text-[9px] font-bold uppercase" style={{ color: TACTIC_COLORS['Credential Access'] }}>Credential Access</div>
                <p className="text-[9px] text-gray-500 leading-relaxed">Techniques for stealing credentials like account names and passwords.</p>
              </div>
              <div className="space-y-1">
                <div className="text-[9px] font-bold uppercase" style={{ color: TACTIC_COLORS['Initial Access'] }}>Initial Access</div>
                <p className="text-[9px] text-gray-500 leading-relaxed">Techniques that use various entry vectors to gain their initial foothold.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
