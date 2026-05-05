import React, { useState, useEffect, useRef } from 'react';
import { useSentinelStore } from '../store';
import { motion, AnimatePresence } from 'motion/react';
import { Terminal, Database, Brain, Globe, ShieldCheck, AlertCircle, XCircle, CheckCircle2 } from 'lucide-react';

interface APIResult {
  status: 'connected' | 'missing' | 'invalid_key' | 'rate_limited' | 'error';
  message: string;
  impact: string;
  latency?: number;
  model?: string;
  daily_limit?: string | number;
  plan?: string;
  query_credits?: number;
}

interface ReadinessState {
  gemini?: APIResult;
  abuseipdb?: APIResult;
  shodan?: APIResult;
  overall?: {
    connected: number;
    total: number;
    ready: boolean;
    level: 'FULL' | 'PARTIAL' | 'OFFLINE';
  };
  error?: boolean;
}

export const APIReadinessModal: React.FC<{ onProceed: () => void; onCancel: () => void }> = ({ onProceed, onCancel }) => {
  const [results, setResults] = useState<ReadinessState | null>(null);
  const [step, setStep] = useState<number>(0);
  const [logs, setLogs] = useState<string[]>(['[SYSTEM] Initiating Readiness Sequence...']);
  const [keyInputs, setKeyInputs] = useState<Record<string, string>>({});
  const { config, updateConfig } = useSentinelStore();
  const logsEndRef = useRef<HTMLDivElement>(null);

  const handleSaveKey = async (keyName: string) => {
    const newKey = keyInputs[keyName];
    if (!newKey) return;
    
    await updateConfig({ [`${keyName}_key`]: newKey });
    
    setStep(0);
    setResults(null);
    setLogs(['[SYSTEM] Re-Initiating Readiness Sequence with updated keys...']);
    runDiagnostics();
  };

  const addLog = (msg: string) => {
    setLogs(prev => [...prev, `[${new Date().toISOString().split('T')[1].slice(0, -1)}] ${msg}`]);
  };

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    runDiagnostics();
  }, []);

  const runDiagnostics = async () => {
    const currentConfig = useSentinelStore.getState().config;
    setStep(1); // Gemini checking
    addLog('Establishing secure TSL/SSL tunnel to AI Core (Gemini)...');
    
    let fetchedData: ReadinessState = { overall: { total: 3, connected: 0, ready: false, level: 'OFFLINE' } };
    
    // Check Gemini
    let gStart = performance.now();
    try {
      const gRes = await fetch('/api/check-gemini', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: currentConfig.gemini_key || '' })
      });
      const gData = await gRes.json();
      gData.latency = Math.floor(performance.now() - gStart);
      fetchedData.gemini = gData;
    } catch {
      fetchedData.gemini = { status: 'error', message: 'Network error', impact: 'Offline fallback', latency: Math.floor(performance.now() - gStart) };
    }
    addLog(`Gemini connection ${fetchedData.gemini.status === 'connected' ? 'ESTABLISHED' : 'FAILED'} (${fetchedData.gemini.latency}ms)`);
    setResults(prev => ({ ...prev, gemini: fetchedData.gemini }));

    // AbuseIPDB Step
    setStep(2);
    addLog('Querying AbuseIPDB Threat Intelligence gateway...');
    let aStart = performance.now();
    try {
      const aRes = await fetch('/api/check-abuseipdb', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: currentConfig.abuseipdb_key || '' })
      });
      const aData = await aRes.json();
      aData.latency = Math.floor(performance.now() - aStart);
      fetchedData.abuseipdb = aData;
    } catch {
      fetchedData.abuseipdb = { status: 'error', message: 'Network error', impact: 'Offline fallback', latency: Math.floor(performance.now() - aStart) };
    }
    addLog(`AbuseIPDB handshake ${fetchedData.abuseipdb.status === 'connected' ? 'VERIFIED' : 'REJECTED'} (${fetchedData.abuseipdb.latency}ms)`);
    setResults(prev => ({ ...prev, abuseipdb: fetchedData.abuseipdb }));

    // Shodan Step
    setStep(3);
    addLog('Authenticating with Shodan Reconnaissance API...');
    let sStart = performance.now();
    try {
      const sRes = await fetch('/api/check-shodan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: currentConfig.shodan_key || '' })
      });
      const sData = await sRes.json();
      sData.latency = Math.floor(performance.now() - sStart);
      fetchedData.shodan = sData;
    } catch {
      fetchedData.shodan = { status: 'error', message: 'Network error', impact: 'Offline fallback', latency: Math.floor(performance.now() - sStart) };
    }
    addLog(`Shodan API access ${fetchedData.shodan.status === 'connected' ? 'GRANTED' : 'DENIED'} (${fetchedData.shodan.latency}ms)`);
    setResults(prev => ({ ...prev, shodan: fetchedData.shodan }));

    // Finalize
    setStep(4);
    
    // Evaluate overall readiness
    let connectedCount = 0;
    if (fetchedData.gemini?.status === 'connected') connectedCount++;
    if (fetchedData.abuseipdb?.status === 'connected') connectedCount++;
    if (fetchedData.shodan?.status === 'connected') connectedCount++;
    
    fetchedData.overall = {
      connected: connectedCount,
      total: 3,
      ready: true, // We allow proceeding even if offline
      level: connectedCount === 3 ? 'FULL' : connectedCount > 0 ? 'PARTIAL' : 'OFFLINE'
    };
    
    addLog(`Diagnostics complete. Systems ready: ${connectedCount}/3`);
    setResults(fetchedData);
  };

  const getStatusDisplay = (status?: string) => {
    switch(status) {
      case 'connected':    return { icon: <CheckCircle2 size={18} />, color: 'text-emerald-400', border: 'border-emerald-500/30', bg: 'bg-emerald-500/10' };
      case 'missing':      return { icon: <AlertCircle size={18} />, color: 'text-amber-400', border: 'border-amber-500/30', bg: 'bg-amber-500/10' };
      case 'invalid_key':  return { icon: <XCircle size={18} />, color: 'text-rose-400', border: 'border-rose-500/30', bg: 'bg-rose-500/10' };
      case 'rate_limited': return { icon: <AlertCircle size={18} />, color: 'text-amber-400', border: 'border-amber-500/30', bg: 'bg-amber-500/10' };
      case 'error':        return { icon: <XCircle size={18} />, color: 'text-rose-400', border: 'border-rose-500/30', bg: 'bg-rose-500/10' };
      default:             return { icon: <div className="w-4 h-4 rounded-full border-2 border-slate-500 border-t-transparent animate-spin" />, color: 'text-cyan-400', border: 'border-cyan-500/30', bg: 'bg-cyan-500/10' };
    }
  };

  const apiConfigs = [
    { key: 'gemini' as const, label: 'Gemini AI Framework', icon: Brain, desc: 'Heuristics & Threat Explanation', activeStep: 1 },
    { key: 'abuseipdb' as const, label: 'AbuseIPDB Intel', icon: ShieldCheck, desc: 'Global IP Reputation Blacklist', activeStep: 2 },
    { key: 'shodan' as const, label: 'Shodan Recon', icon: Globe, desc: 'Open Port & Vulnerability Scan', activeStep: 3 },
  ];

  return (
    <div className="fixed inset-0 bg-black/90 backdrop-blur-sm z-[9999] flex items-center justify-center font-mono p-4">
      <motion.div 
        initial={{ opacity: 0, scale: 0.95, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        className="bg-[#050505] border border-cyan-500/30 rounded-xl w-full max-w-2xl overflow-hidden shadow-[0_0_50px_rgba(0,229,255,0.1)] flex flex-col"
      >
        {/* Header */}
        <div className="bg-gradient-to-r from-cyan-950/40 to-transparent border-b border-cyan-500/20 p-6 flex items-center gap-4">
          <Terminal className="text-cyan-400" size={24} />
          <div>
            <h2 className="text-cyan-400 font-bold tracking-widest uppercase text-sm">Deployment Pre-Flight</h2>
            <div className="text-slate-500 text-xs mt-1">Validating external integrations and API limits</div>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
          
          {/* Left Column: API Status */}
          <div className="space-y-3">
            {apiConfigs.map(({ key, label, icon: Icon, desc, activeStep }) => {
              const result = results?.[key];
              const isChecking = step === activeStep;
              const isPending = step < activeStep;
              const display = getStatusDisplay(isPending ? undefined : (isChecking ? undefined : result?.status));
              
              return (
                <div key={key} className={`border rounded-lg p-4 transition-all duration-500 ${isPending ? 'opacity-40 border-slate-800 bg-slate-900/20' : 
                  (isChecking ? 'translate-x-2 border-cyan-500/50 bg-cyan-950/20 shadow-[0_0_15px_rgba(0,229,255,0.1)]' : `${display.bg} ${display.border}`)}`}>
                  
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className={isPending ? 'text-slate-600' : isChecking ? 'text-cyan-400 animate-pulse' : display.color}>
                        <Icon size={20} />
                      </div>
                      <div className="font-bold text-sm text-slate-200">{label}</div>
                    </div>
                    <div className={display.color}>
                      {display.icon}
                    </div>
                  </div>
                  
                  <div className="text-xs text-slate-400 mb-2">{desc}</div>
                  
                  {/* Detailed Results (only show when done and not pending/checking) */}
                  <AnimatePresence>
                    {!isPending && !isChecking && result && (
                      <motion.div 
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="mt-3 pt-3 border-t border-black/20 text-[10px] space-y-1.5"
                      >
                        <div className="flex justify-between">
                          <span className="text-slate-500">STATUS:</span>
                          <span className={`font-bold ${display.color}`}>{result.message.toUpperCase()}</span>
                        </div>
                        {result.latency && (
                          <div className="flex justify-between">
                            <span className="text-slate-500">LATENCY:</span>
                            <span className="text-slate-300">{result.latency}ms</span>
                          </div>
                        )}
                        {result.model && (
                          <div className="flex justify-between">
                            <span className="text-slate-500">MODEL IN USE:</span>
                            <span className="text-cyan-400">{result.model}</span>
                          </div>
                        )}
                        {result.daily_limit !== undefined && (
                          <div className="flex justify-between">
                            <span className="text-slate-500">RECENT REPORTS:</span>
                            <span className="text-cyan-400">{result.daily_limit}</span>
                          </div>
                        )}
                        {result.plan && (
                          <div className="flex justify-between">
                            <span className="text-slate-500">LICENSE TIER:</span>
                            <span className="text-cyan-400">{result.plan.toUpperCase()}</span>
                          </div>
                        )}
                        {result.query_credits !== undefined && (
                          <div className="flex justify-between">
                            <span className="text-slate-500">REMAINING CMDS:</span>
                            <span className="text-cyan-400">{result.query_credits}</span>
                          </div>
                        )}
                        {result.status !== 'connected' && (
                          <div className="mt-2 pt-2 border-t border-black/20 flex flex-col gap-2">
                            <div className="text-amber-500/80 tracking-wide">WARN: {result.impact}</div>
                            <div className="flex gap-2 items-center">
                              <input 
                                type="password" 
                                placeholder={`${label} Key`} 
                                value={keyInputs[key] || ''}
                                onChange={(e) => setKeyInputs(prev => ({ ...prev, [key]: e.target.value }))}
                                className="flex-1 bg-black/50 border border-slate-700 rounded px-2 py-1 text-[10px] text-slate-300 focus:outline-none focus:border-cyan-500/50 font-mono"
                              />
                              <button 
                                onClick={() => handleSaveKey(key)}
                                disabled={!keyInputs[key]}
                                className="px-2 py-1 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded hover:bg-cyan-500/30 disabled:opacity-50 transition-colors text-[10px] font-bold uppercase tracking-wider"
                              >
                                Retry
                              </button>
                            </div>
                          </div>
                        )}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}
          </div>

          {/* Right Column: Console & Overall */}
          <div className="flex flex-col gap-4">
            
            {/* Terminal View */}
            <div className="flex-1 bg-black border border-slate-800 rounded-lg p-3 font-mono text-[10px] sm:text-xs overflow-hidden flex flex-col relative">
              <div className="absolute top-0 left-0 w-full h-4 bg-gradient-to-b from-black to-transparent z-10"></div>
              <div className="flex-1 overflow-y-auto scrollbar-hide space-y-2 text-slate-400 pb-2 pt-2">
                {logs.map((log, i) => (
                  <motion.div 
                    initial={{ opacity: 0, x: -10 }} 
                    animate={{ opacity: 1, x: 0 }} 
                    key={i} 
                    className={log.includes('ERROR') || log.includes('FAILED') ? 'text-rose-400' :
                               log.includes('ESTABLISHED') || log.includes('VERIFIED') || log.includes('GRANTED') ? 'text-emerald-400' : 
                               log.includes('WARN') ? 'text-amber-400' : 'text-slate-400'}
                  >
                    {log}
                  </motion.div>
                ))}
                <div ref={logsEndRef} />
              </div>
              <div className="absolute bottom-0 left-0 w-full h-4 bg-gradient-to-t from-black to-transparent z-10"></div>
            </div>

            {/* Overall Status */}
            {step === 4 && results && (
              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className={`p-4 rounded-lg border ${results.error ? 'bg-rose-500/10 border-rose-500/40 text-rose-400' : 
                  results.overall?.level === 'FULL' ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400' : 
                  'bg-amber-500/10 border-amber-500/40 text-amber-400'}`}
              >
                <div className="text-center font-bold tracking-widest text-sm mb-1">
                  {results.error ? 'VERIFICATION FAILED' : 
                   results.overall?.level === 'FULL' ? 'ALL SYSTEMS OPERATIONAL' :
                   results.overall?.level === 'PARTIAL' ? 'DEGRADED PERFORMANCE' : 'OFFLINE MODE ENGAGED'}
                </div>
                {!results.error && results.overall?.level !== 'FULL' && (
                  <div className="text-[10px] text-center opacity-80 mt-2 leading-relaxed">
                    Local heuristic fallbacks will be used for offline components. Advanced AI pattern recognition will be limited.
                  </div>
                )}
              </motion.div>
            )}

            {/* Action Buttons */}
            {step === 4 && (
              <motion.div 
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex gap-3 mt-auto"
              >
                <button
                  onClick={onCancel}
                  className="flex-1 py-3 px-4 bg-transparent border border-slate-700 text-slate-300 hover:bg-slate-800 hover:text-white rounded-lg transition-colors text-xs font-bold tracking-wider"
                >
                  ABORT
                </button>
                <button
                  onClick={onProceed}
                  className="flex-[2] py-3 px-4 bg-cyan-500 hover:bg-cyan-400 text-black rounded-lg transition-colors text-xs font-bold tracking-wider shadow-[0_0_20px_rgba(0,229,255,0.3)] hover:shadow-[0_0_30px_rgba(0,229,255,0.5)]"
                >
                  INITIALIZE LIVE FEED
                </button>
              </motion.div>
            )}
          </div>

        </div>
      </motion.div>
    </div>
  );
};

