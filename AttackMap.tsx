import React, { useMemo, useState, useEffect } from 'react';
import { ComposableMap, Geographies, Geography, ZoomableGroup, Marker, Line } from 'react-simple-maps';
import { useSentinelStore } from '../store';
import { Globe, Plus, Minus, Home, Shield, AlertTriangle, Zap, Info, Filter, Clock, Activity, Database, Cpu, Search, ExternalLink, Bot } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '../lib/utils';

const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";
const PALESTINE_COORDS: [number, number] = [35.2332, 31.9522];

const getRiskColor = (risk: string) => {
  switch (risk) {
    case 'critical': return '#ef4444';
    case 'high': return '#f97316';
    case 'medium': return '#eab308';
    default: return '#22d3ee';
  }
};

const AttackDetailsPopup = ({ attack, onClose }: { attack: any, onClose: () => void }) => {
  return (
    <motion.div 
      initial={{ opacity: 0, scale: 0.9, y: 20 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.9, y: 20 }}
      className="absolute bottom-24 left-1/2 -translate-x-1/2 w-80 dark:bg-[#0a0a0a] bg-gray-100/95 backdrop-blur-xl border border-cyan-500/30 rounded-lg shadow-[0_0_40px_rgba(0,229,255,0.15)] z-[100] overflow-hidden"
    >
      <div className="bg-cyan-500/10 p-3 border-b border-cyan-500/20 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap size={14} className="text-cyan-400" />
          <span className="font-mono text-[10px] font-bold text-text-main uppercase tracking-widest">Intelligence Profile</span>
        </div>
        <button onClick={onClose} className="text-gray-500 hover:text-text-main transition-colors">
          <Plus size={14} className="rotate-45" />
        </button>
      </div>
      <div className="p-4 space-y-4">
        <div className="flex justify-between items-start">
          <div>
            <div className="text-[8px] font-mono text-gray-500 uppercase mb-1">Source IP</div>
            <div className="text-sm font-mono text-cyan-400 font-bold">{attack.src_ip}</div>
            <div className="text-[10px] font-mono text-text-muted">{attack.country} • {attack.city || 'Auto-located'}</div>
          </div>
          <div className="text-right">
            <div className="text-[8px] font-mono text-gray-500 uppercase mb-1">Risk Score</div>
            <div className={cn(
              "text-sm font-mono font-bold",
              attack.risk_level === 'critical' ? "text-red-500" : "text-orange-500"
            )}>{100 - (attack.reputation_score || 0)}/100</div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div className="bg-black/5 dark:bg-white/5 p-2 rounded border border-black/5 dark:border-white/5">
            <div className="text-[8px] font-mono text-gray-500 uppercase mb-1">Attack Vector</div>
            <div className="text-[10px] font-mono text-text-main uppercase">{attack.attack_type.replace('_', ' ')}</div>
          </div>
          <div className="bg-black/5 dark:bg-white/5 p-2 rounded border border-black/5 dark:border-white/5">
            <div className="text-[8px] font-mono text-gray-500 uppercase mb-1">Target System</div>
            <div className="text-[10px] font-mono text-text-main uppercase">Main Gateway</div>
          </div>
        </div>

        <div className="space-y-2">
          <div className="text-[8px] font-mono text-gray-500 uppercase">OSINT Enrichment</div>
          <div className="flex flex-wrap gap-2">
            {attack.bot_score > 0.6 && (
              <span className="flex items-center gap-1 px-1.5 py-0.5 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-[8px] font-mono uppercase">
                <Bot size={8} /> Botnet Activity
              </span>
            )}
            <span className="flex items-center gap-1 px-1.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-[8px] font-mono uppercase">
              <Shield size={8} /> Known Attacker
            </span>
            <span className="flex items-center gap-1 px-1.5 py-0.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded text-[8px] font-mono uppercase">
              <Zap size={8} /> High Velocity
            </span>
          </div>
        </div>

        <button 
          onClick={() => {
            useSentinelStore.getState().setSelectedIP(attack.src_ip);
            onClose();
          }}
          className="w-full py-2 bg-cyan-500 text-[#0f172a] dark:text-[#050505] font-mono text-[10px] uppercase font-bold rounded hover:bg-cyan-400 transition-colors flex items-center justify-center gap-2"
        >
          Full Investigation <ExternalLink size={12} />
        </button>
      </div>
    </motion.div>
  );
};

const AIInsightsPanel = ({ attacks }: { attacks: any[] }) => {
  const insights = useMemo(() => {
    if (attacks.length === 0) return null;
    
    const topRegion = attacks.reduce((acc: any, curr) => {
      acc[curr.country] = (acc[curr.country] || 0) + 1;
      return acc;
    }, {});
    const mostTargeted = Object.entries(topRegion).sort((a: any, b: any) => b[1] - a[1])[0];

    const topAttack = attacks.reduce((acc: any, curr) => {
      acc[curr.attack_type] = (acc[curr.attack_type] || 0) + 1;
      return acc;
    }, {});
    const mostCommon = Object.entries(topAttack).sort((a: any, b: any) => b[1] - a[1])[0];

    return {
      region: mostTargeted ? mostTargeted[0] : 'N/A',
      attack: mostCommon ? mostCommon[0].replace('_', ' ') : 'N/A',
      patterns: attacks.length > 50 ? 'High-volume distributed scan detected' : 'Isolated targeted attempts'
    };
  }, [attacks]);

  if (!insights) return null;

  return (
    <div className="absolute top-20 right-6 w-64 space-y-4 z-10">
      <motion.div 
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        className="dark:bg-[#0a0a0a] bg-gray-100/80 backdrop-blur-md border border-cyan-500/20 p-4 rounded-lg space-y-4"
      >
        <div className="flex items-center gap-2 border-b border-black/5 dark:border-white/5 pb-2">
          <Cpu size={14} className="text-cyan-400" />
          <span className="font-mono text-[10px] font-bold text-text-main uppercase tracking-widest">AI Threat Insights</span>
        </div>

        <div className="space-y-3">
          <div className="space-y-1">
            <div className="text-[8px] font-mono text-gray-500 uppercase">Top Threat Today</div>
            <div className="text-[10px] font-mono text-red-400 uppercase font-bold">{insights.attack}</div>
          </div>
          <div className="space-y-1">
            <div className="text-[8px] font-mono text-gray-500 uppercase">Most Targeted Region</div>
            <div className="text-[10px] font-mono text-cyan-400 uppercase font-bold">{insights.region}</div>
          </div>
          <div className="space-y-1">
            <div className="text-[8px] font-mono text-gray-500 uppercase">Suspicious Patterns</div>
            <div className="text-[10px] font-mono text-yellow-400 uppercase leading-tight">{insights.patterns}</div>
          </div>
        </div>
      </motion.div>

      <motion.div 
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: 0.1 }}
        className="dark:bg-[#0a0a0a] bg-gray-100/80 backdrop-blur-md border border-black/5 dark:border-white/5 p-4 rounded-lg"
      >
        <div className="flex items-center gap-2 mb-3">
          <Activity size={14} className="text-green-400" />
          <span className="font-mono text-[10px] font-bold text-text-main uppercase tracking-widest">System Flow</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <div className="flex items-center gap-2 w-full">
            <div className="w-6 h-6 rounded bg-black/5 dark:bg-white/5 flex items-center justify-center border border-black/10 dark:border-white/10"><Globe size={10} /></div>
            <div className="flex-1 h-px bg-gradient-to-r from-white/5 to-cyan-500/50" />
            <div className="w-6 h-6 rounded bg-cyan-500/20 flex items-center justify-center border border-cyan-500/40"><Cpu size={10} className="text-cyan-400" /></div>
            <div className="flex-1 h-px bg-gradient-to-r from-cyan-500/50 to-white/5" />
            <div className="w-6 h-6 rounded bg-black/5 dark:bg-white/5 flex items-center justify-center border border-black/10 dark:border-white/10"><Shield size={10} /></div>
          </div>
          <div className="text-[8px] font-mono text-gray-500 uppercase flex justify-between w-full">
            <span>Traffic</span>
            <span>AI Analysis</span>
            <span>Defense</span>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export const AttackMap = () => {
  const { events, setSelectedIP, prediction } = useSentinelStore();
  const [zoom, setZoom] = useState(2.5);
  const [center, setCenter] = useState<[number, number]>(PALESTINE_COORDS);
  const [selectedAttack, setSelectedAttack] = useState<any>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterType, setFilterType] = useState<string>('all');
  const [timeRange, setTimeRange] = useState(100);

  const attacks = useMemo(() => {
    return events
      .filter(e => e.attack_type !== 'normal')
      .filter(e => filterSeverity === 'all' || e.risk_level === filterSeverity)
      .filter(e => filterType === 'all' || e.attack_type === filterType)
      .slice(0, Math.floor((events.length * timeRange) / 100))
      .map(e => ({
        ...e,
        lng: Array.isArray(e.map_coords) ? e.map_coords[0] : (e.map_coords?.lng || 0),
        lat: Array.isArray(e.map_coords) ? e.map_coords[1] : (e.map_coords?.lat || 0),
        id: e.event_id
      }));
  }, [events, filterSeverity, filterType, timeRange]);

  const attackTypes = useMemo(() => {
    const types = new Set(events.filter(e => e.attack_type !== 'normal').map(e => e.attack_type));
    return Array.from(types);
  }, [events]);

  return (
    <div className="bg-app-bg border border-border-subtle rounded-xl h-full flex flex-col relative overflow-hidden group">
      {/* Header Controls */}
      <div className="p-6 flex items-center justify-between z-10 bg-gradient-to-b from-black/80 to-transparent">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="relative">
              <Globe size={20} className="text-cyan-400" />
              <div className="absolute inset-0 bg-cyan-400/20 blur-lg rounded-full animate-pulse" />
            </div>
            <div className="flex flex-col">
              <span className="font-mono text-xs font-bold uppercase tracking-widest text-text-main">Global Threat Intelligence</span>
              <span className="font-mono text-[8px] text-cyan-400/60 uppercase">Real-time OSINT & AI Analysis</span>
            </div>
          </div>

          <div className="h-8 w-px bg-black/10 dark:bg-white/10 mx-2" />

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 bg-black/40 border border-black/5 dark:border-white/5 rounded px-2 py-1">
              <Filter size={12} className="text-gray-500" />
              <select 
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="bg-transparent font-mono text-[10px] text-text-main focus:outline-none uppercase"
              >
                <option value="all">All Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
              </select>
            </div>

            <div className="flex items-center gap-2 bg-black/40 border border-black/5 dark:border-white/5 rounded px-2 py-1">
              <Search size={12} className="text-gray-500" />
              <select 
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className="bg-transparent font-mono text-[10px] text-text-main focus:outline-none uppercase max-w-[120px]"
              >
                <option value="all">All Types</option>
                {attackTypes.map(t => (
                  <option key={t} value={t}>{t.replace('_', ' ')}</option>
                ))}
              </select>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-black/60 border border-cyan-500/30 rounded-lg p-1 shadow-[0_0_15px_rgba(0,229,255,0.1)]">
            <button onClick={() => setZoom(Math.min(zoom + 0.5, 8))} className="w-8 h-8 flex items-center justify-center text-cyan-400 hover:bg-cyan-400/20 rounded transition-colors"><Plus size={16} /></button>
            <div className="h-4 w-px bg-black/10 dark:bg-white/10" />
            <button onClick={() => setZoom(Math.max(zoom - 0.5, 0.8))} className="w-8 h-8 flex items-center justify-center text-cyan-400 hover:bg-cyan-400/20 rounded transition-colors"><Minus size={16} /></button>
            <div className="h-4 w-px bg-black/10 dark:bg-white/10" />
            <button onClick={() => { setZoom(2.5); setCenter(PALESTINE_COORDS); }} className="w-8 h-8 flex items-center justify-center text-cyan-400 hover:bg-cyan-400/20 rounded transition-colors"><Home size={16} /></button>
          </div>
        </div>
      </div>

      <AIInsightsPanel attacks={attacks} />

      <AnimatePresence>
        {selectedAttack && (
          <AttackDetailsPopup 
            attack={selectedAttack} 
            onClose={() => setSelectedAttack(null)} 
          />
        )}
      </AnimatePresence>

      <div className="flex-1 relative bg-app-bg">
        <ComposableMap
          projection="geoMercator"
          style={{ width: "100%", height: "100%", background: "transparent" }}
        >
          <ZoomableGroup
            zoom={zoom}
            center={center}
            onMoveEnd={(position) => {
              setZoom(position.zoom);
              setCenter(position.coordinates);
            }}
            minZoom={0.8}
            maxZoom={8}
          >
            <Geographies geography={GEO_URL}>
              {({ geographies }) =>
                geographies.map((geo) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill="#0a0a0a"
                    stroke="#1a1a1a"
                    strokeWidth={0.5}
                    style={{
                      default: { outline: "none" },
                      hover: { fill: "#111", outline: "none" },
                      pressed: { outline: "none" },
                    }}
                  />
                ))
              }
            </Geographies>

            {/* Predicted Attack Line */}
            {prediction && prediction.likely_source_coords && (
              <motion.g initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <Line
                  from={prediction.likely_source_coords}
                  to={PALESTINE_COORDS}
                  stroke="#f59e0b"
                  strokeWidth={2}
                  strokeDasharray="4 4"
                  strokeLinecap="round"
                />
              </motion.g>
            )}

            {attacks.map((attack) => (
              <motion.g 
                key={attack.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.5 }}
              >
                <Line
                  from={[attack.lng, attack.lat]}
                  to={PALESTINE_COORDS}
                  stroke={getRiskColor(attack.risk_level)}
                  strokeWidth={attack.risk_level === 'critical' ? 1.5 : 0.8}
                  strokeLinecap="round"
                  opacity={0.4}
                  className="cursor-pointer hover:opacity-100 transition-opacity"
                  onClick={() => setSelectedAttack(attack)}
                />
                <Marker coordinates={[attack.lng, attack.lat]}>
                  <circle
                    r={attack.risk_level === 'critical' ? 4 : 3}
                    fill={getRiskColor(attack.risk_level)}
                    className={cn(attack.risk_level === 'critical' && "animate-pulse")}
                    style={{ cursor: "pointer" }}
                    onClick={() => setSelectedAttack(attack)}
                  />
                  {attack.risk_level === 'critical' && (
                    <circle
                      r={8}
                      fill="none"
                      stroke={getRiskColor(attack.risk_level)}
                      strokeWidth={0.5}
                      className="animate-ping"
                    />
                  )}
                </Marker>
              </motion.g>
            ))}

            <Marker coordinates={PALESTINE_COORDS}>
              <circle r={6} fill="#00e5ff" />
              <circle r={12} fill="none" stroke="#00e5ff" strokeWidth={1} className="animate-pulse" />
              <circle r={20} fill="none" stroke="#00e5ff" strokeWidth={0.2} opacity={0.3} />
            </Marker>
          </ZoomableGroup>
        </ComposableMap>

        {/* Bottom HUD */}
        <div className="absolute bottom-6 left-6 right-6 flex items-end justify-between pointer-events-none">
          <div className="bg-black/60 backdrop-blur-md border border-black/5 dark:border-white/5 p-4 rounded-lg pointer-events-auto space-y-3 w-72">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Clock size={12} className="text-gray-500" />
                <span className="font-mono text-[10px] text-text-muted uppercase">Timeline Analysis</span>
              </div>
              <span className="font-mono text-[10px] text-cyan-400">{timeRange}%</span>
            </div>
            <input 
              type="range" 
              min="1" 
              max="100" 
              value={timeRange}
              onChange={(e) => setTimeRange(parseInt(e.target.value))}
              className="w-full h-1 bg-black/10 dark:bg-white/10 rounded-lg appearance-none cursor-pointer accent-cyan-400"
            />
            <div className="flex justify-between font-mono text-[8px] text-gray-600 uppercase">
              <span>Historical</span>
              <span>Live Stream</span>
            </div>
          </div>

          <div className="bg-black/60 backdrop-blur-md border border-black/5 dark:border-white/5 p-4 rounded-lg pointer-events-auto space-y-2">
            <div className="font-mono text-[8px] text-gray-500 uppercase border-b border-black/5 dark:border-white/5 pb-1 mb-2">Risk Legend</div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]" />
                <span className="font-mono text-[10px] text-text-muted uppercase">Critical</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-orange-500" />
                <span className="font-mono text-[10px] text-text-muted uppercase">High</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-cyan-400" />
                <span className="font-mono text-[10px] text-text-muted uppercase">Normal</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
