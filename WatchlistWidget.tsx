import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Eye, X, ShieldAlert, ShieldCheck, ShieldAlert as ShieldCritical } from 'lucide-react';
import { useSentinelStore } from '../store';
import { cn } from '../utils';

export const WatchlistWidget = () => {
  const { watchlist, toggleWatchIP, setSelectedIP, events } = useSentinelStore();

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-red-500 border-red-500/20 bg-red-500/10';
      case 'high': return 'text-orange-500 border-orange-500/20 bg-orange-500/10';
      case 'medium': return 'text-yellow-500 border-yellow-500/20 bg-yellow-500/10';
      default: return 'text-green-500 border-green-500/20 bg-green-500/10';
    }
  };

  return (
    <div className="dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 rounded-xl p-6">
      <div className="flex items-center gap-2 mb-4 font-mono text-cyan-400">
        <Eye size={18} />
        <h2 className="text-sm font-bold tracking-widest uppercase">
          WATCHLIST ({watchlist.length})
        </h2>
      </div>

      {watchlist.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-32 text-gray-600 gap-2">
          <Eye size={32} className="opacity-20" />
          <p className="text-xs font-mono uppercase">No IPs under surveillance</p>
        </div>
      ) : (
        <div className="max-h-64 overflow-y-auto pr-2 space-y-2">
          <AnimatePresence>
            {watchlist.map(ip => {
              const event = events.find(e => e.src_ip === ip);
              const risk = event?.risk_level || 'low';
              const isBlocked = event?.status === 'blocked';

              return (
                <motion.button
                  key={ip}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 10 }}
                  onClick={() => setSelectedIP(ip)}
                  className={cn(
                    "w-full flex items-center justify-between p-2 rounded border transition-all",
                    risk === 'critical' ? "animate-pulse border-red-500/30" : "border-black/5 dark:border-white/5 hover:border-black/10 dark:border-white/10"
                  )}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-text-main">{ip}</span>
                    {isBlocked && (
                      <span className="text-[10px] font-mono text-red-500 line-through">BLOCKED</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={cn("text-[10px] font-mono px-1.5 py-0.5 rounded border", getRiskColor(risk))}>
                      {risk.toUpperCase()}
                    </span>
                    <X 
                      size={14} 
                      className="text-gray-600 hover:text-red-400" 
                      onClick={(e) => { e.stopPropagation(); toggleWatchIP(ip); }}
                    />
                  </div>
                </motion.button>
              );
            })}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
};
