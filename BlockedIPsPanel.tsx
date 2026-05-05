import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { X, Shield, Lock, Search, Trash2, Eye } from 'lucide-react';
import { useSentinelStore } from '../store';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface BlockedIPsPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

export const BlockedIPsPanel = ({ isOpen, onClose }: BlockedIPsPanelProps) => {
  const { blockedIPs, unblockIP, setSelectedIP, events } = useSentinelStore();
  const [search, setSearch] = useState('');

  const blockedIPDetails = useMemo(() => {
    return blockedIPs
      .map(b => {
        const latestEvent = events.find(e => e.src_ip === b.ip) || {
          timestamp: b.blocked_at,
          attack_type: b.attack_type,
          risk_level: b.risk_level,
          country: b.country
        };
        return {
          ip: b.ip,
          country: latestEvent.country,
          attack_type: latestEvent.attack_type,
          risk_level: latestEvent.risk_level,
          time_blocked: b.blocked_at
        };
      })
      .filter(b => b.ip.includes(search));
  }, [blockedIPs, events, search]);

  const handleUnblock = (ip: string) => {
    unblockIP(ip);
    // Assuming a simple toast mechanism exists, or I can add one.
    // For now, just logging.
    console.log(`IP ${ip} has been unblocked`);
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
          />
          <motion.div 
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="fixed top-0 right-0 h-full w-full max-w-md dark:bg-[#0a0a0a] bg-gray-100 border-l border-black/10 dark:border-white/10 z-50 shadow-2xl flex flex-col"
          >
            <div className="p-6 border-b border-black/5 dark:border-white/5 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Lock className="text-cyan-400" size={24} />
                <h2 className="text-lg font-mono text-text-main uppercase tracking-widest">Blocked IPs</h2>
              </div>
              <button onClick={onClose} className="text-gray-500 hover:text-text-main transition-colors">
                <X size={24} />
              </button>
            </div>

            <div className="p-6 border-b border-black/5 dark:border-white/5">
              <div className="text-sm font-mono text-text-muted mb-4">{blockedIPs.length} IPs Blocked</div>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
                <input 
                  type="text"
                  placeholder="Search IP..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full bg-app-bg border border-border-subtle rounded px-10 py-2 font-mono text-sm text-text-main focus:outline-none focus:border-cyan-400/50"
                />
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {blockedIPDetails.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-64 text-gray-500 gap-4">
                  <Shield className="text-green-500/50" size={48} />
                  <p className="font-mono text-sm uppercase">No IPs blocked yet</p>
                </div>
              ) : (
                blockedIPDetails.map(b => (
                  <div key={b.ip} className="bg-black/5 dark:bg-white/5 border border-black/5 dark:border-white/5 p-4 rounded-lg space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-lg"></span>
                        <span className="font-mono text-sm text-cyan-400 cursor-pointer hover:underline" onClick={() => setSelectedIP(b.ip)}>{b.ip}</span>
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => handleUnblock(b.ip)} className="p-2 bg-red-500/10 text-red-400 hover:bg-red-500/20 rounded transition-colors" title="Unblock">
                          <Trash2 size={14} />
                        </button>
                        <button onClick={() => setSelectedIP(b.ip)} className="p-2 bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 rounded transition-colors" title="Details">
                          <Eye size={14} />
                        </button>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <span className="px-2 py-0.5 bg-black/5 dark:bg-white/5 rounded text-[10px] font-mono text-text-muted uppercase">{b.attack_type}</span>
                      <span className={cn(
                        "px-2 py-0.5 rounded text-[10px] font-mono uppercase",
                        b.risk_level === 'critical' ? "bg-red-500/10 text-red-500" : "bg-yellow-500/10 text-yellow-500"
                      )}>{b.risk_level}</span>
                    </div>
                    <div className="text-[10px] font-mono text-gray-500">Blocked {new Date(b.time_blocked).toLocaleTimeString()}</div>
                  </div>
                ))
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};
