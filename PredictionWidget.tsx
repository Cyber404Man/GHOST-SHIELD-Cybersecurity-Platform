import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Brain, Zap, ShieldAlert, Clock, Info, ShieldCheck, CheckCircle } from 'lucide-react';
import { useSentinelStore } from '../store';
import { cn } from '../utils';

export const PredictionWidget: React.FC = () => {
  const { prediction, blockIP, dismissPrediction } = useSentinelStore();
  const [actionTaken, setActionTaken] = useState(false);

  if (!prediction) {
    return (
      <div className="bg-card-bg border border-border-strong rounded-lg p-6 text-center">
        <div className="flex justify-center mb-4">
          <Brain className="text-gray-600 animate-pulse" size={32} />
        </div>
        <h3 className="text-sm font-mono text-text-muted uppercase tracking-widest">AI Prediction Engine</h3>
        <p className="text-xs text-gray-600 mt-2">Analyzing patterns for next likely threat...</p>
      </div>
    );
  }

  const handleTakeAction = () => {
    blockIP({
      ip: prediction.likely_source_ip,
      country: 'Unknown',
      city: 'Unknown',
      attack_type: prediction.predicted_attack,
      risk_level: 'critical', // Preemptive block should be strong
      blocked_at: new Date().toISOString(),
      flag: '🚩'
    });
    
    setActionTaken(true);
    
    // Dismiss automatically after a few seconds
    setTimeout(() => {
      dismissPrediction();
      setActionTaken(false);
    }, 3000);
  };

  const handleDismiss = () => {
    dismissPrediction();
    setActionTaken(false);
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={
        prediction.confidence === 'HIGH' 
          ? { opacity: 1, y: 0, boxShadow: ["0px 0px 5px rgba(239, 68, 68, 0.1)", "0px 0px 25px rgba(239, 68, 68, 0.4)", "0px 0px 5px rgba(239, 68, 68, 0.1)"] }
          : { opacity: 1, y: 0 }
      }
      transition={
        prediction.confidence === 'HIGH' 
          ? { boxShadow: { duration: 2, repeat: Infinity, ease: "easeInOut" } }
          : undefined
      }
      exit={{ opacity: 0, scale: 0.95 }}
      className={cn(
        "bg-card-bg border rounded-lg overflow-hidden transition-all duration-500",
        prediction.confidence === 'HIGH' 
          ? "border-red-500 border-2" 
          : "border-cyan-500/30 shadow-[0_0_20px_rgba(0,229,255,0.05)]"
      )}
    >
      <div className="bg-cyan-500/10 border-b border-cyan-500/20 p-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Brain size={16} className="text-cyan-400" />
          <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-widest">AI Prediction Engine</span>
        </div>
        <div className={cn(
          "px-2 py-0.5 rounded text-[8px] font-mono font-bold uppercase",
          prediction.confidence === 'HIGH' ? "bg-red-500/20 text-red-400" : "bg-yellow-500/20 text-yellow-400"
        )}>
          {prediction.confidence} CONFIDENCE
        </div>
      </div>

      <div className="p-4 space-y-4">
        {actionTaken ? (
          <motion.div 
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="flex flex-col items-center justify-center py-8 text-center space-y-3"
          >
            <CheckCircle className="text-green-500 w-12 h-12 mb-2" />
            <div className="text-green-400 font-mono font-bold uppercase text-sm">Threat Neutralized</div>
            <div className="text-xs text-text-muted font-mono">
              Preemptive block applied to {prediction.likely_source_ip}
            </div>
          </motion.div>
        ) : (
          <>
            <div>
              <div className="text-[9px] text-gray-500 uppercase font-mono mb-1">Next Likely Attack:</div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 bg-red-500 rounded-full animate-ping" />
                <div className="text-lg font-mono font-bold text-text-main uppercase tracking-tighter">
                  {prediction.predicted_attack.replace('_', ' ')}
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between items-center text-[10px] font-mono">
                <span className="text-gray-500">Probability:</span>
                <span className="text-cyan-400">{prediction.probability}%</span>
              </div>
              <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                <motion.div 
                  initial={{ width: 0 }}
                  animate={{ width: `${prediction.probability}%` }}
                  className={cn(
                    "h-full rounded-full",
                    prediction.probability > 75 ? "bg-red-500" : "bg-cyan-500"
                  )}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 py-2 border-y border-black/5 dark:border-white/5">
              <div className="space-y-1">
                <div className="flex items-center gap-1 text-[8px] text-gray-500 uppercase font-mono">
                  <Clock size={8} /> ETA
                </div>
                <div className="text-xs font-mono text-text-main">~{prediction.eta_minutes} minutes</div>
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-1 text-[8px] text-gray-500 uppercase font-mono">
                  <ShieldAlert size={8} /> Based On
                </div>
                <div className="text-xs font-mono text-text-main truncate uppercase">{prediction.based_on.replace('_', ' ')}</div>
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-[8px] text-gray-500 uppercase font-mono">Likely Source IP:</div>
              <div className="text-xs font-mono text-cyan-400">{prediction.likely_source_ip}</div>
            </div>

            <div className={cn(
              "border p-3 rounded space-y-2",
              prediction.confidence === 'HIGH'
                ? "bg-red-500/5 border-red-500/20"
                : "bg-yellow-500/5 border-yellow-500/20"
            )}>
              <div className={cn(
                "flex items-center gap-2",
                prediction.confidence === 'HIGH' ? "text-red-500" : "text-yellow-500"
              )}>
                <Zap size={12} />
                <span className="text-[9px] font-mono font-bold uppercase">Preemptive Action:</span>
              </div>
              <p className="text-[10px] text-text-muted leading-relaxed italic">
                "{prediction.recommendation}"
              </p>
              <div className="flex items-center gap-1 mt-2 text-[8px] font-mono font-bold text-cyan-400 uppercase opacity-70">
                <Brain size={10} /> AI Recommended Action
              </div>
            </div>

            <div className="flex gap-2">
              <button 
                onClick={handleTakeAction}
                disabled={prediction.likely_source_ip === 'Unknown'}
                className={cn(
                  "flex-1 py-2 font-mono text-[10px] font-bold uppercase tracking-widest rounded transition-all flex items-center justify-center gap-1",
                  prediction.likely_source_ip === 'Unknown' 
                    ? "bg-gray-800 text-gray-500 cursor-not-allowed"
                    : "bg-cyan-500 text-[#0f172a] dark:text-[#050505] hover:bg-cyan-400"
                )}
              >
                <ShieldCheck size={12} /> Take Action
              </button>
              <button 
                onClick={handleDismiss}
                className="px-3 py-2 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-text-muted font-mono text-[10px] uppercase tracking-widest rounded hover:bg-black/10 dark:bg-white/10 transition-all"
              >
                Dismiss
              </button>
            </div>

            <div className="text-[8px] text-gray-600 font-mono text-center uppercase">
              Last updated: {new Date(prediction.timestamp || Date.now()).toLocaleTimeString()}
            </div>
          </>
        )}
      </div>
    </motion.div>
  );
};
