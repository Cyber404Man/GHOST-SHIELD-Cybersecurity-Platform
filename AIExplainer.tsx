import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Bot, RefreshCcw, AlertCircle } from 'lucide-react';
import { explainThreat, ThreatData } from '../lib/gemini';

interface AIExplainerProps {
  threatData: ThreatData;
  apiKey?: string;
  onComplete?: (explanation: string) => void;
}

export const AIExplainer: React.FC<AIExplainerProps> = ({ threatData, apiKey, onComplete }) => {
  const [explanation, setExplanation] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [displayedText, setDisplayedText] = useState<string>('');

  const fetchExplanation = async () => {
    setLoading(true);
    setError(null);
    setExplanation('');
    setDisplayedText('');

    try {
      const result = await explainThreat(threatData, apiKey || '');
      setExplanation(result);
      if (onComplete) onComplete(result);
    } catch (err) {
      setError('Failed to generate AI analysis.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchExplanation();
  }, [threatData.src_ip, apiKey]);

  // Typewriter effect
  useEffect(() => {
    if (!loading && explanation && displayedText.length < explanation.length) {
      const timeout = setTimeout(() => {
        setDisplayedText(explanation.slice(0, displayedText.length + 1));
      }, 20);
      return () => clearTimeout(timeout);
    }
  }, [loading, explanation, displayedText]);

  return (
    <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-cyan-400">
          <Bot size={16} />
          <span className="text-[10px] font-mono uppercase tracking-widest font-bold">🤖 AI ANALYSIS</span>
        </div>
        {loading && (
          <div className="flex gap-1">
            <motion.div 
              animate={{ opacity: [0.2, 1, 0.2] }} 
              transition={{ repeat: Infinity, duration: 1 }} 
              className="w-1 h-1 bg-cyan-400 rounded-full" 
            />
            <motion.div 
              animate={{ opacity: [0.2, 1, 0.2] }} 
              transition={{ repeat: Infinity, duration: 1, delay: 0.2 }} 
              className="w-1 h-1 bg-cyan-400 rounded-full" 
            />
            <motion.div 
              animate={{ opacity: [0.2, 1, 0.2] }} 
              transition={{ repeat: Infinity, duration: 1, delay: 0.4 }} 
              className="w-1 h-1 bg-cyan-400 rounded-full" 
            />
          </div>
        )}
      </div>

      <div className="min-h-[60px]">
        {loading ? (
          <div className="space-y-2">
            <div className="h-3 bg-cyan-400/10 rounded w-full animate-pulse" />
            <div className="h-3 bg-cyan-400/10 rounded w-3/4 animate-pulse" />
          </div>
        ) : error ? (
          <div className="flex items-center gap-2 text-red-400 text-xs font-mono">
            <AlertCircle size={14} />
            {error}
          </div>
        ) : (
          <p className="text-xs font-mono text-cyan-100 leading-relaxed">
            {displayedText}
            {displayedText.length < explanation.length && (
              <span className="inline-block w-1.5 h-3 ml-1 bg-cyan-400 animate-pulse align-middle" />
            )}
          </p>
        )}
      </div>

      <div className="flex items-center justify-between pt-2 border-t border-cyan-500/10">
        <div className="text-[8px] font-mono text-cyan-500/60 uppercase">Powered by Gemini AI</div>
        {!loading && !error && (
          <button 
            onClick={fetchExplanation}
            className="text-[8px] font-mono text-cyan-400 hover:text-cyan-300 uppercase flex items-center gap-1 transition-colors"
          >
            <RefreshCcw size={10} /> Re-analyze
          </button>
        )}
      </div>
    </div>
  );
};
