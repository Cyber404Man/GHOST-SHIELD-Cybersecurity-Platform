import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Shield, Zap, Folder, ArrowRight, FileText, CheckCircle2, Loader2, Globe } from 'lucide-react';
import { useSentinelStore } from '../store';
import Papa from 'papaparse';
import { APIReadinessModal } from './APIReadinessModal';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SCREEN 1 — INTRO
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export const IntroScreen: React.FC<{ onSkip: () => void }> = ({ onSkip }) => {
  const [text, setText] = useState('');
  const [showTagline, setShowTagline] = useState(false);
  const [status, setStatus] = useState('');
  const fullText = "GHOST SHIELD";

  useEffect(() => {
    // Typewriter effect for title
    const titleTimer = setTimeout(() => {
      let i = 0;
      const interval = setInterval(() => {
        setText(fullText.slice(0, i + 1));
        i++;
        if (i === fullText.length) clearInterval(interval);
      }, 100);
    }, 800);

    // Tagline fade in
    const taglineTimer = setTimeout(() => setShowTagline(true), 1400);

    // Status sequence
    const statusTimer1 = setTimeout(() => setStatus('Initializing AI Core.'), 2000);
    const statusTimer2 = setTimeout(() => setStatus('Initializing AI Core..'), 2200);
    const statusTimer3 = setTimeout(() => setStatus('Initializing AI Core...'), 2400);
    const statusTimer4 = setTimeout(() => setStatus('READY'), 2800);

    return () => {
      clearTimeout(titleTimer);
      clearTimeout(taglineTimer);
      clearTimeout(statusTimer1);
      clearTimeout(statusTimer2);
      clearTimeout(statusTimer3);
      clearTimeout(statusTimer4);
    };
  }, []);

  return (
    <motion.div 
      initial={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.5 }}
      className="fixed inset-0 bg-black z-[100] flex flex-col items-center justify-center overflow-hidden"
    >
      <button 
        onClick={onSkip}
        className="absolute top-8 right-8 text-cyan-500/50 hover:text-cyan-400 font-mono text-xs tracking-widest transition-colors uppercase"
      >
        Skip Intro ›
      </button>

      <div className="flex flex-col items-center gap-8">
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3, duration: 0.8 }}
        >
          <motion.div
            animate={{ 
              filter: ['drop-shadow(0 0 10px #00e5ff)', 'drop-shadow(0 0 25px #00e5ff)', 'drop-shadow(0 0 10px #00e5ff)'],
            }}
            transition={{ repeat: Infinity, duration: 2 }}
          >
            <Shield className="w-24 h-24 text-cyan-400" strokeWidth={1.5} />
          </motion.div>
        </motion.div>

        <div className="text-center space-y-4">
          <h1 className="text-4xl font-mono font-bold text-cyan-400 tracking-[0.3em] min-h-[1.2em]">
            {text}
          </h1>
          
          <AnimatePresence>
            {showTagline && (
              <motion.p
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="text-cyan-500/60 font-mono text-sm tracking-wider italic"
              >
                "Every threat has a shadow. We are its hunter."
              </motion.p>
            )}
          </AnimatePresence>
        </div>

        <div className="h-8 flex items-center justify-center">
          <p className="text-cyan-400/40 font-mono text-[10px] tracking-widest uppercase">
            {status}
          </p>
        </div>
      </div>
    </motion.div>
  );
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SCREEN 2 — MODE SELECTION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export const ModeSelect: React.FC = () => {
  const { setOperationMode, setScreen } = useSentinelStore();
  const [file, setFile] = useState<File | null>(null);
  const [fileInfo, setFileInfo] = useState<{ name: string; count: number } | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [showReadinessCheck, setShowReadinessCheck] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setIsValidating(true);
      Papa.parse(selectedFile, {
        header: true,
        complete: (results) => {
          setFile(selectedFile);
          setFileInfo({ name: selectedFile.name, count: results.data.length });
          setIsValidating(false);
        },
        error: () => {
          alert('Error parsing CSV file');
          setIsValidating(false);
        }
      });
    }
  };

  const launchSimulation = () => {
    setOperationMode('simulation');
    setScreen('dashboard');
  };

  const handleLiveModeClick = () => {
    setShowReadinessCheck(true);
  };

  const launchLive = () => {
    if (file) {
      setOperationMode('live', file);
      setScreen('dashboard');
    }
  };

  return (
    <div className="fixed inset-0 dark:bg-[#0d1117] bg-gray-50 z-[90] flex flex-col items-center justify-center p-8">
      {showReadinessCheck && (
        <APIReadinessModal
          onProceed={() => {
            setShowReadinessCheck(false);
            if (!file) {
              fileInputRef.current?.click();
            }
          }}
          onCancel={() => {
            setShowReadinessCheck(false);
            // In a real app we'd navigate to settings, here we just close it
          }}
        />
      )}
      <div className="absolute top-8 left-8 flex items-center gap-2">
        <Shield className="w-6 h-6 text-cyan-400" />
        <span className="text-cyan-400 font-mono font-bold tracking-tighter">GHOST SHIELD</span>
      </div>

      <div className="text-center mb-12">
        <h2 className="text-2xl font-mono font-bold text-text-main tracking-widest uppercase">
          Select Operation Mode
        </h2>
        <div className="h-1 w-24 bg-cyan-500 mx-auto mt-4" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-5xl w-full">
        {/* Simulation Card */}
        <motion.div
          whileHover={{ y: -4 }}
          onClick={launchSimulation}
          className="bg-card-bg border border-border-strong hover:border-cyan-500/50 p-8 rounded-xl cursor-pointer group transition-all duration-300 flex flex-col"
        >
          <div className="flex justify-between items-start mb-6">
            <div className="p-3 bg-cyan-500/10 rounded-lg text-cyan-400 group-hover:scale-110 transition-transform">
              <Zap size={32} />
            </div>
            <span className="text-[10px] font-mono bg-cyan-500/20 text-cyan-400 px-2 py-1 rounded uppercase tracking-widest">
              Recommended for Demo
            </span>
          </div>
          
          <h3 className="text-xl font-mono font-bold text-text-main mb-4 uppercase tracking-wider">
            Simulation Mode
          </h3>
          
          <p className="text-text-muted text-sm leading-relaxed mb-8 flex-grow">
            AI-generated attack scenarios using realistic network data. No file required.
            Perfect for demonstration, training, and stress-testing your response protocols.
          </p>

          <button className="w-full py-3 bg-transparent border border-cyan-500/30 text-cyan-400 font-mono text-sm uppercase tracking-widest group-hover:bg-cyan-500 group-hover:text-[#0f172a] dark:text-[#050505] transition-all flex items-center justify-center gap-2">
            Launch Simulation <ArrowRight size={16} />
          </button>
        </motion.div>

        {/* Live Card */}
        <motion.div
          whileHover={{ y: -4 }}
          className={`bg-card-bg border ${file ? 'border-cyan-500' : 'border-border-strong'} hover:border-cyan-500/50 p-8 rounded-xl cursor-pointer group transition-all duration-300 flex flex-col`}
        >
          <div className="flex justify-between items-start mb-6">
            <div className="p-3 bg-purple-500/10 rounded-lg text-purple-400 group-hover:scale-110 transition-transform">
              <Folder size={32} />
            </div>
            <span className="text-[10px] font-mono bg-purple-500/20 text-purple-400 px-2 py-1 rounded uppercase tracking-widest">
              Real Data
            </span>
          </div>
          
          <h3 className="text-xl font-mono font-bold text-text-main mb-4 uppercase tracking-wider">
            Live Analysis
          </h3>
          
          <p className="text-text-muted text-sm leading-relaxed mb-8 flex-grow">
            Upload real network logs for AI analysis. Detect actual threats in your CSV data.
            Supports up to 10,000 log entries with line-by-line processing.
          </p>

          <div className="space-y-4">
            {fileInfo ? (
              <div className="bg-cyan-500/5 border border-cyan-500/20 rounded p-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <FileText className="text-cyan-400" size={20} />
                  <div>
                    <div className="text-xs text-text-main font-mono truncate max-w-[150px]">{fileInfo.name}</div>
                    <div className="text-[10px] text-cyan-500/60 font-mono">{fileInfo.count} entries detected</div>
                  </div>
                </div>
                <CheckCircle2 className="text-cyan-400" size={16} />
              </div>
            ) : null}

            <input 
              type="file" 
              ref={fileInputRef} 
              onChange={handleFileChange} 
              accept=".csv" 
              className="hidden" 
            />

            {!file ? (
              <button 
                onClick={handleLiveModeClick}
                disabled={isValidating}
                className="w-full py-3 bg-transparent border border-gray-700 text-text-muted font-mono text-sm uppercase tracking-widest hover:border-cyan-500/50 hover:text-cyan-400 transition-all flex items-center justify-center gap-2"
              >
                {isValidating ? <Loader2 className="animate-spin" size={16} /> : <Folder size={16} />}
                Upload Log File
              </button>
            ) : (
              <div className="grid grid-cols-2 gap-4">
                <button 
                  onClick={() => fileInputRef.current?.click()}
                  className="py-3 bg-transparent border border-gray-700 text-text-muted font-mono text-[10px] uppercase tracking-widest hover:text-text-main transition-all"
                >
                  Change File
                </button>
                <button 
                  onClick={launchLive}
                  className="py-3 bg-cyan-500 text-[#0f172a] dark:text-[#050505] font-mono text-[10px] font-bold uppercase tracking-widest hover:bg-cyan-400 transition-all"
                >
                  Start Analysis →
                </button>
              </div>
            )}
          </div>
        </motion.div>
      </div>

      <div className="mt-12 text-gray-600 font-mono text-[10px] uppercase tracking-widest">
        You can switch modes anytime from the dashboard
      </div>
    </div>
  );
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GEMINI DATA GENERATION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export const generateSimulationData = async (apiKey: string) => {
  const prompt = `
Generate 50 realistic network security log events as JSON array.
Each event must have these exact fields:
{
  "timestamp": "2026-03-25T14:23:01Z",
  "src_ip": "185.220.101.45",
  "dst_ip": "10.0.1.50",
  "bytes": 1234,
  "protocol": "TCP",
  "port": 22,
  "country": "Russia",
  "city": "Moscow",
  "attack_type": "brute_force",
  "risk_level": "HIGH",
  "confidence": 0.94
}

Mix: 65% normal, 35% attacks.
Attack types: brute_force, port_scan, ddos, bot_activity, suspicious_login, scraping, credential_stuffing.
Use realistic IPs from Russia, China, Iran, USA, Germany, Netherlands, Ukraine, Nigeria, Brazil.
Target IP always: 10.0.1.50 (Palestine protected node).
Return ONLY the JSON array. No explanation. No markdown.
`;

  try {
    const res = await fetch(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=' + apiKey,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { maxOutputTokens: 4000, temperature: 0.7 }
        })
      }
    );
    
    if (!res.ok) throw new Error('Gemini API request failed');
    
    const data = await res.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '[]';
    
    // Clean up markdown if Gemini ignores instructions
    const cleanJson = text.replace(/```json|```/g, '').trim();
    return JSON.parse(cleanJson);
  } catch (error) {
    console.error('Gemini Simulation Generation Error:', error);
    return null; // Fallback to local data handled in caller
  }
};
