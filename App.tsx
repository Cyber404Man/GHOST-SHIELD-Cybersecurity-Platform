import React, { useState, useEffect, useMemo } from 'react';
import Papa from 'papaparse';
import { analyzeRow, sleep } from './utils/processing';
import { generateEnrichment } from './utils/enrichment';
import { WatchlistWidget } from './components/WatchlistWidget';
import { BlockedIPsPanel } from './components/BlockedIPsPanel';
import { AttackMap } from './components/AttackMap';
import { 
  Shield, 
  Activity, 
  Globe, 
  AlertTriangle, 
  Lock, 
  Terminal, 
  Cpu, 
  Wifi,
  Menu,
  X,
  Search,
  Bell,
  User,
  ChevronRight,
  RefreshCcw,
  ExternalLink,
  Settings,
  BarChart3,
  Eye,
  PieChart as PieChartIcon,
  LayoutDashboard,
  FileText,
  Zap,
  Upload,
  CheckCircle,
  Database,
  Map as MapIcon,
  Bot,
  Brain,
  Loader2
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import * as d3 from 'd3';
import { AIExplainer } from './components/AIExplainer';
import { explainThreat } from './lib/gemini';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend
} from 'recharts';
import { 
  ComposableMap, 
  Geographies, 
  Geography, 
  Marker, 
  Line as MapLine 
} from 'react-simple-maps';

import jsPDF from 'jspdf';
import { exportReport, exportSystemDocumentation, exportInstallationGuide, exportAttackMapReport } from './lib/pdfExporter';
import autoTable from 'jspdf-autotable';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useSentinelStore } from './store';
import { NormalizedEvent as Event, IPDetails } from './types';
import { IntroScreen, ModeSelect, generateSimulationData } from './components/AppFlow';
import { PredictionWidget } from './components/PredictionWidget';
import { MitreAttackTab, MITRE_MAP } from './components/MitreAttackTab';
import { generateInvestigationReport } from './lib/gemini';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

// --- Utility ---
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- Components ---

const SidebarItem = ({ icon: Icon, label, active, onClick }: { icon: any, label: string, active?: boolean, onClick: () => void }) => (
  <button 
    onClick={onClick}
    className={cn(
      "w-full flex items-center gap-3 px-4 py-3 transition-all duration-200 group relative",
      active ? "bg-cyan-500/10 text-cyan-400 border-r-2 border-cyan-400" : "text-gray-500 hover:text-text-main hover:bg-black/5 dark:bg-white/5"
    )}
  >
    <Icon size={18} className={active ? "text-cyan-400" : "group-hover:text-text-main"} />
    <span className="font-mono text-xs uppercase tracking-widest">{label}</span>
    {active && (
      <motion.div 
        layoutId="sidebar-active"
        className="absolute inset-0 bg-cyan-400/5 -z-10"
      />
    )}
  </button>
);

const StatCard = ({ label, value, icon: Icon, color, onClick, className, pulse }: { label: string, value: string | number, icon: any, color: string, onClick?: () => void, className?: string, pulse?: boolean }) => (
  <div 
    onClick={onClick}
    className={cn(
      "dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 p-4 rounded-lg hover:border-cyan-400/30 transition-all group",
      onClick && "cursor-pointer hover:shadow-[0_0_15px_rgba(34,211,238,0.2)]",
      className
    )}
  >
    <div className="flex items-start justify-between mb-2">
      <div className="text-[10px] font-mono uppercase tracking-widest text-gray-500">{label}</div>
      <Icon size={16} className={cn(color, pulse && "animate-pulse")} />
    </div>
    <div className="text-2xl font-mono text-text-main tracking-tighter group-hover:text-cyan-400 transition-colors">{value}</div>
  </div>
);

const IPDetailsModal = () => {
  const { selectedIP, setSelectedIP, blockIP, toggleWatchIP, blockedIPs, watchlist, events, config } = useSentinelStore();
  const [toast, setToast] = useState<string | null>(null);
  const [localIpDetails, setLocalIpDetails] = useState<any>(null);
  const [localIpLoading, setLocalIpLoading] = useState(false);

  const getIPEnrichment = async (ip: string) => {
    try {
      const res = await fetch(`/api/ip/details?ip=${ip}`);
      if (res.ok) return await res.json();
    } catch {}
    return generateEnrichment(ip);
  };

  useEffect(() => {
    if (selectedIP) {
      setLocalIpLoading(true);
      getIPEnrichment(selectedIP).then(data => {
        setLocalIpDetails(data);
        setLocalIpLoading(false);
      });
    }
  }, [selectedIP]);

  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(null), 3000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  if (!selectedIP) return null;

  const isBlocked = blockedIPs.some(b => b.ip === selectedIP);
  const isWatched = watchlist.includes(selectedIP);

  const handleBlock = () => {
    if (localIpDetails) {
      blockIP({
        ip: localIpDetails.ip,
        country: localIpDetails.country,
        city: localIpDetails.city,
        attack_type: 'manual',
        risk_level: localIpDetails.risk_level,
        blocked_at: new Date().toISOString(),
        flag: localIpDetails.flag || '🏳️'
      });
      setToast(`IP ${localIpDetails.ip} has been blocked`);
      setSelectedIP(null);
    }
  };

  const handleWatch = () => {
    toggleWatchIP(selectedIP);
    setToast(isWatched ? `IP removed from watchlist` : `IP added to watchlist`);
  };

  const handleExport = () => {
    if (!localIpDetails) return;
    
    const doc = new jsPDF();
    const timestamp = new Date().toLocaleString();
    const dateStr = new Date().toISOString().split('T')[0];
    
    // Theme colors
    const bg: [number, number, number] = [13, 17, 23];
    const accent: [number, number, number] = [0, 229, 255];
    const text: [number, number, number] = [255, 255, 255];
    const gray: [number, number, number] = [150, 150, 150];

    // Background
    doc.setFillColor(bg[0], bg[1], bg[2]);
    doc.rect(0, 0, 210, 297, 'F');

    // Header
    doc.setTextColor(accent[0], accent[1], accent[2]);
    doc.setFontSize(20);
    doc.text('GHOST SHIELD', 20, 20);
    doc.setTextColor(text[0], text[1], text[2]);
    doc.setFontSize(16);
    doc.text('IP INTELLIGENCE REPORT', 20, 30);
    doc.setFontSize(10);
    doc.setTextColor(gray[0], gray[1], gray[2]);
    doc.text(`Generated: ${timestamp}`, 20, 37);

    // Section 1: Overview
    doc.setTextColor(accent[0], accent[1], accent[2]);
    doc.setFontSize(14);
    doc.text('IP OVERVIEW', 20, 50);
    doc.setDrawColor(accent[0], accent[1], accent[2]);
    doc.line(20, 52, 190, 52);
    
    doc.setTextColor(text[0], text[1], text[2]);
    doc.setFontSize(12);
    doc.text(`IP Address: ${localIpDetails.ip}`, 20, 60);
    doc.text(`Risk Level: ${localIpDetails.risk_level.toUpperCase()}`, 20, 67);

    // Section 2: Geolocation
    doc.setTextColor(accent[0], accent[1], accent[2]);
    doc.setFontSize(14);
    doc.text('GEOLOCATION', 20, 80);
    doc.line(20, 82, 190, 82);
    
    doc.setTextColor(text[0], text[1], text[2]);
    doc.setFontSize(12);
    doc.text(`Country: ${localIpDetails.country}`, 20, 90);
    doc.text(`City: ${localIpDetails.city}`, 20, 97);
    doc.text(`ISP: ${localIpDetails.isp}`, 20, 104);
    doc.text(`ASN: ${localIpDetails.asn}`, 20, 111);
    doc.text(`Coordinates: ${localIpDetails.coords_display}`, 20, 118);

    // Section 3: Threat Assessment
    doc.setTextColor(accent[0], accent[1], accent[2]);
    doc.setFontSize(14);
    doc.text('THREAT ASSESSMENT', 20, 130);
    doc.line(20, 132, 190, 132);
    
    doc.setTextColor(text[0], text[1], text[2]);
    doc.setFontSize(12);
    doc.text(`Abuse Score: ${localIpDetails.abuse_score}/100`, 20, 140);
    doc.text(`Tags: ${localIpDetails.tags.join(', ')}`, 20, 147);

    // Section 4: Open Ports
    doc.setTextColor(accent[0], accent[1], accent[2]);
    doc.setFontSize(14);
    doc.text('OPEN PORTS', 20, 160);
    doc.line(20, 162, 190, 162);
    
    doc.setTextColor(text[0], text[1], text[2]);
    doc.setFontSize(12);
    doc.text(localIpDetails.open_ports.length > 0 ? localIpDetails.open_ports.join(' · ') : "No open ports detected", 20, 170);

    // Section 5: Recent Threats & MITRE Mapping
    doc.setTextColor(accent[0], accent[1], accent[2]);
    doc.setFontSize(14);
    doc.text('RECENT THREATS & MITRE MAPPING', 20, 185);
    doc.line(20, 187, 190, 187);

    const tableData = events
      .filter(e => e.src_ip === selectedIP)
      .slice(0, 20)
      .map(e => [
        new Date(e.timestamp).toLocaleTimeString(), 
        e.attack_type.toUpperCase().replace('_', ' '), 
        e.mitre?.technique_id || 'N/A',
        e.risk_level.toUpperCase(), 
        e.status.toUpperCase()
      ]);

    autoTable(doc, {
      startY: 190,
      head: [['Timestamp', 'Attack Type', 'MITRE ID', 'Risk', 'Status']],
      body: tableData,
      theme: 'grid',
      headStyles: { fillColor: accent, textColor: bg },
      styles: { fillColor: bg, textColor: text, fontSize: 9 }
    });

    // Section 6: Recommendations
    const finalY = (doc as any).lastAutoTable.finalY + 10;
    doc.setTextColor(accent[0], accent[1], accent[2]);
    doc.setFontSize(14);
    doc.text('RECOMMENDATIONS', 20, finalY);
    doc.line(20, finalY + 2, 190, finalY + 2);
    
    doc.setTextColor(text[0], text[1], text[2]);
    doc.setFontSize(12);
    let rec = "Continue monitoring";
    if (localIpDetails.risk_level === 'critical') rec = "Immediately block and report to ISP";
    else if (localIpDetails.risk_level === 'high') rec = "Block IP and monitor related subnet";
    else if (localIpDetails.risk_level === 'medium') rec = "Add to watchlist and monitor behavior";
    doc.text(rec, 20, finalY + 10);

    // Footer
    doc.setFontSize(8);
    doc.setTextColor(gray[0], gray[1], gray[2]);
    doc.text('Generated by GHOST SHIELD — Every threat has a shadow. We are its hunter.', 20, 285);
    doc.text(`Page 1`, 190, 285, { align: 'right' });

    doc.save(`IP_Report_${selectedIP}_${dateStr}.pdf`);
  };

  const abuseScoreColor = localIpDetails?.abuse_score ? (localIpDetails.abuse_score > 60 ? "bg-red-500" : localIpDetails.abuse_score > 30 ? "bg-yellow-500" : "bg-green-500") : "bg-green-500";


  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
        {toast && (
          <motion.div 
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 50 }}
            className="fixed bottom-10 bg-cyan-500 text-[#0f172a] dark:text-[#050505] px-4 py-2 rounded-lg font-mono text-sm z-50"
          >
            {toast}
          </motion.div>
        )}
        <motion.div 
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="dark:bg-[#0a0a0a] bg-gray-100 border border-black/10 dark:border-white/10 w-full max-w-2xl rounded-xl overflow-hidden shadow-2xl"
        >
          <div className="p-4 border-b border-black/5 dark:border-white/5 flex items-center justify-between bg-black/5 dark:bg-white/5">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-cyan-400/20 flex items-center justify-center rounded text-cyan-400">
                <Globe size={18} />
              </div>
              <div>
                <div className="text-xs font-mono text-gray-500 uppercase tracking-widest">IP Intelligence</div>
                <div className="text-lg font-mono text-text-main tracking-tighter">{selectedIP}</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                {isWatched && (
                  <span className="px-2 py-1 bg-yellow-500/20 text-yellow-500 rounded text-[10px] font-mono uppercase">
                    WATCHING
                  </span>
                )}
                <button 
                  onClick={handleWatch}
                  className={cn(
                    "px-3 py-1.5 rounded text-[10px] font-mono uppercase transition-colors",
                    isWatched ? "bg-gray-800 text-text-muted hover:bg-gray-700" : "bg-yellow-500/20 text-yellow-500 hover:bg-yellow-500/30"
                  )}
                >
                  {isWatched ? "UNWATCH" : "WATCH"}
                </button>
              </div>
              <button onClick={() => setSelectedIP(null)} className="text-gray-500 hover:text-text-main">
                <X size={20} />
              </button>
            </div>
          </div>

          <div className="p-6">
            {localIpLoading ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8 animate-pulse">
                <div className="space-y-6">
                  <div className="grid grid-cols-2 gap-4">
                    {[...Array(4)].map((_, i) => (
                      <div key={i} className="h-12 bg-black/5 dark:bg-white/5 rounded"></div>
                    ))}
                  </div>
                  <div className="h-4 bg-black/5 dark:bg-white/5 rounded"></div>
                  <div className="h-4 bg-black/5 dark:bg-white/5 rounded"></div>
                </div>
                <div className="h-64 bg-black/5 dark:bg-white/5 rounded flex items-center justify-center">
                  <RefreshCcw className="animate-spin text-gray-500" size={32} />
                </div>
              </div>
            ) : localIpDetails ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="space-y-6">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <div className="text-[10px] font-mono text-gray-600 uppercase mb-1">Country</div>
                      <div className="text-sm font-mono text-text-main">{localIpDetails.flag} {localIpDetails.country}</div>
                    </div>
                    <div>
                      <div className="text-[10px] font-mono text-gray-600 uppercase mb-1">City</div>
                      <div className="text-sm font-mono text-text-main">{localIpDetails.city}</div>
                    </div>
                    <div>
                      <div className="text-[10px] font-mono text-gray-600 uppercase mb-1">ISP</div>
                      <div className="text-sm font-mono text-text-main">{localIpDetails.isp}</div>
                    </div>
                    <div>
                      <div className="text-[10px] font-mono text-gray-600 uppercase mb-1">ASN</div>
                      <div className="text-sm font-mono text-text-main">{localIpDetails.asn}</div>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <div className="text-[10px] font-mono text-gray-600 uppercase">Abuse Score</div>
                      <div className={cn(
                        "text-xs font-mono font-bold",
                        localIpDetails.abuse_score > 60 ? "text-red-500" : localIpDetails.abuse_score > 30 ? "text-yellow-500" : "text-green-500"
                      )}>{localIpDetails.abuse_score}/100</div>
                    </div>
                    <div className="h-2 bg-black/5 dark:bg-white/5 rounded-full overflow-hidden">
                      <motion.div 
                        initial={{ width: 0 }}
                        animate={{ width: `${localIpDetails.abuse_score}%` }}
                        className={cn("h-full", abuseScoreColor)}
                      />
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    {localIpDetails.tags.map((tag: string) => (
                      <span key={tag} className="px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded text-[10px] font-mono uppercase">
                        {tag}
                      </span>
                    ))}
                    <span className={cn(
                      "px-2 py-1 border rounded text-[10px] font-mono uppercase",
                      localIpDetails.risk_level === 'high' ? "bg-red-500/10 text-red-400 border-red-500/20" : "bg-green-500/10 text-green-400 border-green-500/20"
                    )}>
                      Risk: {localIpDetails.risk_level}
                    </span>
                  </div>

                  {localIpDetails.mitre && (
                    <div className="bg-cyan-500/5 border border-cyan-500/20 p-4 rounded-lg space-y-3">
                      <div className="flex items-center gap-2 text-cyan-400">
                        <Shield size={14} />
                        <span className="text-[10px] font-mono font-bold uppercase tracking-widest">MITRE ATT&CK Mapping</span>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <div className="text-[8px] text-gray-500 uppercase font-mono">Tactic</div>
                          <div className="text-[10px] text-text-main font-mono uppercase">{localIpDetails.mitre.tactic}</div>
                        </div>
                        <div>
                          <div className="text-[8px] text-gray-500 uppercase font-mono">Technique</div>
                          <div className="text-[10px] text-text-main font-mono uppercase">{localIpDetails.mitre.technique}</div>
                        </div>
                      </div>
                      <div className="text-[9px] text-text-muted leading-relaxed font-mono italic">
                        "{localIpDetails.mitre.description}"
                      </div>
                      <a 
                        href={localIpDetails.mitre.mitre_url} 
                        target="_blank" 
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-[8px] text-cyan-400 hover:underline font-mono uppercase"
                      >
                        View Framework Details <ExternalLink size={8} />
                      </a>
                    </div>
                  )}

                  {config.show_ai_modal && (
                    <AIExplainer 
                      threatData={{
                        src_ip: selectedIP,
                        country: localIpDetails.country,
                        attack_type: localIpDetails.attack_type || 'suspicious',
                        risk_level: localIpDetails.risk_level,
                        abuse_score: localIpDetails.abuse_score,
                        tags: localIpDetails.tags,
                        open_ports: localIpDetails.open_ports
                      }}
                      apiKey={config.gemini_key}
                    />
                  )}
                </div>

                <div className="space-y-6">
                  <div className="h-48 bg-black/5 dark:bg-white/5 rounded-lg border border-black/10 dark:border-white/10 relative overflow-hidden">
                    <ComposableMap projection="geoMercator" projectionConfig={{ scale: 100 }}>
                      <Geographies geography="https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json">
                        {({ geographies }) => geographies.map(geo => (
                          <Geography key={geo.rsmKey} geography={geo} fill="#1a1a1a" stroke="#333" />
                        ))}
                      </Geographies>
                      <Marker coordinates={[localIpDetails.lng, localIpDetails.lat]}>
                        <circle r={6} fill="#ef4444" className="animate-pulse" />
                        <title>{`${localIpDetails.ip} - ${localIpDetails.country}, ${localIpDetails.city}`}</title>
                      </Marker>
                    </ComposableMap>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    <button 
                      onClick={handleBlock}
                      disabled={isBlocked}
                      className={cn(
                        "flex flex-col items-center justify-center p-3 border rounded-lg transition-colors",
                        isBlocked ? "bg-gray-500/10 border-gray-500/20 text-gray-500 cursor-not-allowed" : "bg-red-500/10 border-red-500/20 text-red-400 hover:bg-red-500/20"
                      )}
                    >
                      <Lock size={16} className="mb-1" />
                      <span className="text-[10px] font-mono uppercase">{isBlocked ? 'Blocked' : 'Block'}</span>
                    </button>
                    <button 
                      onClick={handleWatch}
                      className={cn(
                        "flex flex-col items-center justify-center p-3 border rounded-lg transition-colors",
                        isWatched ? "bg-yellow-500/20 border-yellow-500/40 text-yellow-400" : "bg-yellow-500/10 border-yellow-500/20 text-yellow-400 hover:bg-yellow-500/20"
                      )}
                    >
                      <Eye size={16} className="mb-1" />
                      <span className="text-[10px] font-mono uppercase">Watch</span>
                    </button>
                    <button 
                      onClick={handleExport}
                      className="flex flex-col items-center justify-center p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg text-blue-400 hover:bg-blue-500/20 transition-colors"
                    >
                      <FileText size={16} className="mb-1" />
                      <span className="text-[10px] font-mono uppercase">Export</span>
                    </button>
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};

// --- Tabs ---

const DashboardTab = ({ onTabChange }: { onTabChange: (tab: string) => void }) => {
  const { events, config, operationMode, setScreen, isProcessing, isBooting, processingProgress, totalEvents, consoleLogs, setFeedFilter } = useSentinelStore();
  const [isBlockedPanelOpen, setIsBlockedPanelOpen] = useState(false);
  const [showSummary, setShowSummary] = useState(false);

  useEffect(() => {
    const handleComplete = () => setShowSummary(true);
    window.addEventListener('analysis-complete', handleComplete);
    return () => window.removeEventListener('analysis-complete', handleComplete);
  }, []);
  
  const stats = useMemo(() => {
    const threats = events.filter(e => e.attack_type !== 'normal');
    const blocked = events.filter(e => e.status === 'blocked');
    const avgRisk = events.length ? events.reduce((acc, e) => {
      const score = e.risk_level === 'critical' ? 100 : e.risk_level === 'high' ? 75 : e.risk_level === 'medium' ? 50 : 10;
      return acc + score;
    }, 0) / events.length : 0;

    return [
      { label: 'Total Events', value: totalEvents, icon: Activity, color: 'text-blue-400', pulse: true, onClick: () => { setFeedFilter('all'); onTabChange('feed'); } },
      { label: 'Active Threats', value: threats.length, icon: AlertTriangle, color: 'text-red-400', pulse: true, onClick: () => { setFeedFilter('threats'); onTabChange('feed'); } },
      { label: 'Blocked IPs', value: blocked.length, icon: Lock, color: 'text-orange-400', onClick: () => setIsBlockedPanelOpen(true) },
      { label: 'Risk Score', value: Math.round(avgRisk), icon: Zap, color: 'text-yellow-400', pulse: true },
    ];
  }, [events, totalEvents, onTabChange, setFeedFilter]);

  const attackData = useMemo(() => {
    const counts: Record<string, number> = {};
    events.forEach(e => {
      if (e.attack_type !== 'normal') {
        counts[e.attack_type] = (counts[e.attack_type] || 0) + 1;
      }
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [events]);

  const riskData = useMemo(() => {
    const counts: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    events.forEach(e => {
      counts[e.risk_level]++;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [events]);

  const COLORS = ['#22d3ee', '#f87171', '#fbbf24', '#a78bfa', '#34d399', '#f472b6'];

  return (
    <div className="space-y-6">
      <BlockedIPsPanel isOpen={isBlockedPanelOpen} onClose={() => setIsBlockedPanelOpen(false)} />
      
      {showSummary && (
        <div className="fixed inset-0 z-[200] flex items-center justify-center bg-black/90 backdrop-blur-md p-4">
          <motion.div 
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="dark:bg-[#0a0a0a] bg-gray-100 border border-cyan-500/30 p-10 rounded-xl max-w-2xl w-full text-center space-y-8 shadow-[0_0_50px_rgba(0,229,255,0.1)]"
          >
            <div className="flex justify-center">
              <div className="w-20 h-20 bg-cyan-500/20 rounded-full flex items-center justify-center text-cyan-400 border border-cyan-500/40">
                <CheckCircle size={40} />
              </div>
            </div>
            
            <div className="space-y-2">
              <h2 className="text-3xl font-mono font-bold text-text-main tracking-widest uppercase">Analysis Complete</h2>
              <p className="text-gray-500 font-mono text-sm">GHOST SHIELD has finished scanning the provided log file.</p>
            </div>

            <div className="grid grid-cols-3 gap-4 py-6 border-y border-black/5 dark:border-white/5">
              <div className="space-y-1 cursor-pointer hover:bg-black/5 dark:bg-white/5 p-2 rounded transition-colors" onClick={() => { setFeedFilter('all'); onTabChange('feed'); setShowSummary(false); }}>
                <div className="text-[10px] font-mono text-gray-600 uppercase">Total Scanned</div>
                <div className="text-xl font-mono text-text-main">{totalEvents}</div>
              </div>
              <div className="space-y-1 cursor-pointer hover:bg-black/5 dark:bg-white/5 p-2 rounded transition-colors" onClick={() => { setFeedFilter('threats'); onTabChange('feed'); setShowSummary(false); }}>
                <div className="text-[10px] font-mono text-gray-600 uppercase">Threats Found</div>
                <div className="text-xl font-mono text-red-500">{events.filter(e => e.attack_type !== 'normal').length}</div>
              </div>
              <div className="space-y-1">
                <div className="text-[10px] font-mono text-gray-600 uppercase">Clean Traffic</div>
                <div className="text-xl font-mono text-green-500">{Math.round((events.filter(e => e.risk_level === 'low').length / totalEvents) * 100)}%</div>
              </div>
            </div>

            <div className="flex gap-4">
              <button 
                onClick={() => {
                  exportReport({
                    events,
                    totalEvents,
                    mode: operationMode,
                    threatsDetected: events.filter(e => e.attack_type !== 'normal').length,
                  });
                }}
                className="flex-1 py-4 bg-cyan-500 text-[#0f172a] dark:text-[#050505] font-mono text-xs font-bold uppercase tracking-widest rounded hover:bg-cyan-400 transition-all flex items-center justify-center gap-2"
              >
                <FileText size={16} /> Export PDF Report
              </button>
              <button 
                onClick={() => setShowSummary(false)}
                className="px-8 py-4 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-text-main font-mono text-xs uppercase tracking-widest rounded hover:bg-black/10 dark:bg-white/10 transition-all"
              >
                Dismiss
              </button>
            </div>
          </motion.div>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={cn(
            "px-3 py-1 rounded-full text-[10px] font-mono uppercase tracking-widest border flex items-center gap-2",
            operationMode === 'simulation' ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/20" : "bg-green-500/10 text-green-400 border-green-500/20"
          )}>
            <div className={cn("w-1.5 h-1.5 rounded-full animate-pulse", operationMode === 'simulation' ? "bg-cyan-400" : "bg-green-400")} />
            {operationMode === 'simulation' ? 'Simulation Mode' : 'Live Mode'}
            {useSentinelStore.getState().simulationSource === 'gemini' && (
              <span className="ml-2 text-[8px] bg-cyan-500/20 px-1 rounded">Powered by Gemini AI</span>
            )}
          </div>
          <button 
            onClick={() => setScreen('mode-select')}
            className="px-3 py-1 bg-black/5 dark:bg-white/5 hover:bg-black/10 dark:bg-white/10 text-text-muted hover:text-text-main rounded text-[10px] font-mono uppercase transition-colors flex items-center gap-1"
          >
            <RefreshCcw size={10} /> Switch
          </button>
        </div>
        <div className="text-[10px] font-mono text-gray-500 uppercase">Last Sync: {new Date().toLocaleTimeString()}</div>
      </div>

      {(isProcessing || isBooting) && (
        <div className="space-y-4">
          <div className="dark:bg-[#0a0a0a] bg-gray-100 border border-cyan-500/30 p-4 rounded-lg overflow-hidden relative">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Terminal size={14} className="text-cyan-400" />
                <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest">
                  {isBooting ? 'Initializing Analysis Engine...' : 'Processing Network Logs...'}
                </span>
              </div>
              <div className="text-[10px] font-mono text-cyan-400/60">
                {isProcessing ? `${processingProgress} / ${totalEvents} ENTRIES` : 'SYSTEM BOOT'}
              </div>
            </div>
            
            <div className="h-1 bg-black/5 dark:bg-white/5 rounded-full overflow-hidden">
              <motion.div 
                initial={{ width: 0 }}
                animate={{ width: isBooting ? '100%' : `${(processingProgress / totalEvents) * 100}%` }}
                transition={isBooting ? { duration: 3 } : { duration: 0.3 }}
                className="h-full bg-cyan-500 shadow-[0_0_10px_rgba(0,229,255,0.5)]"
              />
            </div>

            <div className="mt-4 h-32 overflow-y-auto font-mono text-[10px] space-y-1 scrollbar-hide bg-black/40 p-2 rounded border border-black/5 dark:border-white/5">
              {consoleLogs.map((log, i) => (
                <div key={i} className={cn(
                  log.includes('CRITICAL') ? 'text-red-500' : 
                  log.includes('HIGH') ? 'text-orange-500' : 
                  log.includes('OK') ? 'text-green-500' : 
                  'text-cyan-400/60'
                )}>
                  {log}
                </div>
              ))}
              <div className="animate-pulse text-cyan-400">_</div>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat, i) => (
          <StatCard key={i} {...stat} />
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 rounded-lg p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="font-mono text-xs uppercase tracking-widest text-text-main">Live Events Table</div>
            <button 
              onClick={() => onTabChange('feed')}
              className="text-cyan-400 hover:underline font-mono text-[10px] uppercase"
            >
              View All
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-black/5 dark:border-white/5">
                  <th className="pb-3 font-mono text-[10px] uppercase text-gray-600">Timestamp</th>
                  <th className="pb-3 font-mono text-[10px] uppercase text-gray-600">Source IP</th>
                  <th className="pb-3 font-mono text-[10px] uppercase text-gray-600">Attack Type</th>
                  <th className="pb-3 font-mono text-[10px] uppercase text-gray-600">MITRE ID</th>
                  <th className="pb-3 font-mono text-[10px] uppercase text-gray-600">Risk</th>
                  <th className="pb-3 font-mono text-[10px] uppercase text-gray-600">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {events.slice(0, 8).map((event) => (
                  <tr key={event.event_id} className="group hover:bg-black/5 dark:bg-white/5 transition-colors">
                    <td className="py-3 font-mono text-[10px] text-gray-500">{new Date(event.timestamp).toLocaleTimeString()}</td>
                    <td className="py-3 font-mono text-xs text-cyan-400 cursor-pointer hover:underline" onClick={() => useSentinelStore.getState().setSelectedIP(event.src_ip)}>{event.src_ip}</td>
                    <td className="py-3 font-mono text-xs text-text-main uppercase">{event.attack_type.replace('_', ' ')}</td>
                    <td className="py-3 font-mono text-[10px] text-cyan-400/80 uppercase">{event.mitre?.technique_id || 'N/A'}</td>
                    <td className="py-3">
                      <span className={cn(
                        "px-2 py-0.5 rounded text-[9px] font-mono uppercase border",
                        event.risk_level === 'critical' ? "bg-red-500/10 text-red-500 border-red-500/20" :
                        event.risk_level === 'high' ? "bg-orange-500/10 text-orange-500 border-orange-500/20" :
                        event.risk_level === 'medium' ? "bg-yellow-500/10 text-yellow-500 border-yellow-500/20" :
                        "bg-green-500/10 text-green-500 border-green-500/20"
                      )}>
                        {event.risk_level}
                      </span>
                    </td>
                    <td className="py-3 font-mono text-[10px] text-gray-500 uppercase">{event.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="space-y-6">
          <PredictionWidget />
          <WatchlistWidget />
          <div className="dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 rounded-lg p-6 h-[300px]">
            <div className="font-mono text-xs uppercase tracking-widest text-text-main mb-4">Attack Distribution</div>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={attackData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {attackData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', borderRadius: '4px' }}
                  itemStyle={{ fontSize: '10px', fontFamily: 'monospace' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 rounded-lg p-6 h-[300px]">
            <div className="font-mono text-xs uppercase tracking-widest text-text-main mb-4">Risk Levels</div>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a1a" vertical={false} />
                <XAxis dataKey="name" stroke="#4b5563" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis stroke="#4b5563" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip 
                  cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                  contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', borderRadius: '4px' }}
                  itemStyle={{ fontSize: '10px', fontFamily: 'monospace' }}
                />
                <Bar dataKey="value" fill="#22d3ee" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};

const LiveFeedTab = ({ search, setSearch }: { search: string, setSearch: (s: string) => void }) => {
  const { events, setSelectedIP, watchlist, feedFilter, setFeedFilter } = useSentinelStore();
  
  const filteredEvents = React.useMemo(() => {
    if (!Array.isArray(events)) return [];
    let baseEvents = events;
    
    if (feedFilter === 'threats') {
      baseEvents = events.filter(e => e.attack_type !== 'normal');
    } else if (feedFilter === 'blocked') {
      baseEvents = events.filter(e => e.status === 'blocked');
    }
    
    const lowerSearch = search.toLowerCase();
    return baseEvents.filter(e => 
      e.src_ip.toLowerCase().includes(lowerSearch) ||
      e.dst_ip.toLowerCase().includes(lowerSearch) ||
      e.attack_type.toLowerCase().includes(lowerSearch)
    );
  }, [events, search, feedFilter]);
  
  return (
    <div className="dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 rounded-lg overflow-hidden flex flex-col h-full">
      <div className="p-4 border-b border-black/5 dark:border-white/5 flex items-center justify-between bg-black/5 dark:bg-white/5">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <Terminal size={16} className="text-cyan-400" />
            <span className="font-mono text-xs uppercase tracking-widest text-text-main">Real-Time Event Stream</span>
          </div>
          
          <div className="flex items-center bg-black/40 rounded p-1 border border-black/5 dark:border-white/5">
            <button 
              onClick={() => setFeedFilter('all')}
              className={cn(
                "px-3 py-1 font-mono text-[10px] uppercase rounded transition-colors",
                feedFilter === 'all' ? "bg-cyan-500 text-[#0f172a] dark:text-[#050505] font-bold" : "text-gray-500 hover:text-text-main"
              )}
            >
              All
            </button>
            <button 
              onClick={() => setFeedFilter('threats')}
              className={cn(
                "px-3 py-1 font-mono text-[10px] uppercase rounded transition-colors",
                feedFilter === 'threats' ? "bg-red-500 text-[#0f172a] dark:text-[#050505] font-bold" : "text-gray-500 hover:text-text-main"
              )}
            >
              Threats
            </button>
            <button 
              onClick={() => setFeedFilter('blocked')}
              className={cn(
                "px-3 py-1 font-mono text-[10px] uppercase rounded transition-colors",
                feedFilter === 'blocked' ? "bg-orange-500 text-[#0f172a] dark:text-[#050505] font-bold" : "text-gray-500 hover:text-text-main"
              )}
            >
              Blocked
            </button>
          </div>
        </div>
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input 
            type="text"
            placeholder="Filter events..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-app-bg border border-border-subtle rounded px-8 py-1.5 font-mono text-xs text-text-main focus:outline-none focus:border-cyan-400/50 w-64"
          />
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
          <span className="font-mono text-[10px] text-red-500 uppercase">Live</span>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-2 scrollbar-hide">
        {filteredEvents.map((event) => (
          <motion.div 
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            key={event.event_id}
            className="grid grid-cols-12 gap-4 p-3 border border-black/5 dark:border-white/5 rounded hover:bg-black/5 dark:bg-white/5 transition-colors group items-center"
          >
            <div className="col-span-2 font-mono text-[10px] text-gray-600">{new Date(event.timestamp).toLocaleTimeString()}</div>
            <div className="col-span-3 font-mono text-xs text-cyan-400 cursor-pointer hover:underline hover:text-cyan-300 flex items-center gap-2" onClick={() => setSelectedIP(event.src_ip)}>
              {event.src_ip}
              {watchlist.includes(event.src_ip) && <span className="w-2 h-2 bg-yellow-400 rounded-full" />}
            </div>
            <div className="col-span-1 font-mono text-[10px] text-gray-500">{event.country}</div>
            <div className="col-span-2 font-mono text-xs text-text-main uppercase truncate flex items-center gap-1 relative group/mitre">
              {event.attack_type.replace('_', ' ')}
              {(() => {
                const mitre = MITRE_MAP[event.attack_type.toLowerCase()];
                return mitre ? (
                  <>
                    <span className="text-[8px] font-mono text-cyan-400/60 uppercase cursor-help hover:text-cyan-400 transition-colors">[{mitre.technique_id}]</span>
                    <div className="absolute z-50 left-0 top-full mt-2 hidden group-hover/mitre:block w-64 p-3 bg-gray-900 border border-gray-700 rounded shadow-xl pointer-events-none whitespace-normal">
                      <div className="text-cyan-400 font-bold text-xs mb-1">{mitre.technique} ({mitre.technique_id})</div>
                      <div className="text-gray-300 text-[10px] leading-relaxed normal-case">{mitre.description}</div>
                    </div>
                  </>
                ) : null;
              })()}
            </div>
            <div className="col-span-2 font-mono text-xs text-text-muted">Rep: {event.reputation_score}</div>
            <div className="col-span-2 flex justify-end items-center gap-2">
              <button 
                onClick={() => setSelectedIP(event.src_ip)}
                className="p-1.5 bg-black/5 dark:bg-white/5 hover:bg-cyan-500/20 text-text-muted hover:text-cyan-400 rounded transition-colors"
                title="View Details"
              >
                <Eye size={14} />
              </button>
              <span className="font-mono text-[10px] text-gray-500 uppercase">{event.status}</span>
              <span className={cn(
                "w-2 h-2 rounded-full",
                event.risk_level === 'critical' ? "bg-red-500" :
                event.risk_level === 'high' ? "bg-red-500" :
                event.risk_level === 'medium' ? "bg-yellow-500" :
                "bg-green-500"
              )} />
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
};

const AttackMapTab = () => {
  return <AttackMap />;
};

const BotDetectionTab = () => {
  const { events, setSelectedIP } = useSentinelStore();
  
  const botEvents = useMemo(() => events.filter(e => e.bot_score > 0.5), [events]);
  
  const botScoreData = useMemo(() => {
    const bins = Array(10).fill(0);
    botEvents.forEach(e => {
      const bin = Math.min(Math.floor(e.bot_score * 10), 9);
      bins[bin]++;
    });
    return bins.map((v, i) => ({ range: `${i*10}-${(i+1)*10}%`, count: v }));
  }, [botEvents]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 rounded-lg p-6 h-[400px]">
          <div className="font-mono text-xs uppercase tracking-widest text-text-main mb-6">Bot Score Distribution</div>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={botScoreData}>
              <XAxis dataKey="range" stroke="#4b5563" fontSize={8} tickLine={false} axisLine={false} />
              <YAxis stroke="#4b5563" fontSize={8} tickLine={false} axisLine={false} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', borderRadius: '4px' }}
                itemStyle={{ fontSize: '10px', fontFamily: 'monospace' }}
              />
              <Bar dataKey="count" fill="#a78bfa" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="lg:col-span-2 dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 rounded-lg p-6 flex flex-col">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <Bot size={18} className="text-purple-400" />
              <span className="font-mono text-xs uppercase tracking-widest text-text-main">Bot Activity Analysis</span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-black/5 dark:border-white/5">
                  <th className="pb-3 font-mono text-[10px] uppercase text-gray-600">IP Address</th>
                  <th className="pb-3 font-mono text-[10px] uppercase text-gray-600">Bot Score</th>
                  <th className="pb-3 font-mono text-[10px] uppercase text-gray-600">Category</th>
                  <th className="pb-3 font-mono text-[10px] uppercase text-gray-600">Status</th>
                  <th className="pb-3 font-mono text-[10px] uppercase text-gray-600">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {botEvents.slice(0, 10).map((bot) => (
                  <tr key={bot.event_id} className="group hover:bg-black/5 dark:bg-white/5 transition-colors">
                    <td className="py-3 font-mono text-xs text-cyan-400 cursor-pointer hover:underline" onClick={() => setSelectedIP(bot.src_ip)}>{bot.src_ip}</td>
                    <td className="py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-black/5 dark:bg-white/5 rounded-full overflow-hidden">
                          <div className="h-full bg-purple-500" style={{ width: `${bot.bot_score * 100}%` }} />
                        </div>
                        <span className="font-mono text-[10px] text-purple-400">{Math.round(bot.bot_score * 100)}%</span>
                      </div>
                    </td>
                    <td className="py-3 font-mono text-xs text-text-main uppercase">{bot.attack_type.replace('_', ' ')}</td>
                    <td className="py-3">
                      <span className="px-2 py-0.5 bg-purple-500/10 text-purple-400 border border-purple-500/20 rounded text-[9px] font-mono uppercase">
                        {bot.status}
                      </span>
                    </td>
                    <td className="py-3">
                      <div className="flex gap-2">
                        <button className="p-1 text-gray-500 hover:text-red-400 transition-colors"><Lock size={14} /></button>
                        <button className="p-1 text-gray-500 hover:text-cyan-400 transition-colors"><Eye size={14} /></button>
                        <button className="p-1 text-gray-500 hover:text-green-400 transition-colors"><CheckCircle size={14} /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

const SettingsTab = () => {
  const { config, updateConfig } = useSentinelStore();
  
  return (
    <div className="max-w-4xl space-y-8">
      <section className="space-y-4">
        <div className="font-mono text-xs uppercase tracking-widest text-cyan-400 border-b border-cyan-400/20 pb-2">Session Mode</div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-center justify-between p-4 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-lg">
            <div>
              <div className="text-sm font-mono text-text-main">Simulation Mode</div>
              <div className="text-[10px] font-mono text-gray-500">Generate synthetic threat data</div>
            </div>
            <input 
              type="checkbox" 
              checked={config.mode === 'simulation'} 
              onChange={() => updateConfig({ mode: 'simulation' })}
              className="w-4 h-4 accent-cyan-400"
            />
          </div>
          <div className="flex items-center justify-between p-4 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-lg">
            <div>
              <div className="text-sm font-mono text-text-main">Live Mode</div>
              <div className="text-[10px] font-mono text-gray-500">Process real network logs</div>
            </div>
            <input 
              type="checkbox" 
              checked={config.mode === 'live'} 
              onChange={() => updateConfig({ mode: 'live' })}
              className="w-4 h-4 accent-cyan-400"
            />
          </div>
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-[10px] font-mono text-gray-500 uppercase">Auto-refresh Interval ({config.refresh_interval}s)</label>
          </div>
          <input 
            type="range" min="5" max="60" step="5"
            value={config.refresh_interval || 5}
            onChange={(e) => updateConfig({ refresh_interval: parseInt(e.target.value) })}
            className="w-full h-1 bg-black/10 dark:bg-white/10 rounded-lg appearance-none cursor-pointer accent-cyan-400"
          />
        </div>
      </section>

      <section className="space-y-4">
        <div className="font-mono text-xs uppercase tracking-widest text-cyan-400 border-b border-cyan-400/20 pb-2">API Configuration</div>
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-[10px] font-mono text-gray-500 uppercase">AbuseIPDB API Key</label>
              <div className="flex gap-2">
                <input 
                  type="password" 
                  value={config.abuseipdb_key || ''}
                  onChange={(e) => updateConfig({ abuseipdb_key: e.target.value })}
                  placeholder="Enter key..."
                  className="flex-1 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded px-3 py-2 font-mono text-xs text-text-main focus:outline-none focus:border-cyan-400/50"
                />
                <button className="px-3 py-2 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded font-mono text-[10px] uppercase hover:bg-black/10 dark:bg-white/10 transition-colors">Test</button>
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-mono text-gray-500 uppercase">Shodan API Key</label>
              <div className="flex gap-2">
                <input 
                  type="password" 
                  value={config.shodan_key || ''}
                  onChange={(e) => updateConfig({ shodan_key: e.target.value })}
                  placeholder="Enter key..."
                  className="flex-1 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded px-3 py-2 font-mono text-xs text-text-main focus:outline-none focus:border-cyan-400/50"
                />
                <button className="px-3 py-2 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded font-mono text-[10px] uppercase hover:bg-black/10 dark:bg-white/10 transition-colors">Test</button>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 text-[10px] font-mono">
            <div className={cn("w-2 h-2 rounded-full", config.abuseipdb_key ? "bg-green-500" : "bg-gray-600")} />
            <span className="text-gray-500">Status: {config.abuseipdb_key ? "Connected ✓" : "Not configured"}</span>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <div className="font-mono text-xs uppercase tracking-widest text-cyan-400 border-b border-cyan-400/20 pb-2">AI EXPLAINER (GEMINI)</div>
        <div className="space-y-4">
          <div className="space-y-2">
            <label className="text-[10px] font-mono text-gray-500 uppercase">Gemini API Key</label>
            <div className="flex gap-2">
              <input 
                type="password" 
                value={config.gemini_key || ''}
                onChange={(e) => {
                  updateConfig({ gemini_key: e.target.value });
                  localStorage.setItem('ghost_shield_gemini_key', e.target.value);
                }}
                placeholder="Enter Gemini API key..."
                className="flex-1 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded px-3 py-2 font-mono text-xs text-text-main focus:outline-none focus:border-cyan-400/50"
              />
              <button 
                onClick={async () => {
                  if (!config.gemini_key) return;
                  const testThreat = {
                    src_ip: '1.1.1.1',
                    country: 'Test Country',
                    attack_type: 'brute_force',
                    risk_level: 'high'
                  };
                  try {
                    await explainThreat(testThreat, config.gemini_key);
                    alert("Gemini API Test Successful!");
                  } catch (err) {
                    alert("Gemini API Test Failed. Check your key.");
                  }
                }}
                className="px-3 py-2 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 rounded font-mono text-[10px] uppercase hover:bg-cyan-500/20 transition-colors"
              >
                Test
              </button>
            </div>
            <p className="text-[8px] font-mono text-gray-600">Get your key at <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noreferrer" className="text-cyan-500 hover:underline">AI Studio</a></p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center justify-between p-3 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-lg">
              <div className="text-[10px] font-mono text-text-main uppercase">Auto-explain High Risk</div>
              <input 
                type="checkbox" 
              checked={!!config.auto_explain_high} 
                onChange={(e) => updateConfig({ auto_explain_high: e.target.checked })}
                className="w-3 h-3 accent-cyan-400"
              />
            </div>
            <div className="flex items-center justify-between p-3 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-lg">
              <div className="text-[10px] font-mono text-text-main uppercase">Show in Alerts</div>
              <input 
                type="checkbox" 
              checked={!!config.show_ai_alerts} 
                onChange={(e) => updateConfig({ show_ai_alerts: e.target.checked })}
                className="w-3 h-3 accent-cyan-400"
              />
            </div>
            <div className="flex items-center justify-between p-3 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-lg">
              <div className="text-[10px] font-mono text-text-main uppercase">Show in IP Modal</div>
              <input 
                type="checkbox" 
              checked={!!config.show_ai_modal} 
                onChange={(e) => updateConfig({ show_ai_modal: e.target.checked })}
                className="w-3 h-3 accent-cyan-400"
              />
            </div>
          </div>

          <div className="flex items-center gap-2 text-[10px] font-mono">
            <div className={cn("w-2 h-2 rounded-full", config.gemini_key ? "bg-cyan-500 shadow-[0_0_8px_rgba(0,255,255,0.5)]" : "bg-gray-600")} />
            <span className="text-gray-500">Status: {config.gemini_key ? "AI Core Active ✓" : "Using fallback mode"}</span>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <div className="font-mono text-xs uppercase tracking-widest text-cyan-400 border-b border-cyan-400/20 pb-2">UI Preferences</div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-center justify-between p-4 bg-app-bg border border-border-subtle rounded-lg">
            <div>
              <div className="text-sm font-mono text-text-main">Dark Mode</div>
              <div className="text-[10px] font-mono text-text-muted">Use dark color scheme</div>
            </div>
            <input 
              type="checkbox" 
              checked={!!config.dark_mode} 
              onChange={(e) => updateConfig({ dark_mode: e.target.checked })}
              className="w-4 h-4 accent-cyan-400"
            />
          </div>
          <div className="flex items-center justify-between p-4 bg-app-bg border border-border-subtle rounded-lg">
            <div>
              <div className="text-sm font-mono text-text-main">UI Animations</div>
              <div className="text-[10px] font-mono text-text-muted">Enable visual effects</div>
            </div>
            <input 
              type="checkbox" 
              checked={!!config.animations} 
              onChange={(e) => updateConfig({ animations: e.target.checked })}
              className="w-4 h-4 accent-cyan-400"
            />
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <div className="font-mono text-xs uppercase tracking-widest text-cyan-400 border-b border-cyan-400/20 pb-2">Detection Engine</div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-[10px] font-mono text-gray-500 uppercase">Sensitivity ({config.sensitivity})</label>
              </div>
              <input 
                type="range" min="1" max="10" 
                value={config.sensitivity || 5}
                onChange={(e) => updateConfig({ sensitivity: parseInt(e.target.value) })}
                className="w-full h-1 bg-black/10 dark:bg-white/10 rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-[10px] font-mono text-gray-500 uppercase">Auto-block Threshold ({config.auto_block_threshold}%)</label>
              </div>
              <input 
                type="range" min="50" max="100" 
                value={config.auto_block_threshold || 80}
                onChange={(e) => updateConfig({ auto_block_threshold: parseInt(e.target.value) })}
                className="w-full h-1 bg-black/10 dark:bg-white/10 rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />
            </div>
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-lg">
              <div className="text-sm font-mono text-text-main">Auto-block Critical IPs</div>
              <input 
                type="checkbox" 
              checked={!!config.auto_block_critical} 
                onChange={(e) => updateConfig({ auto_block_critical: e.target.checked })}
                className="w-4 h-4 accent-cyan-400"
              />
            </div>
            <div className="flex items-center justify-between p-4 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-lg">
              <div className="text-sm font-mono text-text-main">Show Predictions Overlay</div>
              <input 
                type="checkbox" 
              checked={!!config.show_predictions} 
                onChange={(e) => updateConfig({ show_predictions: e.target.checked })}
                className="w-4 h-4 accent-cyan-400"
              />
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

const ReportsTab = () => {
  const { events, totalEvents, operationMode } = useSentinelStore();

  const insights = useMemo(() => {
    const attacks = events.filter(e => e.attack_type !== 'normal');
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
  }, [events]);

  return (
    <div className="space-y-8">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 rounded-lg p-8 text-center space-y-4">
          <FileText size={48} className="mx-auto text-gray-600" />
          <div>
            <h3 className="text-lg font-mono text-text-main">Threat Intelligence Report</h3>
            <p className="text-xs font-mono text-gray-500">Generate a comprehensive PDF summary of system activity</p>
          </div>
          <button 
            onClick={() => exportReport({ events, totalEvents, mode: operationMode })}
            className="px-6 py-3 bg-cyan-500 text-[#0f172a] dark:text-[#050505] font-mono text-xs uppercase tracking-widest rounded hover:bg-cyan-400 transition-colors flex items-center gap-2 mx-auto"
          >
            <FileText size={16} /> Generate PDF Report
          </button>
        </div>

        <div className="dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 rounded-lg p-8 text-center space-y-4">
          <Globe size={48} className="mx-auto text-gray-600" />
          <div>
            <h3 className="text-lg font-mono text-text-main">Attack Map Intelligence</h3>
            <p className="text-xs font-mono text-gray-500">Detailed analysis of geographic threat distribution and AI insights</p>
          </div>
          <button 
            onClick={() => exportAttackMapReport({ attacks: events.filter(e => e.attack_type !== 'normal'), insights })}
            className="px-6 py-3 bg-cyan-500 text-[#0f172a] dark:text-[#050505] font-mono text-xs uppercase tracking-widest rounded hover:bg-cyan-400 transition-colors flex items-center gap-2 mx-auto"
          >
            <Globe size={16} /> Export Map Intelligence
          </button>
        </div>

        <div className="dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 rounded-lg p-8 text-center space-y-4">
          <Database size={48} className="mx-auto text-gray-600" />
          <div>
            <h3 className="text-lg font-mono text-text-main">System Documentation</h3>
            <p className="text-xs font-mono text-gray-500">Download technical specifications and system architecture</p>
          </div>
          <button 
            onClick={() => exportSystemDocumentation()}
            className="px-6 py-3 bg-black/10 dark:bg-white/10 text-text-main border border-white/20 font-mono text-xs uppercase tracking-widest rounded hover:bg-black/20 dark:bg-white/20 transition-colors flex items-center gap-2 mx-auto"
          >
            <FileText size={16} /> Download Documentation
          </button>
        </div>

        <div className="dark:bg-[#0a0a0a] bg-gray-100 border border-black/5 dark:border-white/5 rounded-lg p-8 text-center space-y-4">
          <Zap size={48} className="mx-auto text-gray-600" />
          <div>
            <h3 className="text-lg font-mono text-text-main">Installation & Live Guide</h3>
            <p className="text-xs font-mono text-gray-500">Step-by-step guide to install and enable real-time analysis</p>
          </div>
          <button 
            onClick={() => exportInstallationGuide()}
            className="px-6 py-3 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono text-xs uppercase tracking-widest rounded hover:bg-cyan-500/20 transition-colors flex items-center gap-2 mx-auto"
          >
            <Zap size={16} /> Download Guide
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 p-4 rounded-lg">
          <div className="text-[10px] font-mono text-gray-500 uppercase mb-2">Weekly Summary</div>
          <div className="text-sm font-mono text-text-main">2,405 Threats Blocked</div>
          <div className="text-[10px] font-mono text-green-400 mt-1">+12% from last week</div>
        </div>
        <div className="bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 p-4 rounded-lg">
          <div className="text-[10px] font-mono text-gray-500 uppercase mb-2">Top Attack Vector</div>
          <div className="text-sm font-mono text-text-main">Brute Force (SSH)</div>
          <div className="text-[10px] font-mono text-gray-500 mt-1">42% of total attacks</div>
        </div>
        <div className="bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 p-4 rounded-lg">
          <div className="text-[10px] font-mono text-gray-500 uppercase mb-2">System Health</div>
          <div className="text-sm font-mono text-text-main">99.98% Uptime</div>
          <div className="text-[10px] font-mono text-cyan-400 mt-1">All systems operational</div>
        </div>
      </div>
    </div>
  );
};

const ThreatGraphTab = () => {
  const { events } = useSentinelStore();
  const svgRef = React.useRef<SVGSVGElement>(null);
  const [report, setReport] = useState<string | null>(null);
  const [relationships, setRelationships] = useState<any[]>([]);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

  const handleGenerateReport = async () => {
    setIsGeneratingReport(true);
    setReport(null);
    setRelationships([]);
    try {
      const generated = await generateInvestigationReport(events);
      setReport(generated.report);
      if (generated.relationships) {
        setRelationships(generated.relationships);
      }
    } catch (err: any) {
      setReport("Error generating report: " + err.message);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  useEffect(() => {
    if (!svgRef.current || events.length === 0) return;

    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    // Prepare data
    const nodes: any[] = [];
    const links: any[] = [];
    const nodeSet = new Set();

    events.slice(0, 50).forEach(event => {
      if (!nodeSet.has(event.src_ip)) {
        nodes.push({ id: event.src_ip, type: 'src', risk: event.risk_level });
        nodeSet.add(event.src_ip);
      }
      if (!nodeSet.has(event.dst_ip)) {
        nodes.push({ id: event.dst_ip, type: 'dst', risk: 'low' });
        nodeSet.add(event.dst_ip);
      }
      links.push({ source: event.src_ip, target: event.dst_ip, risk: event.risk_level, type: 'attack' });
    });

    // Add API generated relationships
    relationships.forEach(rel => {
      if (nodeSet.has(rel.source) && nodeSet.has(rel.target)) {
        links.push({ source: rel.source, target: rel.target, type: 'relation', desc: rel.description });
      }
    });

    const simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d: any) => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2));

    const link = svg.append("g")
      .attr("stroke-opacity", 0.6)
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke", (d: any) => {
        if (d.type === 'relation') return '#a855f7'; // purple for AI relationship
        if (d.risk === 'critical') return '#ef4444';
        if (d.risk === 'high') return '#f97316';
        if (d.risk === 'medium') return '#eab308';
        return '#22d3ee';
      })
      .attr("stroke-dasharray", (d: any) => d.type === 'relation' ? '5,5' : 'none')
      .attr("stroke-width", (d: any) => {
        if (d.type === 'relation') return 1.5;
        return d.risk === 'critical' ? 2 : 1;
      });
      
    link.append("title")
      .text((d: any) => d.type === 'relation' ? `AI Relation: ${d.desc}` : '');

    const node = svg.append("g")
      .attr("stroke", "#000")
      .attr("stroke-width", 1.5)
      .selectAll("circle")
      .data(nodes)
      .join("circle")
      .attr("r", (d: any) => d.type === 'dst' ? 8 : 5)
      .attr("fill", (d: any) => {
        if (d.type === 'dst') return '#fff';
        if (d.risk === 'critical') return '#ef4444';
        if (d.risk === 'high') return '#f97316';
        return '#22d3ee';
      })
      .call(d3.drag<SVGCircleElement, any>()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended) as any);

    node.append("title")
      .text((d: any) => d.id);

    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      node
        .attr("cx", (d: any) => d.x)
        .attr("cy", (d: any) => d.y);
    });

    function dragstarted(event: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }

    function dragged(event: any) {
      event.subject.fx = event.x;
      event.subject.fy = event.y;
    }

    function dragended(event: any) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }

    return () => simulation.stop();
  }, [events, relationships]);

  return (
    <div className="h-full flex flex-col space-y-4 relative">
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h2 className="text-xl font-mono text-text-main tracking-tighter uppercase">Threat Graph</h2>
          <p className="text-xs text-gray-500 font-mono">Visualizing IP relationships and attack vectors</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex gap-4 mr-4 border-r border-black/10 dark:border-white/10 pr-4">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-cyan-400" />
              <span className="text-[10px] font-mono uppercase text-gray-500">Source IP</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-white" />
              <span className="text-[10px] font-mono uppercase text-gray-500">Target IP</span>
            </div>
          </div>
          <button 
            onClick={handleGenerateReport} 
            disabled={isGeneratingReport || events.length === 0}
            className="flex items-center gap-2 px-3 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded transition-colors disabled:opacity-50 font-mono text-xs font-bold uppercase"
          >
            {isGeneratingReport ? <><Loader2 size={14} className="animate-spin" /> Analyzing...</> : <><Search size={14} /> Generate Investigation Report</>}
          </button>
        </div>
      </div>
      <div className="flex-1 flex gap-4 h-[calc(100%-80px)]">
        <div className={cn(
          "bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-lg overflow-hidden relative transition-all duration-300",
          report ? "w-2/3" : "w-full"
        )}>
          <svg ref={svgRef} className="w-full h-full" />
          <div className="absolute bottom-4 right-4 p-3 bg-black/60 backdrop-blur-md border border-black/10 dark:border-white/10 rounded font-mono text-[10px] space-y-2">
            <div className="text-text-muted uppercase border-b border-black/10 dark:border-white/10 pb-1 mb-2">Risk Legend</div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-1 bg-red-500" />
              <span>Critical</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-1 bg-orange-500" />
              <span>High</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-1 bg-cyan-400" />
              <span>Low/Normal</span>
            </div>
            <div className="flex items-center gap-2 mt-2 pt-2 border-t border-black/10 dark:border-white/10">
              <div className="w-2 h-0 border-t-2 border-dashed border-purple-500" />
              <span className="text-purple-400 font-bold text-[9px]">AI Assessed Link</span>
            </div>
          </div>
        </div>
        
        <AnimatePresence>
          {report && (
            <motion.div 
              initial={{ opacity: 0, w: 0, x: 20 }}
              animate={{ opacity: 1, w: "auto", x: 0 }}
              exit={{ opacity: 0, w: 0, x: 20 }}
              className="w-1/3 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded-lg p-4 flex flex-col h-full overflow-hidden"
            >
              <div className="flex justify-between items-center mb-4 pb-2 border-b border-black/10 dark:border-white/10">
                <div className="flex items-center gap-2">
                  <Brain size={16} className="text-cyan-400" />
                  <h3 className="font-mono text-sm text-text-main uppercase tracking-widest">AI Investigation Analysis</h3>
                </div>
                <button onClick={() => setReport(null)} className="text-gray-500 hover:text-white transition-colors">
                  <X size={16} />
                </button>
              </div>
              <div className="overflow-y-auto flex-1 pr-2 prose prose-invert prose-p:text-xs prose-p:font-mono prose-p:leading-relaxed prose-headings:font-mono prose-headings:text-cyan-400 prose-ul:text-xs prose-ul:font-mono prose-li:text-gray-300 scrollbar-hide">
                <Markdown remarkPlugins={[remarkGfm]}>{report}</Markdown>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};

// --- Main App ---

const AlertPopup = ({ event, onClose, apiKey, showAI }: { event: any, onClose: () => void, apiKey: string, showAI: boolean }) => {
  return (
    <motion.div 
      initial={{ opacity: 0, x: 100, scale: 0.9 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 100, scale: 0.9 }}
      className="fixed top-6 right-6 z-[100] w-80 dark:bg-[#0a0a0a] bg-gray-100 border border-red-500/30 rounded-lg shadow-[0_0_30px_rgba(239,68,68,0.2)] overflow-hidden"
    >
      <div className="bg-red-500/10 p-3 flex items-center justify-between border-b border-red-500/20">
        <div className="flex items-center gap-2 text-red-500">
          <AlertTriangle size={16} />
          <span className="text-[10px] font-mono font-bold uppercase tracking-widest">Critical Alert</span>
        </div>
        <button onClick={onClose} className="text-gray-500 hover:text-text-main">
          <X size={14} />
        </button>
      </div>
      <div className="p-4 space-y-3">
        <div>
          <div className="text-[8px] font-mono text-gray-500 uppercase">Attack Type</div>
          <div className="flex items-center gap-2">
            <div className="text-sm font-mono text-text-main uppercase tracking-tighter">{event.attack_type.replace('_', ' ')}</div>
            {event.mitre && (
              <span className="px-1.5 py-0.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded text-[8px] font-mono font-bold" title={event.mitre.description}>
                {event.mitre.technique_id}
              </span>
            )}
          </div>
        </div>
        {event.mitre && (
          <div className="bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 p-2 rounded">
            <div className="flex justify-between items-start mb-1">
              <div className="text-[8px] font-mono text-gray-500 uppercase">MITRE Tactic</div>
              <div className="text-[8px] font-mono text-cyan-400/80 uppercase">{event.mitre.technique_id}</div>
            </div>
            <div className="text-[10px] font-mono text-cyan-400 uppercase font-bold mb-1">
              {event.mitre.tactic_id}: {event.mitre.tactic}
            </div>
            {(event.attack_type === 'brute_force' || event.mitre) && (
              <div className="text-[9px] font-mono text-text-muted mt-1 leading-relaxed">
                {event.mitre.description}
              </div>
            )}
          </div>
        )}
        <div className="flex justify-between">
          <div>
            <div className="text-[8px] font-mono text-gray-500 uppercase">Source IP</div>
            <div className="text-xs font-mono text-cyan-400">{event.src_ip}</div>
          </div>
          <div className="text-right">
            <div className="text-[8px] font-mono text-gray-500 uppercase">Risk Level</div>
            <div className="text-xs font-mono text-red-500 uppercase">{event.risk_level}</div>
          </div>
        </div>

        {showAI && (
          <div className="pt-2 border-t border-black/5 dark:border-white/5">
            <AIExplainer 
              threatData={{
                src_ip: event.src_ip,
                country: event.country || 'Unknown',
                attack_type: event.attack_type,
                risk_level: event.risk_level,
                port: event.port,
                protocol: event.protocol
              }}
              apiKey={apiKey}
            />
          </div>
        )}

        <button 
          onClick={() => {
            useSentinelStore.getState().setSelectedIP(event.src_ip);
            onClose();
          }}
          className="w-full py-2 bg-red-500 text-[#0f172a] dark:text-[#050505] font-mono text-[10px] uppercase font-bold rounded hover:bg-red-400 transition-colors"
        >
          Investigate Threat
        </button>
      </div>
      <motion.div 
        initial={{ width: "100%" }}
        animate={{ width: "0%" }}
        transition={{ duration: 10, ease: "linear" }}
        className="h-0.5 bg-red-500"
      />
    </motion.div>
  );
};

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [search, setSearch] = useState('');
  const [activeAlert, setActiveAlert] = useState<any>(null);
  const { 
    fetchEvents, 
    fetchConfig, 
    config, 
    startSession, 
    uploadLogs, 
    uploadLoading, 
    ipLoading, 
    watchlist,
    isProcessing,
    processingProgress,
    totalEvents,
    currentScreen,
    setScreen,
    operationMode,
    uploadedFile,
    addEvents
  } = useSentinelStore();
  
  useEffect(() => {
    setSearch('');
  }, [activeTab]);

  // Intro timer
  useEffect(() => {
    if (currentScreen === 'intro') {
      const timer = setTimeout(() => setScreen('mode-select'), 3500);
      return () => clearTimeout(timer);
    }
  }, [currentScreen]);

  // Simulation Logic
  useEffect(() => {
    if (currentScreen === 'dashboard' && operationMode === 'simulation') {
      let interval: any;
      
      const runSimulation = async () => {
        if (config.gemini_key) {
          useSentinelStore.setState({ simulationSource: 'gemini' });
          const geminiEvents = await generateSimulationData(config.gemini_key);
          if (geminiEvents && geminiEvents.length > 0) {
            // Add a few events every 5 seconds
            interval = setInterval(() => {
              const count = Math.floor(Math.random() * 3) + 1;
              const batch = [];
              for (let i = 0; i < count; i++) {
                const randomEvent = geminiEvents[Math.floor(Math.random() * geminiEvents.length)];
                batch.push({
                  ...randomEvent,
                  event_id: Math.random().toString(36).substr(2, 9),
                  timestamp: new Date().toISOString(),
                  status: 'detected'
                });
              }
              addEvents(batch);
            }, 5000);
            return;
          }
        }
        
        // Fallback simulation
        useSentinelStore.setState({ simulationSource: 'fallback' });
        interval = setInterval(() => {
          const count = Math.floor(Math.random() * 2) + 1;
          const batch = [];
          for (let i = 0; i < count; i++) {
            const isAttack = Math.random() > 0.7;
            const attackTypes = ['brute_force', 'port_scan', 'ddos', 'bot_activity', 'suspicious_login'];
            const countries = ['Russia', 'China', 'Iran', 'USA', 'Germany', 'Netherlands', 'Ukraine', 'Nigeria', 'Brazil'];
            const ips = ['185.220.101.45', '45.142.120.11', '103.203.57.14', '192.168.1.100', '8.8.8.8'];
            
            batch.push({
              event_id: Math.random().toString(36).substr(2, 9),
              timestamp: new Date().toISOString(),
              src_ip: ips[Math.floor(Math.random() * ips.length)],
              dst_ip: '10.0.1.50',
              bytes: Math.floor(Math.random() * 5000),
              protocol: Math.random() > 0.5 ? 'TCP' : 'UDP',
              port: [22, 80, 443, 3389, 8080][Math.floor(Math.random() * 5)],
              country: countries[Math.floor(Math.random() * countries.length)],
              city: 'Unknown',
              attack_type: isAttack ? attackTypes[Math.floor(Math.random() * attackTypes.length)] : 'normal',
              risk_level: isAttack ? (Math.random() > 0.8 ? 'critical' : 'high') : 'low',
              confidence: Math.random(),
              status: 'detected',
              reputation_score: Math.floor(Math.random() * 100),
              bot_score: Math.random()
            });
          }
          addEvents(batch);
        }, 5000);
      };

      runSimulation();
      return () => clearInterval(interval);
    }
  }, [currentScreen, operationMode, config.gemini_key]);

  // Live Mode Logic
  useEffect(() => {
    if (currentScreen === 'dashboard' && operationMode === 'live' && uploadedFile) {
      const processFile = async () => {
        const { setProcessingState } = useSentinelStore.getState();
        
        // Cinematic Boot Sequence
        setProcessingState({ isBooting: true, consoleLogs: [] });
        
        const bootLogs = [
          "Initializing AI Core.......... OK",
          "Loading detection models....... OK",
          `File loaded: ${uploadedFile.name}........ OK`,
          "BEGIN ANALYSIS"
        ];

        for (const log of bootLogs) {
          useSentinelStore.setState(state => ({ consoleLogs: [...state.consoleLogs, `> ${log}`] }));
          await sleep(750);
        }

        setProcessingState({
          isBooting: false,
          isProcessing: true,
          processingProgress: 0,
          consoleLogs: [...useSentinelStore.getState().consoleLogs, "--------------------------------"]
        });
        
        Papa.parse(uploadedFile, {
          header: true,
          complete: async (results) => {
            const data = results.data as any[];
            setProcessingState({ totalEvents: data.length, processingProgress: 0, isProcessing: true });
            
            useSentinelStore.setState({ events: [] });

            for (let i = 0; i < data.length; i++) {
              const row = data[i];
              const analyzed = analyzeRow(row);
              
              const event: Event = {
                ...analyzed,
                event_id: Math.random().toString(36).substr(2, 9),
                timestamp: new Date().toISOString(),
                status: 'detected',
                mitre: MITRE_MAP[analyzed.attack_type.toLowerCase()]
              };
              
              addEvents([event]);
              
              const logMsg = `[${new Date().toLocaleTimeString()}] ${event.src_ip} -> ${event.attack_type.toUpperCase()} (${event.risk_level})`;
              useSentinelStore.setState(state => ({ 
                consoleLogs: [...state.consoleLogs, logMsg].slice(-50),
                processingProgress: i + 1 
              }));
              
              if (event.risk_level === 'high' || event.risk_level === 'critical') {
                triggerThreatAlert(event);
                await sleep(500);
              }
              
              await sleep(150);
            }
            setProcessingState({ isProcessing: false });
            // Show summary modal (we'll use a local state in DashboardTab for this)
            // But we need to trigger it. Let's use a custom event or store state.
            // For now, I'll just set a flag in the store.
            useSentinelStore.setState({ isProcessing: false });
            // I'll add a way to trigger the modal in DashboardTab
            window.dispatchEvent(new CustomEvent('analysis-complete'));
          }
        });
      };
      
      processFile();
    }
  }, [currentScreen, operationMode, uploadedFile]);

  useEffect(() => {
    fetchConfig();
    if (operationMode !== 'simulation' && operationMode !== 'live') {
      fetchEvents();
      const interval = setInterval(fetchEvents, config.refresh_interval * 1000);
      return () => clearInterval(interval);
    }
  }, [config.refresh_interval, fetchConfig, fetchEvents, operationMode]);

  const triggerThreatAlert = (event: any) => {
    console.log(`[ALERT] Threat detected: ${event.attack_type} from ${event.src_ip}`);
    setActiveAlert(event);
    // Auto-close after 10 seconds
    setTimeout(() => {
      setActiveAlert((prev: any) => prev?.event_id === event.event_id ? null : prev);
    }, 10000);
  };

  useEffect(() => {
    if (config.dark_mode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [config.dark_mode]);

  useEffect(() => {
    const handleComplete = () => {
      // This will be caught by DashboardTab
    };
    window.addEventListener('analysis-complete', handleComplete);
    return () => window.removeEventListener('analysis-complete', handleComplete);
  }, []);



  return (
    <div className="min-h-screen bg-app-bg text-text-main font-sans selection:bg-cyan-500/30">
      <AnimatePresence mode="wait">
        {currentScreen === 'intro' && (
          <IntroScreen key="intro" onSkip={() => setScreen('mode-select')} />
        )}
        
        {currentScreen === 'mode-select' && (
          <ModeSelect key="mode-select" />
        )}

        {currentScreen === 'dashboard' && (
          <motion.div 
            key="dashboard"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex h-screen overflow-hidden"
          >
            <IPDetailsModal />
            
            <AnimatePresence>
              {activeAlert && (
                <AlertPopup 
                  event={activeAlert} 
                  onClose={() => setActiveAlert(null)} 
                  apiKey={config.gemini_key}
                  showAI={config.show_ai_alerts}
                />
              )}
            </AnimatePresence>
      
            <aside className="w-64 border-r border-black/5 dark:border-white/5 dark:bg-[#0a0a0a] bg-gray-100 flex flex-col z-20">
              <div className="p-6 flex items-center gap-3 border-b border-black/5 dark:border-white/5">
                <Shield className="text-cyan-400" size={24} />
                <div className="font-mono font-bold text-text-main tracking-tighter">GHOST SHIELD</div>
              </div>
              
              <nav className="flex-1 py-6">
                <SidebarItem icon={LayoutDashboard} label="Dashboard" active={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')} />
                <SidebarItem icon={Eye} label="Watchlist" active={activeTab === 'watchlist'} onClick={() => setActiveTab('watchlist')} />
                <SidebarItem icon={Terminal} label="Live Feed" active={activeTab === 'feed'} onClick={() => setActiveTab('feed')} />
                <SidebarItem icon={Shield} label="MITRE ATT&CK" active={activeTab === 'mitre'} onClick={() => setActiveTab('mitre')} />
                <SidebarItem icon={MapIcon} label="Attack Map" active={activeTab === 'map'} onClick={() => setActiveTab('map')} />
                <SidebarItem icon={BarChart3} label="Threat Graph" active={activeTab === 'graph'} onClick={() => setActiveTab('graph')} />
                <SidebarItem icon={Bot} label="Bot Detection" active={activeTab === 'bots'} onClick={() => setActiveTab('bots')} />
                <SidebarItem icon={FileText} label="Reports" active={activeTab === 'reports'} onClick={() => setActiveTab('reports')} />
                <SidebarItem icon={Settings} label="Settings" active={activeTab === 'settings'} onClick={() => setActiveTab('settings')} />
              </nav>

              <div className="p-6 border-t border-black/5 dark:border-white/5">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-8 h-8 rounded-full bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 flex items-center justify-center">
                    <User size={16} className="text-gray-500" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-mono text-text-main truncate">M. Payoneer</div>
                    <div className="text-[8px] font-mono text-cyan-400 uppercase">Level 4 Access</div>
                  </div>
                </div>
                <button 
                  onClick={() => setScreen('mode-select')}
                  className="w-full py-2 bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 rounded font-mono text-[10px] uppercase hover:bg-black/10 dark:bg-white/10 transition-colors"
                >
                  Switch Mode
                </button>
              </div>
            </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <header className="h-16 border-b border-black/5 dark:border-white/5 flex items-center justify-between px-8 dark:bg-[#0a0a0a] bg-gray-100/50 backdrop-blur-md z-10">
          {isProcessing && (
            <div className="absolute top-0 left-0 h-1 bg-cyan-400" style={{ width: `${(processingProgress / totalEvents) * 100}%` }}></div>
          )}
          <div className="flex items-center gap-8 flex-1">
            <div className="flex items-center gap-2">
              <Database size={16} className="text-gray-500" />
              <span className="font-mono text-[10px] text-gray-500 uppercase">System Status: <span className="text-green-500">Nominal</span></span>
            </div>
            <div className="h-4 w-px bg-black/10 dark:bg-white/10" />
            <div className="flex items-center gap-2">
              <Zap size={16} className="text-yellow-500" />
              <span className="font-mono text-[10px] text-gray-500 uppercase">AI Core: <span className="text-text-main">Active</span></span>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-4">
              <button className="relative text-gray-500 hover:text-text-main transition-colors" onClick={() => setActiveTab('watchlist')}>
                <Eye size={18} />
                {watchlist.length > 0 && (
                  <span className="absolute -top-1 -right-2 text-[10px] font-mono text-cyan-400">{watchlist.length}</span>
                )}
              </button>
              <button className="relative text-gray-500 hover:text-text-main transition-colors">
                <Bell size={18} />
                <span className="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full border-2 border-[#0a0a0a]" />
              </button>
              <button className="text-gray-500 hover:text-text-main transition-colors">
                <Search size={18} />
              </button>
            </div>
          </div>
        </header>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-8">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
              className="h-full"
            >
              {activeTab === 'dashboard' && <DashboardTab onTabChange={setActiveTab} />}
              {activeTab === 'watchlist' && (
                <div className="h-full overflow-y-auto">
                  <WatchlistWidget />
                </div>
              )}
              {activeTab === 'feed' && <LiveFeedTab search={search} setSearch={setSearch} />}
              {activeTab === 'mitre' && <MitreAttackTab />}
              {activeTab === 'map' && <AttackMapTab />}
              {activeTab === 'bots' && <BotDetectionTab />}
              {activeTab === 'settings' && <SettingsTab />}
              {activeTab === 'reports' && <ReportsTab />}
              {activeTab === 'graph' && <ThreatGraphTab />}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
