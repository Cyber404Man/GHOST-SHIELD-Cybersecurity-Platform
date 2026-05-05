import { create } from 'zustand';
import axios from 'axios';
import { NormalizedEvent as Event, AppConfig as Config, IPDetails, PredictionInfo } from './types';

// Create a custom axios instance for API calls
const api = axios.create({
  baseURL: '/api'
});

// Add a request interceptor to include the API key
api.interceptors.request.use((config) => {
  // Try multiple ways to get the API key
  const apiKey = (import.meta as any).env?.VITE_GEMINI_API_KEY || 
                 (import.meta as any).env?.GEMINI_API_KEY || 
                 (process.env as any).GEMINI_API_KEY ||
                 (window as any).GEMINI_API_KEY;
                   
  console.log(`[API] API Key Present: ${!!apiKey}`);
  if (apiKey) {
    config.headers['x-goog-api-key'] = apiKey;
    // Also add to URL as fallback
    const url = new URL(config.url || '', window.location.origin);
    url.searchParams.set('key', apiKey);
    config.url = url.pathname + url.search;
  }
  
  console.log(`[API] Request to ${config.url}`);
  console.log(`[API] Headers:`, JSON.stringify(config.headers));
  return config;
}, (error) => {
  return Promise.reject(error);
});

export interface BlockedIP {
  ip: string;
  country: string;
  city: string;
  attack_type: string;
  risk_level: string;
  blocked_at: string;
  flag: string;
}

interface SentinelState {
  events: Event[];
  config: Config;
  session: { mode: string; start_time: string; events_processed: number };
  selectedIP: string | null;
  ipDetails: IPDetails | null;
  ipLoading: boolean;
  uploadLoading: boolean;
  blockedIPs: BlockedIP[];
  watchlist: string[];
  prediction: PredictionInfo | null;
  predictionDismissedAt: number | null;
  
  // 3-screen flow state
  currentScreen: 'intro' | 'mode-select' | 'dashboard';
  operationMode: 'simulation' | 'live' | null;
  uploadedFile: File | null;
  simulationSource: 'gemini' | 'local' | 'fallback';
  
  // Processing state
  totalEvents: number;
  processingProgress: number;
  isProcessing: boolean;
  isPaused: boolean;
  isBooting: boolean;
  consoleLogs: string[];
  feedFilter: 'all' | 'threats' | 'blocked';
  
  fetchEvents: () => Promise<void>;
  fetchConfig: () => Promise<void>;
  updateConfig: (newConfig: Partial<Config>) => Promise<void>;
  fetchIPDetails: (ip: string) => Promise<void>;
  setSelectedIP: (ip: string | null) => void;
  startSession: (mode: string) => Promise<void>;
  uploadLogs: (file: File) => Promise<void>;
  blockIP: (ipData: BlockedIP) => void;
  unblockIP: (ip: string) => void;
  toggleWatchIP: (ip: string) => void;
  fetchPrediction: () => Promise<void>;
  dismissPrediction: () => void;
  setProcessingState: (state: Partial<Pick<SentinelState, 'totalEvents' | 'processingProgress' | 'isProcessing' | 'isPaused' | 'isBooting' | 'consoleLogs'>> & { session?: Partial<SentinelState['session']> }) => void;
  setScreen: (screen: 'intro' | 'mode-select' | 'dashboard') => void;
  setOperationMode: (mode: 'simulation' | 'live' | null, file?: File | null) => void;
  addEvents: (newEvents: Event[]) => void;
  setFeedFilter: (filter: 'all' | 'threats' | 'blocked') => void;
}

export const useSentinelStore = create<SentinelState>((set, get) => ({
  events: [],
  config: {
    mode: 'simulation',
    refresh_interval: 5,
    sensitivity: 5,
    auto_block_threshold: 80,
    auto_block_critical: true,
    show_predictions: true,
    dark_mode: true,
    animations: true,
    abuseipdb_key: '',
    shodan_key: '',
    gemini_key: localStorage.getItem('ghost_shield_gemini_key') || (process.env as any).GEMINI_API_KEY || (import.meta as any).env?.VITE_GEMINI_API_KEY || '',
    auto_explain_high: true,
    show_ai_alerts: true,
    show_ai_modal: true,
  },
  session: { mode: 'simulation', start_time: '', events_processed: 0 },
  selectedIP: null,
  ipDetails: null,
  ipLoading: false,
  uploadLoading: false,
  blockedIPs: [],
  watchlist: JSON.parse(localStorage.getItem('sentinel_watchlist') || '[]'),
  prediction: null,
  predictionDismissedAt: null,
  
  // 3-screen flow state
  currentScreen: 'intro',
  operationMode: null,
  uploadedFile: null,
  simulationSource: 'fallback',
  
  // Processing state
  totalEvents: 0,
  processingProgress: 0,
  isProcessing: false,
  isPaused: false,
  isBooting: false,
  consoleLogs: [],
  feedFilter: 'all',

  setScreen: (screen) => set({ currentScreen: screen }),
  setOperationMode: (mode, file = null) => set({ operationMode: mode, uploadedFile: file }),
  setFeedFilter: (filter) => set({ feedFilter: filter }),
  addEvents: (newEvents) => set((state) => {
    const { config, blockedIPs, events: currentEvents } = state;
    const newlyBlocked: BlockedIP[] = [];
    
    const processedEvents = newEvents.map(event => {
      // Check if already blocked in state or in this batch
      let isBlocked = blockedIPs.some(b => b.ip === event.src_ip) || 
                      newlyBlocked.some(b => b.ip === event.src_ip);
      
      // Auto-blocking logic
      if (!isBlocked) {
        const abuseScore = 100 - (event.reputation_score || 100);
        const shouldBlockCritical = config.auto_block_critical && event.risk_level === 'critical';
        const shouldBlockThreshold = abuseScore >= config.auto_block_threshold;
        
        if (shouldBlockCritical || shouldBlockThreshold) {
          isBlocked = true;
          newlyBlocked.push({
            ip: event.src_ip,
            country: event.country || 'Unknown',
            city: 'Auto-detected',
            attack_type: event.attack_type,
            risk_level: event.risk_level,
            blocked_at: new Date().toISOString(),
            flag: '🛡️'
          });
          
          // Log to console if in simulation/live
          console.log(`[AUTO-BLOCK] IP ${event.src_ip} blocked. Reason: ${shouldBlockCritical ? 'Critical Risk' : 'Abuse Threshold Exceeded'}`);
        }
      }
      
      return isBlocked ? { ...event, status: 'blocked' as const } : event;
    });

    return { 
      events: [...processedEvents, ...currentEvents].slice(0, 200),
      totalEvents: state.operationMode === 'simulation' ? state.totalEvents + newEvents.length : state.totalEvents,
      blockedIPs: [...blockedIPs, ...newlyBlocked]
    };
  }),

  setProcessingState: (state) => set((prev) => ({
    ...prev,
    ...state,
    session: state.session ? { ...prev.session, ...state.session } : prev.session
  })),

  fetchEvents: async () => {
    try {
      const res = await api.get('/alerts');
      const events = res.data;
      const { blockedIPs } = get();
      // Apply blocked status to events
      const updatedEvents = events.map((e: Event) => 
        blockedIPs.some(b => b.ip === e.src_ip) ? { ...e, status: 'blocked' } : e
      );
      set({ events: updatedEvents });
      
      // Auto-fetch prediction if something changed
      if (updatedEvents.some((e: Event) => e.risk_level === 'high' || e.risk_level === 'critical')) {
        get().fetchPrediction();
      }
    } catch (err: any) {
      console.error('Failed to fetch events', err.message);
    }
  },

  fetchConfig: async () => {
    try {
      const res = await api.get('/config');
      set((state) => ({ config: { ...state.config, ...res.data } }));
    } catch (err: any) {
      console.error('Failed to fetch config', err.message);
    }
  },
  updateConfig: async (newConfig) => {
    try {
      await api.post('/config', newConfig);
      set((state) => ({ config: { ...state.config, ...newConfig } }));
    } catch (err: any) {
      console.error('Failed to update config', err.message);
    }
  },
  fetchIPDetails: async (ip) => {
    set({ ipLoading: true });
    try {
      const res = await api.get(`/ip/${ip}`);
      set({ ipDetails: res.data, ipLoading: false });
    } catch (err: any) {
      console.error('Failed to fetch IP details', err.message);
      set({ ipLoading: false });
    }
  },
  setSelectedIP: (ip) => set({ selectedIP: ip }),
  startSession: async (mode) => {
    try {
      await api.post('/session/start', { mode });
      set({ session: { mode, start_time: new Date().toISOString(), events_processed: 0 } });
    } catch (err: any) {
      console.error('Failed to start session', err.message);
    }
  },
  uploadLogs: async (file) => {
    set({ uploadLoading: true });
    try {
      const formData = new FormData();
      formData.append('file', file);
      await api.post('/upload-logs', formData);
      set({ uploadLoading: false });
    } catch (err: any) {
      console.error('Failed to upload logs', err.message);
      set({ uploadLoading: false });
    }
  },
  toggleWatchIP: (ip) => {
    const { watchlist } = get();
    const newWatchlist = watchlist.includes(ip) 
      ? watchlist.filter(i => i !== ip) 
      : [...watchlist, ip];
    localStorage.setItem('sentinel_watchlist', JSON.stringify(newWatchlist));
    set({ watchlist: newWatchlist });
  },

  blockIP: (ipData) => {
    const { blockedIPs, events } = get();
    if (!blockedIPs.some(b => b.ip === ipData.ip)) {
      set({ 
        blockedIPs: [...blockedIPs, { ...ipData, blocked_at: new Date().toISOString() }],
        events: events.map(e => e.src_ip === ipData.ip ? { ...e, status: 'blocked' } : e)
      });
    }
  },

  unblockIP: (ip) => {
    const { blockedIPs, events } = get();
    set({ 
      blockedIPs: blockedIPs.filter(b => b.ip !== ip),
      events: events.map(e => e.src_ip === ip ? { ...e, status: 'detected' } : e)
    });
  },

  fetchPrediction: async () => {
    const { predictionDismissedAt } = get();
    // Do not show prediction if dismissed within the last 2 minutes
    if (predictionDismissedAt && (Date.now() - predictionDismissedAt) < 120000) {
       return;
    }

    try {
      const res = await api.get('/predict');
      set({ prediction: res.data });
    } catch (err: any) {
      console.error('Failed to fetch prediction', err.message);
    }
  },

  dismissPrediction: () => {
    set({ prediction: null, predictionDismissedAt: Date.now() });
  },
}));
