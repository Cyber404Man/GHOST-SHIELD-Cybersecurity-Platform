SYSTEM OVERVIEW
GHOST SHIELD is a next-generation cybersecurity platform designed for real-time threat
detection, analysis, and automated response. It leverages advanced AI models and the
MITRE ATT&CK framework to provide deep visibility into network traffic and potential
adversarial activities.

Core Objectives:
• Real-time monitoring of global network traffic.
• Automated classification of threats using AI Core.
• Predictive analysis to anticipate future attack vectors.
• Comprehensive mapping to the MITRE ATT&CK framework.
• Seamless integration of IP intelligence and reputation scoring.

2. KEY FEATURES
Feature
Description
Predictive AI
Engine
Analyzes current kill-chain stages to predict the next likely attack with probability and ETA.
MITRE Mapping
Every detected event is automatically mapped to real-world tactics and techniques (T1110,
T1595, etc.).
Live Analysis
Processes CSV logs line-by-line with cinematic visualization and real-time console feedback.
Global Attack Map
Interactive 3D visualization of source-to-destination attack vectors across the globe.
IP Intelligence
Deep-dive enrichment including ISP, ASN, Abuse Score, and Geolocation for every source IP.
Automated
Blocking
Configurable thresholds for automatic mitigation of critical and high-risk threats.

4. TECHNICAL ARCHITECTURE
Frontend Stack:
• React 19 + TypeScript
• Tailwind CSS 4.0 (Utility-first styling)
• Framer Motion (Advanced animations)
• Zustand (State management)
• D3.js & Recharts (Data visualization)
• Lucide React (Iconography)
Backend & AI Stack:
• Node.js + Express (Server environment)
• Google Gemini AI Core (Threat explanation & prediction)
• MITRE ATT&CK Knowledge Base (Framework mapping)
• IP Intelligence APIs (Enrichment source)

6. DATA MODELS
Entity
Key Properties
NormalizedEvent
event_id, timestamp, src_ip, attack_type, risk_level, mitre_info
IPDetails
ip, country, city, isp, abuse_score, open_ports, tags
MitreInfo
tactic, technique, technique_id, description, mitre_url
PredictionInfo
predicted_attack, probability, eta_minutes, confidence

8. USER GUIDE
Simulation Mode:
Used for training and testing. Generates synthetic attack patterns to demonstrate system
capabilities and AI response logic.
Live Analysis Mode:
Upload real network logs in CSV format. The system will analyze each entry, perform
enrichment, map to MITRE, and provide real-time alerts.
Predictive AI:
Monitor the Prediction Widget in the sidebar. When a high-confidence threat is predicted,
use the "Take Action Now" button to preemptively block the source
