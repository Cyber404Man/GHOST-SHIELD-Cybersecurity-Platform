import os
import time
import random
import csv
import io
import httpx
from typing import List, Optional, Dict
from fastapi import FastAPI, UploadFile, File, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta

app = FastAPI(title="GHOST SHIELD Backend")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"[FastAPI] Incoming: {request.method} {request.url}")
    response = await call_next(request)
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Models ---

class Event(BaseModel):
    event_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    attack_type: str
    risk_level: str
    bot_score: float
    classification: str
    reputation_score: int
    country: str
    status: str
    prediction_hint: str

class IPDetails(BaseModel):
    ip: str
    country: str
    city: str
    isp: str
    asn: str
    abuse_score: int
    risk_level: str
    open_ports: List[int]
    tags: List[str]
    map_coords: List[float]

class Config(BaseModel):
    mode: str
    refresh_interval: int
    sensitivity: int
    auto_block_threshold: int
    auto_block_critical: bool
    show_predictions: bool
    dark_mode: bool
    animations: bool
    abuseipdb_key: str
    shodan_key: str
    gemini_key: str = ""
    auto_explain_high: bool = True
    show_ai_alerts: bool = True
    show_ai_modal: bool = True

# --- Global State ---

session_state = {
    "mode": "simulation",
    "start_time": datetime.now().isoformat(),
    "events_processed": 0
}

config_state = Config(
    mode="simulation",
    refresh_interval=5,
    sensitivity=5,
    auto_block_threshold=80,
    auto_block_critical=True,
    show_predictions=True,
    dark_mode=True,
    animations=True,
    abuseipdb_key="",
    shodan_key="",
    gemini_key="",
    auto_explain_high=True,
    show_ai_alerts=True,
    show_ai_modal=True
)

events_db: List[Event] = []

# --- Mock AI Pipeline ---

class MockModel:
    def predict(self, features):
        # features: [[bytes, protocol_num, port]]
        byte_count = features[0][0]
        if byte_count > 5000:
            return ['ddos']
        elif byte_count < 10:
            return ['port_scan']
        return ['normal']

class MockAnomaly:
    def predict(self, features):
        byte_count = features[0][0]
        if byte_count > 8000:
            return [-1] # Anomaly
        return [1] # Normal

def init_ai_models():
    return MockModel(), MockAnomaly()

clf_model, iso_model = init_ai_models()

# --- Helpers ---

def generate_simulated_event(seed_val=None):
    if seed_val:
        random.seed(seed_val)
    
    event_id = f"EVT-{random.randint(100000, 999999)}"
    timestamp = datetime.now().isoformat()
    
    # Mix: 70% normal, 30% attacks
    is_attack = random.random() < 0.3
    
    attack_types = ["brute_force", "port_scan", "ddos", "bot_activity", "suspicious_login", "scraping"]
    countries = ["USA", "China", "Russia", "Germany", "Brazil", "UK", "India", "Netherlands", "Japan", "Canada"]
    
    if not is_attack:
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        attack_type = "normal"
        risk_level = "low"
        bot_score = random.uniform(0, 0.2)
        classification = "benign"
        reputation_score = random.randint(80, 100)
        status = "allowed"
        prediction_hint = "High confidence: Normal user behavior"
    else:
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        attack_type = random.choice(attack_types)
        risk_level = random.choice(["medium", "high", "critical"])
        bot_score = random.uniform(0.6, 1.0)
        classification = "malicious"
        reputation_score = random.randint(0, 40)
        status = "blocked" if risk_level == "critical" else "detected"
        prediction_hint = f"Anomaly detected: {attack_type} pattern"

    return Event(
        event_id=event_id,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip="10.0.0.5",
        attack_type=attack_type,
        risk_level=risk_level,
        bot_score=round(bot_score, 2),
        classification=classification,
        reputation_score=reputation_score,
        country=random.choice(countries),
        status=status,
        prediction_hint=prediction_hint
    )

# Initialize with 50 events
random.seed(42)
for _ in range(50):
    events_db.append(generate_simulated_event())

# --- Endpoints ---

@app.post("/session/start")
async def start_session(mode: str = "simulation"):
    global session_state, events_db
    session_state["mode"] = mode
    session_state["start_time"] = datetime.now().isoformat()
    session_state["events_processed"] = 0
    
    if mode == "simulation":
        events_db = []
        random.seed(42)
        for _ in range(50):
            events_db.append(generate_simulated_event())
            
    return {"status": "success", "mode": mode}

@app.get("/session/state")
async def get_session_state():
    return session_state

import uuid
from fastapi.responses import StreamingResponse
import asyncio
import json

# --- Global State ---
sessions = {} # To store events per session_id
session_state = {
    "mode": "simulation",
    "start_time": datetime.now().isoformat(),
    "events_processed": 0
}

# ... (keep other global state)

# --- Endpoints ---

@app.post("/upload-logs")
async def upload_logs(file: UploadFile = File(...)):
    try:
        content = await file.read()
        decoded = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(decoded))
        
        required = ["timestamp", "src_ip", "dst_ip", "bytes", "protocol", "port"]
        
        new_events = []
        for row in reader:
            if not all(col in row for col in required):
                continue
            
            # Run AI Detection
            features = [[int(row['bytes']), 6 if row['protocol'] == 'TCP' else 17, int(row['port'])]]
            pred_type = clf_model.predict(features)[0]
            is_anomaly = iso_model.predict(features)[0] == -1
            
            risk = "low"
            if is_anomaly or pred_type != 'normal':
                risk = "high" if pred_type in ['ddos', 'brute_force'] else "medium"
            
            new_events.append({
                "timestamp": str(row['timestamp']),
                "src_ip": str(row['src_ip']),
                "dst_ip": str(row['dst_ip']),
                "attack_type": pred_type,
                "risk_level": risk,
                "confidence": round(random.uniform(0.8, 0.99), 3),
                "anomaly_score": round(random.uniform(-0.5, 0.5), 3),
                "processing_time": round(random.uniform(0.001, 0.008), 3)
            })
        
        session_id = str(uuid.uuid4())
        sessions[session_id] = {"events": new_events}
        return {"session_id": session_id, "events_count": len(new_events)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/session/stream")
async def stream_session(id: str):
    if id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
        
    async def generate():
        session = sessions[id]
        for i, event in enumerate(session["events"]):
            result = {
                "row": i + 1,
                "total": len(session["events"]),
                "src_ip": event["src_ip"],
                "dst_ip": event["dst_ip"],
                "attack_type": event["attack_type"],
                "risk_level": event["risk_level"].upper(),
                "confidence": event["confidence"],
                "anomaly_score": event["anomaly_score"],
                "processing_time": event["processing_time"]
            }
            
            yield f"data: {json.dumps(result)}\n\n"
            await asyncio.sleep(0.4)
    
    return StreamingResponse(generate(), media_type="text/event-stream")

@app.get("/session/report")
async def get_report(id: str):
    if id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    events = sessions[id]["events"]
    threats = [e for e in events if e["attack_type"] != "normal"]
    critical = [e for e in events if e["risk_level"] == "critical"]
    blocked = [e for e in events if e["risk_level"] in ["high", "critical"]]
    
    return {
        "total_logs": len(events),
        "threats_detected": len(threats),
        "ips_blocked": len(blocked),
        "critical_events": len(critical),
        "avg_response_time": round(sum(e["processing_time"] for e in events) / len(events), 3),
        "clean_traffic_pct": round((len(events) - len(threats)) / len(events) * 100, 1),
        "top_threat_origin": "China" # Simulated
    }

@app.get("/alerts")
async def get_alerts():
    # In simulation mode, add a new event occasionally
    if config_state.mode in ["simulation", "hybrid"]:
        if random.random() < 0.5:
            events_db.insert(0, generate_simulated_event())
            if len(events_db) > 200:
                events_db.pop()
    
    return events_db[:100]

@app.get("/attack-map-data")
async def get_attack_map_data():
    attacks = [e for e in events_db if e.attack_type != "normal"]
    return attacks

@app.get("/bot-detection/summary")
async def get_bot_summary():
    bots = [e for e in events_db if e.bot_score > 0.5]
    return {
        "total_bots": len(bots),
        "categories": {
            "scraper": len([b for b in bots if b.attack_type == "scraping"]),
            "brute_force": len([b for b in bots if b.attack_type == "brute_force"]),
            "spam": 5, # simulated
            "credential_stuffing": 3 # simulated
        },
        "bot_list": bots[:20]
    }

# --- Enrichment Data ---

ENRICHMENT_DATA = {
    "Germany": {
        "cities": ["Frankfurt", "Berlin", "Munich", "Hamburg", "Cologne"],
        "isps": [
            {"name": "Vodafone DE", "asn": "AS3209"},
            {"name": "Deutsche Telekom", "asn": "AS3320"},
            {"name": "Hetzner", "asn": "AS24940"},
            {"name": "1&1", "asn": "AS8560"}
        ],
        "coords": [51.16, 10.45]
    },
    "Russia": {
        "cities": ["Moscow", "Saint Petersburg", "Novosibirsk", "Kazan"],
        "isps": [
            {"name": "Rostelecom", "asn": "AS12389"},
            {"name": "MTS", "asn": "AS8359"},
            {"name": "Beeline", "asn": "AS3216"},
            {"name": "Yandex", "asn": "AS13238"}
        ],
        "coords": [61.52, 105.31]
    },
    "China": {
        "cities": ["Beijing", "Shanghai", "Shenzhen", "Guangzhou"],
        "isps": [
            {"name": "China Telecom", "asn": "AS4134"},
            {"name": "China Unicom", "asn": "AS4837"},
            {"name": "Alibaba Cloud", "asn": "AS37963"},
            {"name": "Tencent", "asn": "AS132203"}
        ],
        "coords": [35.86, 104.19]
    },
    "USA": {
        "cities": ["New York", "Los Angeles", "Chicago", "Dallas", "Seattle"],
        "isps": [
            {"name": "Comcast", "asn": "AS7922"},
            {"name": "AWS", "asn": "AS16509"},
            {"name": "Cloudflare", "asn": "AS13335"},
            {"name": "AT&T", "asn": "AS7018"}
        ],
        "coords": [37.09, -95.71]
    },
    "Brazil": {
        "cities": ["Sao Paulo", "Rio de Janeiro", "Brasilia"],
        "isps": [
            {"name": "Claro", "asn": "AS28573"},
            {"name": "Vivo", "asn": "AS26615"},
            {"name": "NET Virtua", "asn": "AS10429"}
        ],
        "coords": [-14.23, -51.92]
    },
    "Netherlands": {
        "cities": ["Amsterdam", "Rotterdam", "The Hague"],
        "isps": [
            {"name": "KPN", "asn": "AS286"},
            {"name": "Leaseweb", "asn": "AS60781"},
            {"name": "AMS-IX", "asn": "AS1200"}
        ],
        "coords": [52.13, 5.29]
    },
    "India": {
        "cities": ["Mumbai", "Delhi", "Bangalore", "Chennai"],
        "isps": [
            {"name": "Jio", "asn": "AS55836"},
            {"name": "Airtel", "asn": "AS9498"},
            {"name": "BSNL", "asn": "AS9829"}
        ],
        "coords": [20.59, 78.96]
    }
}

@app.get("/ip/details")
async def get_ip_details(ip: str):
    # Calculate seed from IP octets
    try:
        octets = [int(o) for o in ip.split('.')]
        seed = sum(octets)
    except:
        seed = 0
    
    countries = list(ENRICHMENT_DATA.keys())
    country_name = countries[seed % len(countries)]
    country_data = ENRICHMENT_DATA[country_name]
    
    city = country_data["cities"][seed % len(country_data["cities"])]
    isp_data = country_data["isps"][seed % len(country_data["isps"])]
    lat = country_data["coords"][0] + random.uniform(-2, 2)
    lng = country_data["coords"][1] + random.uniform(-2, 2)
    
    # Base simulation result
    result = {
        "ip": ip,
        "country": country_name,
        "city": city,
        "isp": isp_data["name"],
        "asn": isp_data["asn"],
        "abuse_score": random.randint(0, 100),
        "risk_level": "high" if random.random() > 0.7 else "low",
        "open_ports": [80, 443, 22, 8080] if random.random() > 0.5 else [80, 443],
        "tags": ["Botnet", "Scanner"] if random.random() > 0.8 else ["Data Center"],
        "map_coords": [lat, lng],
        "data_source": "Simulation"
    }
    
    # Override with real AbuseIPDB data if key exists
    abuse_key = config_state.abuseipdb_key or os.getenv("ABUSEIPDB_KEY", "")
    if abuse_key:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": abuse_key, "Accept": "application/json"}
                )
            if res.status_code == 200:
                data = res.json().get("data", {})
                result["abuse_score"] = data.get("abuseConfidenceScore", result["abuse_score"])
                result["country"] = data.get("countryCode", result["country"])
                result["isp"] = data.get("isp", result["isp"])
                result["data_source"] = "AbuseIPDB"
        except:
            pass  # Keep simulation data
            
    # Override with real Shodan data if key exists
    shodan_key = config_state.shodan_key or os.getenv("SHODAN_KEY", "")
    if shodan_key:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}"
                )
            if res.status_code == 200:
                data = res.json()
                result["open_ports"] = data.get("ports", result["open_ports"])
                result["isp"] = data.get("isp", result["isp"])
                result["country"] = data.get("country_name", result["country"])
                result["city"] = data.get("city", result["city"])
                result["asn"] = data.get("asn", result["asn"])
                result["data_source"] = "Shodan"
        except:
            pass  # Keep simulation data

    return result

@app.get("/config")
async def get_config():
    return config_state

@app.post("/api/check-readiness")
async def check_readiness(keys: dict):
    results = {}
    
    # 1. CHECK GEMINI
    try:
        gemini_key = keys.get("gemini_key") or os.getenv("GEMINI_API_KEY", "")
        if not gemini_key:
            results["gemini"] = {
                "status": "missing",
                "message": "No API key configured",
                "impact": "AI threat explanations will be unavailable"
            }
        else:
            # Real test call to Gemini
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={gemini_key}",
                    json={"contents": [{"parts": [{"text": "test"}]}],
                          "generationConfig": {"maxOutputTokens": 5}}
                )
            if res.status_code == 200:
                results["gemini"] = {
                    "status": "connected",
                    "message": "Gemini AI ready",
                    "impact": "AI threat explanations active",
                    "model": "gemini-2.0-flash"
                }
            elif res.status_code == 400:
                results["gemini"] = {
                    "status": "connected",
                    "message": "Gemini AI ready",
                    "impact": "AI threat explanations active"
                }
            else:
                results["gemini"] = {
                    "status": "invalid_key",
                    "message": f"Invalid key (HTTP {res.status_code})",
                    "impact": "AI explanations will use fallback mode"
                }
    except Exception as e:
        results["gemini"] = {
            "status": "error",
            "message": f"Connection failed: {str(e)[:50]}",
            "impact": "AI explanations will use fallback mode"
        }

    # 2. CHECK ABUSEIPDB
    try:
        abuse_key = keys.get("abuseipdb_key") or os.getenv("ABUSEIPDB_KEY", "")
        if not abuse_key:
            results["abuseipdb"] = {
                "status": "missing",
                "message": "No API key configured",
                "impact": "IP reputation will use simulated scores"
            }
        else:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
                    headers={"Key": abuse_key, "Accept": "application/json"}
                )
            if res.status_code == 200:
                data = res.json()
                results["abuseipdb"] = {
                    "status": "connected",
                    "message": "AbuseIPDB ready",
                    "impact": "Real IP reputation scores active",
                    "daily_limit": data.get("data", {}).get("totalReports", "unknown")
                }
            elif res.status_code == 401:
                results["abuseipdb"] = {
                    "status": "invalid_key",
                    "message": "Invalid API key",
                    "impact": "IP reputation will use simulated scores"
                }
            elif res.status_code == 429:
                results["abuseipdb"] = {
                    "status": "rate_limited",
                    "message": "Rate limit reached",
                    "impact": "Will use cached/simulated data"
                }
            else:
                results["abuseipdb"] = {
                    "status": "error",
                    "message": f"HTTP {res.status_code}",
                    "impact": "IP reputation will use simulated scores"
                }
    except Exception as e:
        results["abuseipdb"] = {
            "status": "error",
            "message": f"Connection failed: {str(e)[:50]}",
            "impact": "IP reputation will use simulated scores"
        }

    # 3. CHECK SHODAN
    try:
        shodan_key = keys.get("shodan_key") or os.getenv("SHODAN_KEY", "")
        if not shodan_key:
            results["shodan"] = {
                "status": "missing",
                "message": "No API key configured",
                "impact": "Open ports will use simulated data"
            }
        else:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(
                    f"https://api.shodan.io/api-info?key={shodan_key}"
                )
            if res.status_code == 200:
                data = res.json()
                results["shodan"] = {
                    "status": "connected",
                    "message": "Shodan ready",
                    "impact": "Real port scanning data active",
                    "plan": data.get("plan", "unknown"),
                    "query_credits": data.get("query_credits", 0)
                }
            elif res.status_code == 401:
                results["shodan"] = {
                    "status": "invalid_key",
                    "message": "Invalid API key",
                    "impact": "Open ports will use simulated data"
                }
            else:
                results["shodan"] = {
                    "status": "error",
                    "message": f"HTTP {res.status_code}",
                    "impact": "Open ports will use simulated data"
                }
    except Exception as e:
        results["shodan"] = {
            "status": "error",
            "message": f"Connection failed: {str(e)[:50]}",
            "impact": "Open ports will use simulated data"
        }

    # Overall readiness
    connected = sum(1 for r in results.values() if isinstance(r, dict) and r.get("status") == "connected")
    total = 3
    
    results["overall"] = {
        "connected": connected,
        "total": total,
        "ready": connected == total,
        "level": "FULL" if connected == total else 
                 "PARTIAL" if connected > 0 else "OFFLINE"
    }
    
    return results

@app.post("/config")
async def update_config(new_config: Config):
    global config_state
    config_state = new_config
    return config_state

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
