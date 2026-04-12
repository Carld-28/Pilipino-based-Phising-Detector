import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import json

from urllib3 import request

from detectors.url_detector import URLDetector
from detectors.message_detector import MessageDetector
from detectors.voice_detector import VoiceDetector
from database.mongo_client import MongoClient
from ml_predictor import predict_phishing

app = FastAPI(title="Phishing Detection API", version="1.0.0")

# Add this near the top of app.py (after app = FastAPI())
@app.get("/")
async def root():
    return {"message": "Hello! The backend is working perfectly."}


# CORS configuration for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000", "http://localhost:5000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize detectors and database
url_detector = URLDetector()
message_detector = MessageDetector()
voice_detector = VoiceDetector()
db = MongoClient()

# Request models
class URLScanRequest(BaseModel):
    url: str

class MessageScanRequest(BaseModel):
    message: str

# Response models
class ScanResult(BaseModel):
    is_phishing: bool
    risk_score: float
    ml_score: float = 0.0
    final_score: float = 0.0
    risk_level: str
    threats: list[str]
    explanation: str
    timestamp: str

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "phishing-detection"}

@app.post("/scan-url", response_model=ScanResult)
async def scan_url(request: URLScanRequest):
    
    print("URL RECEIVED:", request.url)

    try:
        
        result = url_detector.analyze(request.url)
        print("RESULT:", result)

        # --- ML Integration ---
        ml_score = predict_phishing(request.url)
        rule_score = result.get("risk_score", 0.0)
        final_score = (rule_score + ml_score) / 2
        
        is_phishing = final_score >= 0.7
        if final_score >= 0.7:
            risk_level = "HIGH"
        elif final_score >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        result["ml_score"] = ml_score
        result["final_score"] = final_score
        result["risk_level"] = risk_level
        result["is_phishing"] = is_phishing
        result["risk_score"] = final_score
        # ----------------------

        scan_record = {
            "type": "url",
            "input": request.url,
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        }

        try:
            db.save_scan(scan_record)
            print("✅ URL SAVED:", scan_record)
        except Exception as e:
            print("DB ERROR:", e)

        return ScanResult(
            is_phishing=is_phishing,
            risk_score=final_score,
            ml_score=ml_score,
            final_score=final_score,
            risk_level=risk_level,
            threats=result.get("threats", []),
            explanation=result.get("explanation", ""),
            timestamp=datetime.utcnow().isoformat()
        )

    except Exception as e:
        print("URL ERROR:", e)  # 🔥 THIS IS KEY
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/scan-message", response_model=ScanResult)
async def scan_message(request: MessageScanRequest):
    
    print("RAW REQUEST:", request)   # ✅ always safe

    try:
        print("Message:", request.message)  # ✅ now safe

        result = message_detector.analyze(request.message)

        # --- ML Integration ---
        ml_score = predict_phishing(request.message)
        rule_score = result.get("risk_score", 0.0)
        final_score = (rule_score + ml_score) / 2
        
        is_phishing = final_score >= 0.7
        if final_score >= 0.7:
            risk_level = "HIGH"
        elif final_score >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        result["ml_score"] = ml_score
        result["final_score"] = final_score
        result["risk_level"] = risk_level
        result["is_phishing"] = is_phishing
        result["risk_score"] = final_score
        # ----------------------

        scan_record = {
            "type": "message",
            "input": request.message,
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        }

        try:
            db.save_scan(scan_record)
            print("✅ MSG SAVED:", scan_record)
        except Exception as e:
            print("DB ERROR:", e)

        return ScanResult(
            is_phishing=is_phishing,
            risk_score=final_score,
            ml_score=ml_score,
            final_score=final_score,
            risk_level=risk_level,
            threats=result.get("threats", []),
            explanation=result.get("explanation", ""),
            timestamp=datetime.utcnow().isoformat()
        )

    except Exception as e:
        print("ERROR in scan_message:", e)
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/scan-voice")
async def scan_voice(file: UploadFile = File(...)):

    print("VOICE FILE RECEIVED:", file.filename)

    try:
        audio_content = await file.read()

        result = voice_detector.analyze(audio_content)

        # --- ML Integration ---
        transcript = result.get("transcript", "")
        ml_score = predict_phishing(transcript)
        rule_score = result.get("risk_score", 0.0)
        final_score = (rule_score + ml_score) / 2
        
        is_phishing = final_score >= 0.6
        if final_score >= 0.6:
            risk_level = "HIGH"
        elif final_score >= 0.3:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        result["ml_score"] = ml_score
        result["final_score"] = final_score
        result["risk_level"] = risk_level
        result["is_phishing"] = is_phishing
        result["risk_score"] = final_score
        # ----------------------

        scan_record = {
            "type": "voice",
            "filename": file.filename,
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        }

        try:
            db.save_scan(scan_record)
        except Exception as e:
            print("DB ERROR:", e)

        return ScanResult(
            is_phishing=is_phishing,
            risk_score=final_score,
            ml_score=ml_score,
            final_score=final_score,
            risk_level=risk_level,
            threats=result.get("threats", []),
            explanation=result.get("explanation", ""),
            timestamp=datetime.utcnow().isoformat()
        )

    except Exception as e:
        print("VOICE ERROR:", e)
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/scans")
async def get_scans(limit: int = 50):
    try:
        scans = db.get_scans(limit)
        print("SCANS:", scans)
        return {"scans": scans, "count": len(scans)}
    except Exception as e:
        print("SCAN FETCH ERROR:", e)
        return {"scans": [], "count": 0}
@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get a specific scan by ID"""
    try:
        scan = db.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("FASTAPI_PORT", 8000))
    uvicorn.run(app, host="localhost", port=port)
