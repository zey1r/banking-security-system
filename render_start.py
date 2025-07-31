#!/usr/bin/env python3
"""
VeriVigil Banking Fraud Detection API - Render Production Starter
Ultra-minimal deployment for Render.com free tier
"""

import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Create minimal FastAPI app
app = FastAPI(
    title="Banking Fraud Detection API - Minimal", 
    description="Lightweight fraud detection service",
    version="1.0.0"
)

# CORS for GitHub Pages integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://zey1r.github.io", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "🏦 Banking Fraud Detection API is running!", "status": "online"}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "fraud-detection-api", "version": "1.0.0"}

@app.post("/fraud-detection/analyze")
async def analyze_fraud_minimal(data: dict):
    """Minimal fraud detection without ML dependencies"""
    
    # Basic rule-based fraud detection
    amount = float(data.get("amount", 0))
    currency = data.get("currency", "TRY")
    location = data.get("location", "").lower()
    merchant_category = data.get("merchant_category", "").lower()
    
    # Simple risk scoring
    risk_score = 0.1  # Base risk
    
    # Amount-based risk
    if amount > 10000:
        risk_score += 0.3
    if amount > 50000:
        risk_score += 0.2
    if amount > 100000:
        risk_score += 0.2
    
    # Location-based risk
    high_risk_locations = ["dubai", "nigeria", "russia"]
    if any(loc in location for loc in high_risk_locations):
        risk_score += 0.25
    
    # Category-based risk
    high_risk_categories = ["casino", "gambling", "crypto"]
    if any(cat in merchant_category for cat in high_risk_categories):
        risk_score += 0.3
    
    # Currency risk
    if currency != "TRY":
        risk_score += 0.15
    
    # Cap risk score
    risk_score = min(risk_score, 0.99)
    
    return {
        "transaction_id": data.get("transaction_id", "UNKNOWN"),
        "risk_score": round(risk_score, 3),
        "risk_level": "HIGH" if risk_score > 0.7 else "MEDIUM" if risk_score > 0.4 else "LOW",
        "is_fraud": risk_score > 0.7,
        "confidence": 0.85,
        "message": f"Risk analysis completed - {risk_score*100:.1f}% risk detected"
    }

if __name__ == "__main__":
    # Render ortam değişkenlerini al
    port = int(os.environ.get("PORT", 8000))
    host = "0.0.0.0"
    
    print(f"🏦 VeriVigil Banking API starting on {host}:{port}")
    print(f"🌍 Environment: {os.environ.get('ENVIRONMENT', 'production')}")
    
    # Production-ready settings
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=True,
        workers=1  # Render free tier için optimize
    )
