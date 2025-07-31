#!/usr/bin/env python3
"""
VeriVigil Banking Fraud Detection API - Render Production Starter
Optimized for Render.com deployment with minimal dependencies
"""

import os
import uvicorn

# Import with error handling for missing dependencies
try:
    from fraud_detection_api.api.main_simple import app
except ImportError as e:
    print(f"Import error: {e}")
    print("Creating minimal FastAPI app...")
    
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    
    app = FastAPI(title="Banking Fraud Detection API - Minimal")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://zey1r.github.io", "*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    @app.get("/")
    async def root():
        return {"message": "Banking Fraud Detection API is running!"}
    
    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "fraud-detection-api"}

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
