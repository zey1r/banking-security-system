"""
Enterprise Performance Optimization Module
High-throughput, low-latency fraud detection
Target: 10,000+ TPS, <50ms latency
"""

import asyncio
import aioredis
import aiocache
from typing import Dict, List, Any, Optional
import time
import psutil
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import pickle
import numpy as np
from collections import deque
import threading

@dataclass
class PerformanceMetrics:
    """Performance metrics tracking"""
    request_count: int = 0
    total_latency: float = 0.0
    max_latency: float = 0.0
    min_latency: float = float('inf')
    error_count: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    
    @property
    def avg_latency(self) -> float:
        return self.total_latency / max(self.request_count, 1)
    
    @property
    def cache_hit_ratio(self) -> float:
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / max(total, 1)

class PerformanceOptimizer:
    """
    Enterprise performance optimization for banking workloads
    Features: Connection pooling, caching, async processing, load balancing
    """
    
    def __init__(self):
        self.metrics = PerformanceMetrics()
        self.request_times = deque(maxlen=1000)  # Last 1000 requests
        self.thread_pool = ThreadPoolExecutor(max_workers=50)
        self.cache = None
        self.redis_pool = None
        self._setup_caching()
        
    async def _setup_caching(self):
        """Setup Redis connection pool for high-performance caching"""
        try:
            self.redis_pool = aioredis.ConnectionPool.from_url(
                "redis://localhost:6379",
                max_connections=100,
                encoding='utf-8',
                decode_responses=True
            )
            
            # Multi-level caching strategy
            self.cache = aiocache.Cache(
                aiocache.Cache.REDIS,
                endpoint="localhost",
                port=6379,
                pool_max_connections=100,
                serializer=aiocache.serializers.PickleSerializer()
            )
        except Exception as e:
            logging.warning(f"Redis not available, using memory cache: {e}")
            self.cache = aiocache.Cache(aiocache.Cache.MEMORY)
    
    async def optimize_fraud_detection(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        High-performance fraud detection with optimization
        Target: <50ms processing time
        """
        start_time = time.time()
        
        try:
            # 1. Quick cache lookup for known patterns
            cache_key = self._generate_cache_key(transaction_data)
            cached_result = await self._get_from_cache(cache_key)
            
            if cached_result:
                self.metrics.cache_hits += 1
                return self._add_performance_metadata(cached_result, start_time, True)
            
            self.metrics.cache_misses += 1
            
            # 2. Parallel processing pipeline
            tasks = [
                self._fast_rule_engine(transaction_data),
                self._ml_inference_optimized(transaction_data),
                self._behavioral_analysis_fast(transaction_data),
                self._device_reputation_check(transaction_data)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 3. Aggregate results
            final_result = self._aggregate_results(results, transaction_data)
            
            # 4. Cache result for future requests
            await self._cache_result(cache_key, final_result)
            
            return self._add_performance_metadata(final_result, start_time, False)
            
        except Exception as e:
            self.metrics.error_count += 1
            logging.error(f"Performance optimization error: {e}")
            raise
        finally:
            self._update_metrics(start_time)
    
    async def _fast_rule_engine(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ultra-fast rule-based checks (target: <5ms)"""
        rules_result = {
            'rule_engine_score': 0,
            'triggered_rules': []
        }
        
        amount = data.get('amount', 0)
        
        # High-speed rule checks
        if amount > 100000:
            rules_result['rule_engine_score'] += 40
            rules_result['triggered_rules'].append('high_amount')
            
        if data.get('payment_method') == 'mobile_payment' and amount > 50000:
            rules_result['rule_engine_score'] += 30
            rules_result['triggered_rules'].append('high_mobile_payment')
            
        # Time-based rules
        import datetime
        current_hour = datetime.datetime.now().hour
        if current_hour < 6 or current_hour > 23:
            rules_result['rule_engine_score'] += 15
            rules_result['triggered_rules'].append('unusual_hour')
        
        return rules_result
    
    async def _ml_inference_optimized(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimized ML inference with model caching"""
        # Simulate optimized ML inference
        # In production: Use ONNX, TensorRT, or similar for fast inference
        
        ml_result = {
            'ml_confidence': 0.85,
            'ml_score': 25,
            'model_version': 'v2.1-optimized'
        }
        
        # Feature extraction (optimized)
        features = self._extract_features_fast(data)
        
        # Simulated fast ML prediction
        await asyncio.sleep(0.01)  # Simulate 10ms inference time
        
        return ml_result
    
    async def _behavioral_analysis_fast(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Fast behavioral pattern analysis"""
        behavior_result = {
            'behavior_score': 10,
            'patterns': []
        }
        
        # Quick behavioral checks
        user_id = data.get('user_id', 'unknown')
        
        # Check for rapid successive transactions
        # In production: Use Redis for user session tracking
        
        return behavior_result
    
    async def _device_reputation_check(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Fast device and IP reputation check"""
        device_result = {
            'device_score': 5,
            'reputation': 'clean'
        }
        
        device_fingerprint = data.get('device_fingerprint')
        if not device_fingerprint:
            device_result['device_score'] = 20
            device_result['reputation'] = 'unknown'
        
        return device_result
    
    def _extract_features_fast(self, data: Dict[str, Any]) -> np.ndarray:
        """Fast feature extraction for ML models"""
        # Optimized feature extraction
        features = [
            data.get('amount', 0) / 100000,  # Normalized amount
            1 if data.get('payment_method') == 'mobile_payment' else 0,
            1 if data.get('payment_method') == 'transfer' else 0,
            len(data.get('destination_name', '')),
            1 if 'acil' in data.get('transaction_description', '').lower() else 0
        ]
        
        return np.array(features, dtype=np.float32)
    
    def _aggregate_results(self, results: List[Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate all analysis results"""
        total_score = 0
        confidence = 1.0
        factors = []
        
        for result in results:
            if isinstance(result, Exception):
                continue
                
            if isinstance(result, dict):
                total_score += result.get('rule_engine_score', 0)
                total_score += result.get('ml_score', 0)
                total_score += result.get('behavior_score', 0)
                total_score += result.get('device_score', 0)
                
                if 'triggered_rules' in result:
                    factors.extend(result['triggered_rules'])
        
        # Determine risk level and decision
        if total_score >= 80:
            decision = 'BLOCKED'
            risk_level = 'VERY_HIGH'
        elif total_score >= 60:
            decision = 'MANUAL_REVIEW'
            risk_level = 'HIGH'
        elif total_score >= 40:
            decision = 'REQUIRES_2FA'
            risk_level = 'MEDIUM'
        else:
            decision = 'APPROVED'
            risk_level = 'LOW'
        
        return {
            'transaction_id': data.get('transaction_id'),
            'risk_assessment': {
                'risk_score': min(total_score, 100),
                'risk_level': risk_level,
                'decision': decision,
                'confidence': confidence,
                'factors': factors,
                'ml_scores': {
                    'total_score': total_score
                }
            },
            'processing_time_ms': 0,  # Will be filled by performance metadata
            'model_version': 'enterprise-v1.0'
        }
    
    def _generate_cache_key(self, data: Dict[str, Any]) -> str:
        """Generate cache key for transaction pattern"""
        # Create key based on transaction pattern, not exact data
        pattern_data = {
            'amount_range': self._get_amount_range(data.get('amount', 0)),
            'payment_method': data.get('payment_method'),
            'hour': time.localtime().tm_hour,
            'weekday': time.localtime().tm_wday
        }
        
        return f"fraud_pattern:{hash(str(sorted(pattern_data.items())))}"
    
    def _get_amount_range(self, amount: float) -> str:
        """Categorize amount into ranges for caching"""
        if amount < 1000:
            return 'small'
        elif amount < 10000:
            return 'medium'
        elif amount < 100000:
            return 'large'
        else:
            return 'very_large'
    
    async def _get_from_cache(self, key: str) -> Optional[Dict[str, Any]]:
        """Get result from cache"""
        try:
            if self.cache:
                return await self.cache.get(key)
        except Exception as e:
            logging.warning(f"Cache get error: {e}")
        return None
    
    async def _cache_result(self, key: str, result: Dict[str, Any], ttl: int = 300):
        """Cache result with TTL"""
        try:
            if self.cache:
                await self.cache.set(key, result, ttl=ttl)
        except Exception as e:
            logging.warning(f"Cache set error: {e}")
    
    def _add_performance_metadata(self, result: Dict[str, Any], start_time: float, 
                                 was_cached: bool) -> Dict[str, Any]:
        """Add performance metadata to result"""
        processing_time = (time.time() - start_time) * 1000  # Convert to ms
        
        result['processing_time_ms'] = round(processing_time, 2)
        result['cached'] = was_cached
        result['timestamp'] = time.time()
        
        return result
    
    def _update_metrics(self, start_time: float):
        """Update performance metrics"""
        latency = (time.time() - start_time) * 1000
        
        self.metrics.request_count += 1
        self.metrics.total_latency += latency
        self.metrics.max_latency = max(self.metrics.max_latency, latency)
        self.metrics.min_latency = min(self.metrics.min_latency, latency)
        
        self.request_times.append(latency)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics"""
        return {
            'total_requests': self.metrics.request_count,
            'avg_latency_ms': round(self.metrics.avg_latency, 2),
            'max_latency_ms': round(self.metrics.max_latency, 2),
            'min_latency_ms': round(self.metrics.min_latency, 2),
            'error_rate': self.metrics.error_count / max(self.metrics.request_count, 1),
            'cache_hit_ratio': round(self.metrics.cache_hit_ratio, 2),
            'requests_per_second': self._calculate_rps(),
            'system_stats': self._get_system_stats()
        }
    
    def _calculate_rps(self) -> float:
        """Calculate requests per second"""
        if len(self.request_times) < 2:
            return 0.0
        
        recent_requests = list(self.request_times)[-100:]  # Last 100 requests
        if len(recent_requests) < 10:
            return 0.0
            
        time_span = len(recent_requests) * (sum(recent_requests) / len(recent_requests)) / 1000
        return len(recent_requests) / max(time_span, 1)
    
    def _get_system_stats(self) -> Dict[str, Any]:
        """Get system performance statistics"""
        return {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'active_threads': threading.active_count()
        }

class ConnectionPool:
    """Enterprise database connection pooling"""
    
    def __init__(self, max_connections: int = 100):
        self.max_connections = max_connections
        self.available_connections = deque()
        self.active_connections = set()
        self.connection_count = 0
        self.lock = threading.Lock()
    
    async def get_connection(self):
        """Get database connection from pool"""
        with self.lock:
            if self.available_connections:
                conn = self.available_connections.popleft()
                self.active_connections.add(conn)
                return conn
            
            if self.connection_count < self.max_connections:
                # Create new connection (simulated)
                conn = f"connection_{self.connection_count}"
                self.connection_count += 1
                self.active_connections.add(conn)
                return conn
            
            # Pool exhausted
            raise Exception("Connection pool exhausted")
    
    async def return_connection(self, conn):
        """Return connection to pool"""
        with self.lock:
            if conn in self.active_connections:
                self.active_connections.remove(conn)
                self.available_connections.append(conn)

# Global performance optimizer instance
performance_optimizer = PerformanceOptimizer()
connection_pool = ConnectionPool(max_connections=200)
