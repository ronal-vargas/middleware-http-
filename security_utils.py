import re
import math
import json
import asyncio
import secrets
from datetime import datetime
from fastapi import Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from . import settings

# --- Path Utilities ---

def is_forbidden_path(path: str) -> bool:
    """Detecta rutas prohibidas según configuración."""
    return any(pattern.match(path) for pattern in settings.COMPILED_FORBIDDEN_PATTERNS)

# --- User-Agent Utilities ---

def is_suspicious_ua(ua: str) -> bool:
    """Detecta User-Agent sospechoso según patrones precompilados."""
    return any(pattern.search(ua) for pattern in settings.COMPILED_SUSPICIOUS_UA)

# --- Attack Detection ---

def detect_attack_type(full_path: str) -> str | None:
    """
    Detecta tipo de ataque en la URL/completa según patrones compilados.
    Retorna la clave del ataque (e.g. 'sql_injection') o None.
    """
    for attack_type, patterns in settings.COMPILED_ATTACK_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(full_path):
                return attack_type
    return None

# --- Suspicious 404 Detection ---

def is_suspicious_404(path: str) -> bool:
    """Detecta si un 404 debería considerarse sospechoso."""
    return any(pattern.search(path) for pattern in settings.COMPILED_SUSPICIOUS_404)

# --- Security Headers ---

def get_security_headers() -> dict[str, str]:
    """Devuelve los headers de seguridad para respuestas HTTP."""
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        ),
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "X-XSS-Protection": "1; mode=block",
        "Cache-Control": "no-store"
    }

# --- Entropy Calculation ---

def calculate_entropy(data: str | bytes) -> float:
    """Calcula la entropía de Shannon de una cadena o bytes para detectar ofuscación."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

# --- Client IP Extraction ---

def get_client_ip(request: Request) -> str:
    """Obtiene la IP real del cliente, considerando proxies."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host

# --- Ban and Strike Helpers ---

# Estas funciones pueden mover la lógica existente de main.py a un módulo propio.

async def add_strike(redis_client, ip: str, reason: str, context: dict) -> int:
    """Incrementa el contador de strikes y guarda contexto para un posible ban."""
    key = f"{settings.STRIKE_PREFIX}{ip}"
    info_key = f"{key}:info"
    timestamp = datetime.utcnow().isoformat()
    await redis_client.lpush(info_key, json.dumps({"timestamp": timestamp, "reason": reason, "context": context}))
    await redis_client.ltrim(info_key, 0, 9)
    strikes = await redis_client.incr(key)
    if strikes == 1:
        await redis_client.expire(key, settings.STRIKE_TTL_SEC)
        await redis_client.expire(info_key, settings.STRIKE_TTL_SEC)
    return strikes

async def ban_ip(redis_client, ip: str, reason: str, context: dict):
    """Banea una IP: Redis state + Fail2Ban + iptables."""
    ban_key = f"banned:{ip}"
    data = {"timestamp": datetime.utcnow().isoformat(), "reason": reason, "context": context, "duration": f"{settings.BAN_DURATION}s"}
    await redis_client.setex(ban_key, settings.BAN_DURATION, json.dumps(data))
    # Fail2Ban
    asyncio.create_task(
        asyncio.create_subprocess_exec(
            "sudo", "fail2ban-client", "set", "custom-scanner", "banip", ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
    )
    # iptables
    asyncio.create_task(
        asyncio.create_subprocess_exec(
            "sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
    )
