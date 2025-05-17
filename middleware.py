@app.middleware("http")
async def secure_and_log(request: Request, call_next):
    start_time = time.time()
    # 1) Normalizar y datos básicos
    path = utils.normalize_path(request.url.path) if hasattr(utils, 'normalize_path') else request.url.path
    normalized = path.lower().strip()
    query_str = str(request.query_params)
    method = request.method
    client_ip = utils.get_client_ip(request)
    ua = request.headers.get("User-Agent", "Unknown")

    request_data = {
        "ip": client_ip,
        "method": method,
        "path": normalized,
        "query": query_str,
        "ua": ua
    }

    # 1.5) Si la IP está en whitelist temporal, saltamos todo
    whitelist_key = f"ip:trusted:{client_ip}"
    if await redis_client.exists(whitelist_key):
        return await call_next(request)

    rate_headers = {}

    # 2) Whitelist IPs y rutas estáticas (/metrics, ALLOWED_IPS, /static, OPTIONS)
    if normalized.startswith("/metrics"):
        if client_ip not in ALLOWED_IPS:
            return JSONResponse({"detail": "Access denied"}, status_code=403, headers=utils.get_security_headers())
        return await call_next(request)
    if client_ip in ALLOWED_IPS or normalized.startswith("/static") or method == "OPTIONS":
        return await call_next(request)

    # 3) Comprobar ban en Redis
    ban_key = f"banned:{client_ip}"
    if await redis_client.ttl(ban_key) > 0:
        banned_ips_total.inc()
        ttl = await redis_client.ttl(ban_key)
        security_logger.warning({**request_data, "event": "ip_banned", "remaining": f"{ttl}s"})
        return JSONResponse({"detail": "Access denied"}, status_code=403, headers=utils.get_security_headers())

    # 4) Rate limiting
    rate_key = f"rate:{client_ip}"
    req_count = await redis_client.incr(rate_key)
    ttl = await redis_client.ttl(rate_key)
    if req_count == 1:
        await redis_client.expire(rate_key, settings.RATE_LIMIT_WINDOW)
        ttl = settings.RATE_LIMIT_WINDOW

    rate_headers = {
        "X-RateLimit-Limit": str(settings.RATE_LIMIT_MAX),
        "X-RateLimit-Remaining": str(max(0, settings.RATE_LIMIT_MAX - req_count)),
        "X-RateLimit-Reset": str(ttl)
    }
    if req_count > settings.RATE_LIMIT_MAX:
        banned_ips_total.inc()
        security_logger.warning({**request_data, "event": "rate_limited", "count": req_count})
        await utils.add_strike(redis_client, client_ip, "rate_limit_exceeded", request_data)
        return JSONResponse(
            {"detail": "Too many requests"},
            status_code=429,
            headers={**utils.get_security_headers(), **rate_headers, "Retry-After": str(ttl)}
        )

    # 5) UA sospechoso
    if utils.is_suspicious_ua(ua):
        security_logger.warning({**request_data, "event": "suspicious_ua"})
        strikes = await utils.add_strike(redis_client, client_ip, "suspicious_ua", request_data)
        if strikes >= settings.STRIKE_THRESHOLD:
            await utils.ban_ip(redis_client, client_ip, "malicious_ua", request_data)
            banned_ips_total.inc()
            return JSONResponse({"detail": "Access denied"}, status_code=403, headers=utils.get_security_headers())

    # 6) Detección de ataque en URL/query
    full_path = f"{normalized}?{query_str}" if query_str else normalized
    attack_type = utils.detect_attack_type(full_path)
    if attack_type:
        security_logger.error({**request_data, "event": "attack_detected", "type": attack_type})
        strikes = await utils.add_strike(redis_client, client_ip, f"attack_{attack_type}", request_data)
        if attack_type in ("sql_injection", "command_injection", "ransomware_specific") or strikes >= settings.STRIKE_THRESHOLD:
            await utils.ban_ip(redis_client, client_ip, attack_type, request_data)
            banned_ips_total.inc()
            return JSONResponse({"detail": "Access denied"}, status_code=403, headers=utils.get_security_headers())

    # 7) Protección de /docs, /redoc, /openapi.json
    if normalized.startswith("/docs") or normalized.startswith("/redoc") or normalized == "/openapi.json":
        auth = request.headers.get("Authorization", "")
        if not secrets.compare_digest(auth, settings.DOCS_AUTH_HEADER):
            security_logger.warning({**request_data, "event": "unauth_docs"})
            await utils.add_strike(redis_client, client_ip, "unauthorized_docs", request_data)
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="docs"'})

    # 8) Limitar tamaño de payload
    if method in ("POST", "PUT", "PATCH"):
        cl = request.headers.get("content-length", "0")
        try:
            if int(cl) > settings.MAX_PAYLOAD_SIZE:
                security_logger.warning({**request_data, "event": "payload_too_large"})
                return JSONResponse({"detail": "Payload too large"}, status_code=413)
        except ValueError:
            pass

    # 9) Llamada al endpoint y captura de errores
    try:
        response = await call_next(request)
    except Exception as e:
        logger.exception(f"Error interno en {method} {normalized}: {e}")
        return JSONResponse({"detail": "Internal error"}, status_code=500)

    # 10) Strike & ban para 404s sospechosos
    if response.status_code == 404:
        # 10.1) Forbidden paths → ban inmediato
        if utils.is_forbidden_path(normalized):
            security_logger.error({**request_data, "event": "forbidden_path_immediate_ban"})
            banned_ips_total.inc()
            await utils.ban_ip(redis_client, client_ip, "forbidden_path", request_data)
            return JSONResponse({"detail": "Not Found"}, status_code=404)

        # 10.2) Whitelist dinámica de 404 (wildcards fnmatch)
        if any(fnmatch.fnmatch(normalized, w) for w in WHITELIST_404):
            return response

        # 10.3) Strikes para otros 404 y ban al umbral
        strike_key = f"{settings.STRIKE_PREFIX}{client_ip}"
        strikes = await redis_client.incr(strike_key)
        if strikes == 1:
            await redis_client.expire(strike_key, settings.STRIKE_TTL_SEC)
            security_logger.warning({
                **request_data,
                "event": "strike_404",
                "reason": "not_whitelisted",
                "count": 1
            })
        elif strikes >= settings.STRIKE_THRESHOLD:
            security_logger.error({**request_data, "event": "ban_after_404", "count": strikes})
            await utils.ban_ip(redis_client, client_ip, "excessive_404", request_data)
            banned_ips_total.inc()
        return JSONResponse({"detail": "Not Found"}, status_code=404)

    # 11) Añadir headers de seguridad
    for h, v in utils.get_security_headers().items():
        response.headers[h] = v

    # 12) Añadir X-RateLimit headers
    for h, v in rate_headers.items():
        response.headers[h] = v

    # 13) Medir duración de la petición
    request_duration.labels(method=method, endpoint=normalized).observe(time.time() - start_time)

    return response
