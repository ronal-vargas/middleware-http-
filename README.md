# middleware-http-
Middleware HTTP para FastAPI que detecta y bloquea escaneos abusivos, bots, ataques automatizados y amenazas de ransomware. Comparte tu experiencia y aporta mejoras para fortalecer juntos la seguridad de nuestras APIs. ¡La colaboración es bienvenida!

Introducción
¿Cansado de los escaneos abusivos, ataques automatizados y amenazas de ransomware?
Este middleware HTTP fue creado con el objetivo de banear bots, prevenir ataques y fortalecer la seguridad de tus aplicaciones. La motivación principal de este proyecto es compartir una solución real a los problemas de seguridad que enfrentamos a diario y construir, con la ayuda de la comunidad, un middleware cada vez más robusto.

Este repositorio está abierto a todos los desarrolladores interesados en mejorar la seguridad de sus sistemas y compartir experiencias.
Aquí podrás encontrar un punto de partida para proteger tus endpoints y, lo más importante, aprender juntos sobre nuevas amenazas y cómo mitigarlas. Todas las ideas, mejoras y reportes de vulnerabilidades serán bienvenidos.

¡Muchas gracias por tu interés!
Espero tus aportes.
Estamos aquí para aprender y crecer como comunidad.


¿Cómo funciona este middleware?
1. Normaliza y extrae datos clave de cada solicitud (IP, ruta, método, User-Agent, etc.).
2. Permite el paso a IPs confiables y rutas estáticas o de monitoreo mediante listas blancas.
3. Bloquea automáticamente las IPs que ya están marcadas como baneadas.
4. Aplica rate limiting por IP. Si se excede el límite, suma strikes y puede banear la IP.
5. Detecta User-Agent sospechosos y banea si se repite el comportamiento malicioso.
6. Analiza URLs y parámetros para detectar patrones de ataques (como SQLi, comandos o ransomware) y banea según sea necesario.
7. Restringe el acceso a la documentación (`/docs`, `/redoc`, `/openapi.json`) solo a usuarios autorizados.
8. Rechaza peticiones con payload demasiado grande para prevenir abusos.
9. Gestiona errores internos y registra toda la actividad relevante.
10. Suma strikes a IPs que generan muchos errores 404 sospechosos y las banea si se alcanza el umbral configurado.
11. Añade cabeceras de seguridad a las respuestas y mide el tiempo de cada petición para monitoreo.
12. Integra los eventos de seguridad con Fail2Ban, registrando todos los baneos y acciones sospechosas en logs compatibles para automatizar bloqueos a nivel de firewall.

El objetivo es bloquear amenazas comunes como bots, escáneres, fuerza bruta y ransomware antes de que lleguen a tu aplicación. Todos los eventos relevantes se registran para análisis y automatización de bloqueos mediante Fail2Ban.
