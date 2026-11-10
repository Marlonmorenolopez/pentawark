"""
Motor de recomendaciones de remediación (SecureScan Pro / PentaWark).

Contexto: antes de este módulo, el módulo de Pentesting detectaba
vulnerabilidades pero no explicaba qué hacer con ellas. El único rastro de
"remediación" en todo el backend era un campo `remediation: str` de una
sola línea en `InjectionFinding` (modules/pentesting/injection_scanner.py),
poblado solo para los 10 tipos de inyección de ese scanner concreto -- ZAP,
Nuclei, SQLMap, Metasploit y Searchsploit no tenían ninguna guía de
corrección asociada a sus hallazgos, y ni siquiera ese campo llegaba al
modelo unificado de Findings (ver findings.py) ni a los reportes.

Este módulo NO reemplaza nada existente: toma un Finding ya normalizado
por `findings.normalize_findings()` y le añade una guía de remediación
estructurada (`build_remediation()`), basada en reglas por categoría /
herramienta / tipo de inyección / prefijo de CVE. Cuando ninguna regla
coincide con suficiente confianza, se marca explícitamente
`requiere_revision_manual = True` y NO se inventan pasos específicos --
ver sección 8.2 del encargo: "No generes instrucciones específicas a
partir de información insuficiente como si fueran diagnóstico confirmado".

Uso:
    from remediation import build_remediation
    guia = build_remediation(finding)   # finding = un dict de findings.normalize_findings()
"""

from typing import Any, Callable, Dict, List, Optional
import re


# ── Tipos ────────────────────────────────────────────────────────────────────

Matcher = Callable[[Dict[str, Any]], bool]


def _raw(f: Dict[str, Any]) -> Dict[str, Any]:
    r = f.get('raw')
    return r if isinstance(r, dict) else {}


def _text(f: Dict[str, Any]) -> str:
    """Texto combinado (título + evidencia + tool) en minúsculas, para matching laxo."""
    parts = [f.get('title', ''), f.get('evidence', ''), f.get('tool', '')]
    raw = _raw(f)
    parts.append(str(raw.get('name', '')))
    parts.append(str(raw.get('description', '')))
    return ' '.join(p for p in parts if p).lower()


def by_injection_type(*prefixes: str) -> Matcher:
    """InjectionFinding/SQLMapFinding ambos exponen 'injection_type' en raw."""
    def _m(f: Dict[str, Any]) -> bool:
        it = str(_raw(f).get('injection_type', '')).lower()
        return any(it.startswith(p) for p in prefixes)
    return _m


def by_keyword(*keywords: str) -> Matcher:
    def _m(f: Dict[str, Any]) -> bool:
        t = _text(f)
        return any(k in t for k in keywords)
    return _m


def by_tool(*tools: str) -> Matcher:
    def _m(f: Dict[str, Any]) -> bool:
        return (f.get('tool') or '').lower() in tools
    return _m


def all_of(*matchers: Matcher) -> Matcher:
    return lambda f: all(m(f) for m in matchers)


def any_of(*matchers: Matcher) -> Matcher:
    return lambda f: any(m(f) for m in matchers)


# ── Catálogo de reglas ──────────────────────────────────────────────────────
#
# Cada regla se evalúa en orden; se aplica la PRIMERA que coincida (más
# específica primero). 'confianza' es 'alta' cuando la detección de la
# herramienta ya confirma el problema (ej. inyección activa con evidencia),
# 'media' cuando es un indicio que normalmente requiere revisión (ej.
# versión desactualizada detectada por fingerprint), nunca se inventa una
# causa específica para un hallazgo que la herramienta no la sustenta.

RULES: List[Dict[str, Any]] = [
    {
        'id': 'sql-injection',
        'match': any_of(by_injection_type('sql_'), by_tool('sqlmap')),
        'categoria': 'SQL Injection',
        'confianza': 'alta',
        'descripcion': (
            'La aplicación incorpora datos proporcionados por el usuario en una '
            'consulta SQL sin parametrizarlos ni validarlos adecuadamente. Esto '
            'permite alterar la lógica de la consulta para leer, modificar o '
            'eliminar datos fuera del alcance previsto, y en algunos casos '
            'ejecutar comandos en el servidor de base de datos.'
        ),
        'impacto': (
            'Acceso no autorizado a datos (confidencialidad), modificación o '
            'borrado de registros (integridad) y, según los privilegios de la '
            'cuenta de base de datos, posible compromiso del servidor que la aloja.'
        ),
        'causa_probable': (
            'Concatenación de entrada del usuario directamente en la sentencia SQL '
            '(string building) en lugar de usar consultas parametrizadas o un ORM '
            'con enlace de parámetros.'
        ),
        'pasos': [
            'Localizar la consulta vulnerable y el punto de entrada (parámetro/endpoint) reportado en la evidencia.',
            'Reemplazar la concatenación de cadenas por consultas parametrizadas (prepared statements) o por el mecanismo de binding del ORM en uso.',
            'Aplicar el principio de mínimo privilegio a la cuenta de base de datos usada por la aplicación (sin DROP/GRANT salvo que sea estrictamente necesario).',
            'Validar el tipo y formato de la entrada en el servidor (no solo en el cliente) como defensa adicional, nunca como única mitigación.',
            'Agregar una prueba automatizada (unitaria o de integración) que envíe el payload detectado y verifique que la consulta ya no se altera.',
        ],
        'ejemplo_vulnerable': {
            'lang': 'python', 'tech': 'Python / psycopg2 (genérico)',
            'code': 'query = f"SELECT * FROM users WHERE username = \'{username}\'"\ncursor.execute(query)',
        },
        'ejemplo_corregido': {
            'lang': 'python', 'tech': 'Python / psycopg2 (genérico)',
            'code': 'query = "SELECT * FROM users WHERE username = %s"\ncursor.execute(query, (username,))',
        },
        'prevencion': [
            'Usar consultas parametrizadas o un ORM en todo el acceso a datos, sin excepciones "por comodidad".',
            'Mínimo privilegio en la cuenta de base de datos de la aplicación.',
            'Incluir reglas SAST (ej. Semgrep) que detecten concatenación de SQL en CI.',
            'Pruebas de seguridad automatizadas (DAST) como parte del pipeline.',
        ],
        'verificacion': (
            'Repetir la prueba de inyección con el mismo payload y punto de entrada '
            'contra un entorno autorizado; la consulta corregida debe tratar el '
            'payload como dato literal (sin alterar el resultado ni producir errores '
            'de sintaxis SQL). Un reintento sin resultados NO es evidencia de '
            'corrección si el servicio no respondió o la prueba no pudo completarse.'
        ),
        'referencias': [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
        ],
    },
    {
        'id': 'xss',
        'match': any_of(by_injection_type('xss_'), by_keyword('cross-site scripting', 'xss')),
        'categoria': 'Cross-Site Scripting (XSS)',
        'confianza': 'alta',
        'descripcion': (
            'La aplicación refleja o almacena datos del usuario en el HTML de la '
            'respuesta sin codificarlos (output encoding), lo que permite inyectar '
            'código JavaScript que se ejecuta en el navegador de otros usuarios.'
        ),
        'impacto': (
            'Robo de sesión (cookies/tokens), suplantación de la víctima frente a la '
            'aplicación, phishing dentro del dominio confiable, o modificación del '
            'contenido visto por otros usuarios.'
        ),
        'causa_probable': (
            'Ausencia de codificación de salida (output encoding) específica del '
            'contexto HTML/JS/atributo donde se inserta el dato, o uso de '
            'funciones que insertan HTML sin sanitizar (ej. innerHTML, dangerouslySetInnerHTML).'
        ),
        'pasos': [
            'Identificar el parámetro y el contexto de salida exactos donde se refleja/almacena el dato (ver evidencia).',
            'Aplicar codificación de salida apropiada al contexto (HTML entity encoding, JS string escaping, atributo HTML) en el punto de renderizado, no en el de entrada.',
            'Si se requiere HTML enriquecido, usar una librería de sanitización confiable (ej. DOMPurify) en vez de una lista negra propia.',
            'Añadir cabecera Content-Security-Policy restrictiva como defensa en profundidad.',
            'Marcar las cookies de sesión como HttpOnly y Secure para reducir el impacto si el XSS persiste.',
        ],
        'ejemplo_vulnerable': {
            'lang': 'javascript', 'tech': 'JavaScript / DOM',
            'code': 'resultsDiv.innerHTML = "Resultados para: " + userInput;',
        },
        'ejemplo_corregido': {
            'lang': 'javascript', 'tech': 'JavaScript / DOM',
            'code': 'resultsDiv.textContent = "Resultados para: " + userInput;\n// o, si se necesita HTML: resultsDiv.innerHTML = DOMPurify.sanitize(html);',
        },
        'prevencion': [
            'Codificación de salida por defecto en el framework/motor de plantillas (la mayoría ya la aplica si no se desactiva explícitamente).',
            'Content-Security-Policy sin \'unsafe-inline\'.',
            'Cookies de sesión HttpOnly + Secure + SameSite.',
            'Revisión de cualquier uso de innerHTML/dangerouslySetInnerHTML/v-html en el repositorio.',
        ],
        'verificacion': (
            'Reenviar el mismo payload al mismo parámetro/endpoint y confirmar que '
            'aparece codificado en la respuesta (ej. &lt;script&gt; en vez de '
            '<script>) en lugar de ejecutarse.'
        ),
        'referencias': [
            'https://owasp.org/www-community/attacks/xss/',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        ],
    },
    {
        'id': 'command-injection',
        'match': any_of(by_injection_type('command_injection'), by_keyword('command injection', 'os command')),
        'categoria': 'Command Injection',
        'confianza': 'alta',
        'descripcion': (
            'La aplicación construye un comando del sistema operativo incluyendo '
            'entrada del usuario sin neutralizar metacaracteres de shell, '
            'permitiendo ejecutar comandos arbitrarios en el servidor.'
        ),
        'impacto': 'Ejecución de código arbitrario en el servidor con los privilegios del proceso de la aplicación -- compromiso total del host en la mayoría de los casos.',
        'causa_probable': 'Uso de funciones que invocan un shell (ej. os.system, shell=True, exec de PHP) con entrada del usuario concatenada directamente.',
        'pasos': [
            'Localizar la llamada que construye el comando y el parámetro afectado.',
            'Evitar invocar un shell: usar la API de ejecución de procesos con una lista de argumentos (sin shell=True / sin backticks/exec de shell).',
            'Si el comando debe variar, usar una allowlist cerrada de valores permitidos en vez de pasar la entrada del usuario al comando.',
            'Ejecutar el proceso con el mínimo privilegio posible (usuario sin permisos administrativos).',
        ],
        'ejemplo_vulnerable': {
            'lang': 'python', 'tech': 'Python / subprocess',
            'code': 'subprocess.run(f"ping -c 1 {host}", shell=True)',
        },
        'ejemplo_corregido': {
            'lang': 'python', 'tech': 'Python / subprocess',
            'code': 'subprocess.run(["ping", "-c", "1", host], shell=False)  # host validado contra un patrón estricto',
        },
        'prevencion': ['No usar shell=True / exec de shell con entrada de usuario.', 'Allowlist de valores permitidos.', 'Principio de mínimo privilegio del proceso.'],
        'verificacion': 'Reenviar el payload de inyección de comandos y confirmar que no se observa ejecución (sin delay inducido, sin salida del comando inyectado, sin diferencia de tiempo de respuesta).',
        'referencias': ['https://owasp.org/www-community/attacks/Command_Injection'],
    },
    {
        'id': 'path-traversal',
        'match': any_of(by_injection_type('path_traversal'), by_keyword('path traversal', 'directory traversal', '../')),
        'categoria': 'Path Traversal',
        'confianza': 'alta',
        'descripcion': 'La aplicación usa entrada del usuario para construir una ruta de archivo sin neutralizar secuencias "../", permitiendo leer (o en algunos casos escribir) archivos fuera del directorio previsto.',
        'impacto': 'Lectura de archivos sensibles del servidor (código fuente, credenciales, archivos de configuración) o, si también permite escritura, posible ejecución remota de código.',
        'causa_probable': 'Concatenación directa de la entrada del usuario en una ruta de archivo sin canonicalizar ni validar contra un directorio base permitido.',
        'pasos': [
            'Canonicalizar la ruta resultante (ej. realpath()/os.path.realpath()) y verificar que siga dentro del directorio base permitido antes de usarla.',
            'Rechazar cualquier entrada que contenga "../", rutas absolutas o caracteres nulos.',
            'Cuando sea posible, mapear identificadores lógicos (ids) a rutas de archivo en el servidor en vez de aceptar la ruta directamente del cliente.',
        ],
        'ejemplo_vulnerable': {'lang': 'python', 'tech': 'Python', 'code': 'path = os.path.join(BASE_DIR, request.args["file"])\nreturn open(path).read()'},
        'ejemplo_corregido': {'lang': 'python', 'tech': 'Python', 'code': 'target = os.path.realpath(os.path.join(BASE_DIR, request.args["file"]))\nif not target.startswith(os.path.realpath(BASE_DIR) + os.sep):\n    abort(400)\nreturn open(target).read()'},
        'prevencion': ['Validar y canonicalizar toda ruta derivada de entrada de usuario.', 'Usar identificadores indirectos en vez de rutas de archivo cuando sea posible.'],
        'verificacion': 'Reenviar el payload con secuencias de traversal y confirmar que la aplicación lo rechaza o lo normaliza sin exponer contenido fuera del directorio base.',
        'referencias': ['https://owasp.org/www-community/attacks/Path_Traversal'],
    },
    {
        'id': 'ssrf',
        'match': any_of(by_injection_type('ssrf'), by_keyword('ssrf', 'server-side request forgery')),
        'categoria': 'SSRF — Server-Side Request Forgery',
        'confianza': 'alta',
        'descripcion': 'La aplicación realiza una petición HTTP a una URL controlada (total o parcialmente) por el usuario, sin restringir los destinos permitidos.',
        'impacto': 'Acceso a servicios internos no expuestos públicamente (metadatos de nube, paneles de administración internos, bases de datos), y en entornos cloud, posible robo de credenciales del servicio de metadatos.',
        'causa_probable': 'Ausencia de una allowlist de hosts/esquemas permitidos antes de realizar la petición saliente.',
        'pasos': [
            'Definir una allowlist explícita de dominios/IPs permitidos para esta funcionalidad.',
            'Rechazar esquemas distintos de http/https y bloquear rangos de IP privados/loopback/metadatos de nube (169.254.169.254, 127.0.0.0/8, 10.0.0.0/8, etc.).',
            'Resolver el DNS del destino y validar la IP resultante contra la allowlist antes de conectar (para evitar bypass por DNS rebinding).',
        ],
        'ejemplo_vulnerable': {'lang': 'python', 'tech': 'Python / requests', 'code': 'resp = requests.get(request.args["url"])'},
        'ejemplo_corregido': {'lang': 'python', 'tech': 'Python / requests', 'code': 'if not is_allowed_host(request.args["url"]):\n    abort(400)\nresp = requests.get(request.args["url"], timeout=5)'},
        'prevencion': ['Allowlist de destinos permitidos.', 'Bloqueo de rangos de IP internos/metadatos de nube.', 'Timeouts cortos en peticiones salientes server-side.'],
        'verificacion': 'Reintentar con el mismo payload apuntando a un recurso interno de prueba y confirmar que la petición es rechazada.',
        'referencias': ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
    },
    {
        'id': 'xxe',
        'match': any_of(by_injection_type('xxe'), by_keyword('xxe', 'xml external entit')),
        'categoria': 'XXE — XML External Entity',
        'confianza': 'alta',
        'descripcion': 'El parser XML de la aplicación procesa entidades externas definidas por el usuario, permitiendo leer archivos locales o realizar peticiones SSRF a través de la definición de entidades.',
        'impacto': 'Lectura de archivos del servidor, SSRF, y en algunos parsers, denegación de servicio (billion laughs).',
        'causa_probable': 'El parser XML se configura con la resolución de entidades externas y DTD habilitada por defecto.',
        'pasos': [
            'Deshabilitar la resolución de entidades externas y el procesamiento de DTD en el parser XML usado.',
            'Si el formato de entrada puede cambiarse, preferir JSON para APIs que no necesiten XML.',
        ],
        'ejemplo_vulnerable': {'lang': 'java', 'tech': 'Java / DocumentBuilderFactory', 'code': 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n// configuración por defecto: entidades externas habilitadas'},
        'ejemplo_corregido': {'lang': 'java', 'tech': 'Java / DocumentBuilderFactory', 'code': 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\ndbf.setXIncludeAware(false);\ndbf.setExpandEntityReferences(false);'},
        'prevencion': ['Deshabilitar DTD/entidades externas en toda configuración de parser XML del proyecto, no solo en el endpoint afectado.'],
        'verificacion': 'Reenviar un payload XXE de prueba (lectura de archivo no sensible) y confirmar que el parser lo rechaza o lo ignora.',
        'referencias': ['https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'],
    },
    {
        'id': 'ssti',
        'match': any_of(by_injection_type('ssti'), by_keyword('server-side template injection', 'ssti')),
        'categoria': 'SSTI — Server-Side Template Injection',
        'confianza': 'alta',
        'descripcion': 'La aplicación renderiza entrada del usuario como parte de una plantilla, permitiendo ejecutar expresiones del motor de plantillas y, en muchos casos, código arbitrario.',
        'impacto': 'Ejecución remota de código en el servidor en la mayoría de los motores de plantillas afectados.',
        'causa_probable': 'La entrada del usuario se concatena en el string de la plantilla en vez de pasarse como variable/contexto de renderizado.',
        'pasos': [
            'Nunca construir el string de la plantilla con entrada del usuario; pasar la entrada como variable del contexto de renderizado.',
            'Si se necesita permitir plantillas definidas por el usuario, usar un entorno de sandbox restringido del motor de plantillas (ej. sandboxed Jinja2).',
        ],
        'ejemplo_vulnerable': {'lang': 'python', 'tech': 'Python / Jinja2', 'code': 'template = Template(f"Hola {user_name}")\ntemplate.render()'},
        'ejemplo_corregido': {'lang': 'python', 'tech': 'Python / Jinja2', 'code': 'template = Template("Hola {{ user_name }}")\ntemplate.render(user_name=user_name)'},
        'prevencion': ['No construir plantillas con entrada del usuario.', 'Sandboxing del motor de plantillas si es imprescindible.'],
        'verificacion': 'Reenviar una expresión matemática simple (ej. {{7*7}}) y confirmar que se muestra literal, sin evaluarse.',
        'referencias': ['https://owasp.org/www-community/attacks/Server_Side_Template_Injection'],
    },
    {
        'id': 'ldap-injection',
        'match': any_of(by_injection_type('ldap'), by_keyword('ldap injection')),
        'categoria': 'LDAP Injection',
        'confianza': 'alta',
        'descripcion': 'La aplicación construye un filtro LDAP incluyendo entrada del usuario sin escapar los caracteres especiales del filtro, permitiendo alterar la lógica de búsqueda/autenticación.',
        'impacto': 'Bypass de autenticación o acceso a información del directorio fuera del alcance previsto.',
        'causa_probable': 'Ausencia de escape de caracteres especiales de filtro LDAP (*, (, ), \\, NUL) antes de construir el filtro.',
        'pasos': [
            'Escapar los caracteres especiales de LDAP en toda entrada de usuario usada en un filtro, usando la función de escape de la librería LDAP en uso.',
            'Usar bind con credenciales de servicio de mínimo privilegio, nunca con la cuenta del propio usuario autenticándose.',
        ],
        'ejemplo_vulnerable': {'lang': 'python', 'tech': 'Python / ldap3', 'code': 'filtro = f"(uid={usuario})"'},
        'ejemplo_corregido': {'lang': 'python', 'tech': 'Python / ldap3', 'code': 'from ldap3.utils.conv import escape_filter_chars\nfiltro = f"(uid={escape_filter_chars(usuario)})"'},
        'prevencion': ['Escapar siempre la entrada usada en filtros LDAP.'],
        'verificacion': 'Reenviar un payload de bypass de filtro LDAP y confirmar que ya no altera el resultado de la búsqueda/autenticación.',
        'referencias': ['https://owasp.org/www-community/attacks/LDAP_injection'],
    },
    {
        'id': 'nosql-injection',
        'match': any_of(by_injection_type('nosql'), by_keyword('nosql injection', 'mongodb injection')),
        'categoria': 'NoSQL Injection',
        'confianza': 'alta',
        'descripcion': 'La aplicación pasa entrada del usuario directamente como parte de una consulta NoSQL (ej. un objeto de filtro de MongoDB), permitiendo inyectar operadores que alteran la consulta.',
        'impacto': 'Bypass de autenticación o acceso a datos fuera del alcance previsto, de forma análoga a una inyección SQL.',
        'causa_probable': 'La entrada del usuario se usa tal cual como valor de un campo del filtro, permitiendo que el cliente envíe un objeto/operador (ej. {"$ne": null}) en vez de un valor literal.',
        'pasos': [
            'Validar y forzar el tipo esperado de cada campo de entrada (ej. forzar string, rechazar objetos/arrays donde se espera un escalar) antes de construir la consulta.',
            'Usar los operadores de consulta parametrizados que ofrezca el driver/ODM en vez de construir el filtro a mano con datos del cliente.',
        ],
        'ejemplo_vulnerable': {'lang': 'javascript', 'tech': 'Node.js / MongoDB', 'code': 'db.users.findOne({ user: req.body.user, pass: req.body.pass })'},
        'ejemplo_corregido': {'lang': 'javascript', 'tech': 'Node.js / MongoDB', 'code': 'db.users.findOne({ user: String(req.body.user), pass: String(req.body.pass) })'},
        'prevencion': ['Forzar tipos escalares en la entrada antes de usarla en el filtro.', 'Esquema de validación de entrada (ej. JSON Schema) en el borde de la API.'],
        'verificacion': 'Reenviar un payload de operador NoSQL y confirmar que la aplicación lo trata como valor literal o lo rechaza.',
        'referencias': ['https://owasp.org/www-community/attacks/NoSQL_injection'],
    },
    {
        'id': 'missing-security-headers',
        'match': by_keyword('security header', 'missing header', 'x-frame-options', 'strict-transport-security', 'content-security-policy'),
        'categoria': 'Cabeceras de seguridad ausentes',
        'confianza': 'media',
        'descripcion': 'La respuesta HTTP no incluye una o más cabeceras de seguridad recomendadas, reduciendo las protecciones del navegador frente a clickjacking, MIME sniffing o downgrade a HTTP.',
        'impacto': 'Aumenta la superficie de ataque frente a clickjacking, XSS (sin CSP) o degradación a conexión no cifrada, pero no es, por sí sola, una vulnerabilidad explotable directamente.',
        'causa_probable': 'El servidor/aplicación no configura estas cabeceras por defecto ni a través de un middleware de seguridad.',
        'pasos': [
            'Agregar X-Content-Type-Options: nosniff.',
            'Agregar X-Frame-Options: DENY (o frame-ancestors en CSP) si la página no necesita ser embebida en iframes de terceros.',
            'Agregar Strict-Transport-Security con una duración adecuada si el sitio se sirve siempre sobre HTTPS.',
            'Definir una Content-Security-Policy ajustada a los recursos reales que carga la aplicación (evitar empezar con \'unsafe-inline\'/\'unsafe-eval\').',
        ],
        'ejemplo_vulnerable': {'lang': 'http', 'tech': 'Respuesta HTTP', 'code': 'HTTP/1.1 200 OK\nContent-Type: text/html'},
        'ejemplo_corregido': {'lang': 'http', 'tech': 'Respuesta HTTP', 'code': 'HTTP/1.1 200 OK\nContent-Type: text/html\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY\nStrict-Transport-Security: max-age=31536000; includeSubDomains'},
        'prevencion': ['Middleware de seguridad centralizado (ej. helmet.js, flask-talisman) en vez de configurarlas endpoint por endpoint.'],
        'verificacion': 'Repetir la petición HTTP y confirmar la presencia de las cabeceras en la respuesta.',
        'referencias': ['https://owasp.org/www-project-secure-headers/'],
    },
    {
        'id': 'exposed-sensitive-path',
        'match': all_of(any_of(by_tool('gobuster', 'ffuf')), by_keyword('admin', 'backup', '.git', '.env', 'config', 'debug')),
        'categoria': 'Ruta o recurso sensible expuesto',
        'confianza': 'media',
        'descripcion': 'El descubrimiento de contenido encontró una ruta que típicamente expone funcionalidad administrativa, archivos de configuración o backups, y que respondió con un código HTTP que sugiere que es accesible.',
        'impacto': 'Divulgación de información sensible (credenciales, estructura interna) o acceso no autorizado a funcionalidad administrativa, según qué exponga la ruta en concreto.',
        'causa_probable': 'La ruta no está protegida por control de acceso, o un archivo que no debería desplegarse en producción (backup, .git, .env) quedó accesible públicamente.',
        'pasos': [
            'Confirmar manualmente qué devuelve la ruta y si contiene información sensible.',
            'Si es funcionalidad administrativa legítima: restringir el acceso por autenticación/autorización y, si es posible, por red (VPN/allowlist de IP).',
            'Si es un archivo que no debería estar desplegado (backup, .git, .env): eliminarlo del directorio servido y revisar el proceso de despliegue para que no vuelva a ocurrir.',
        ],
        'ejemplo_vulnerable': None,
        'ejemplo_corregido': None,
        'prevencion': ['Excluir archivos de configuración/backup/VCS del directorio servido en el pipeline de build.', 'Control de acceso explícito en toda ruta administrativa.'],
        'verificacion': 'Repetir la petición a la ruta y confirmar que ahora requiere autenticación o ya no está accesible.',
        'referencias': ['https://owasp.org/www-project-web-security-testing-guide/'],
    },
    {
        'id': 'known-vulnerable-component',
        'match': all_of(lambda f: bool(f.get('cve')), any_of(by_tool('nuclei', 'zap'))),
        'categoria': 'Componente con vulnerabilidad conocida (CVE)',
        'confianza': 'media',
        'descripcion': (
            'La herramienta identificó, por versión/fingerprint, un componente o '
            'servicio que coincide con una vulnerabilidad conocida públicamente. '
            'Esto es un INDICIO basado en versión reportada, no una explotación confirmada.'
        ),
        'impacto': 'Depende del CVE específico -- consultar la referencia oficial para el impacto exacto y el vector de ataque.',
        'causa_probable': 'Versión desactualizada del componente/servicio detectado.',
        'pasos': [
            'Confirmar la versión real instalada (la detección por fingerprint puede equivocarse) antes de planificar la corrección.',
            'Actualizar el componente a una versión que no esté afectada por el CVE reportado, siguiendo el changelog del proveedor.',
            'Si no es posible actualizar de inmediato, revisar si el proveedor publicó una mitigación temporal (workaround) para el CVE.',
        ],
        'ejemplo_vulnerable': None,
        'ejemplo_corregido': None,
        'prevencion': ['Gestión de dependencias con alertas automáticas de CVEs (ej. Dependabot, Trivy en CI).', 'Ventanas de actualización regulares, no solo reactivas a un hallazgo.'],
        'verificacion': 'Repetir el fingerprint/detección de versión tras la actualización y confirmar que ya no coincide con el rango de versiones afectado por el CVE.',
        'referencias': [],  # se completa dinámicamente con el CVE del propio finding
    },
]

_GENERIC_FALLBACK = {
    'id': 'generic-manual-review',
    'categoria': None,  # se completa con el título real del finding
    'confianza': 'requiere_revision_manual',
    'descripcion': None,  # se usa la descripción/evidencia que ya trae el propio finding
    'impacto': None,
    'causa_probable': None,
    'pasos': [],
    'ejemplo_vulnerable': None,
    'ejemplo_corregido': None,
    'prevencion': [],
    'verificacion': (
        'No hay un procedimiento de verificación automática definido para esta '
        'categoría todavía -- requiere revisión manual por un analista.'
    ),
    'referencias': [],
}


def _pick_rule(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for rule in RULES:
        try:
            if rule['match'](finding):
                return rule
        except Exception:
            continue
    return None


def build_remediation(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye la guía de remediación de un Finding normalizado (ver
    findings.normalize_findings()). Siempre devuelve una estructura con las
    mismas claves; cuando no hay regla aplicable, 'confianza' es
    'requiere_revision_manual' y los campos específicos quedan vacíos en vez
    de rellenarse con una suposición no verificada.
    """
    rule = _pick_rule(finding)

    if rule is None:
        guia = dict(_GENERIC_FALLBACK)
        guia['categoria']      = finding.get('title') or 'Hallazgo sin categorizar'
        guia['descripcion']    = finding.get('evidence') or 'Sin descripción adicional disponible en el hallazgo original.'
        guia['referencias']    = []
        return guia

    guia = {
        'id':               rule['id'],
        'categoria':        rule['categoria'],
        'confianza':        rule['confianza'],
        'descripcion':      rule['descripcion'],
        'impacto':          rule['impacto'],
        'causa_probable':   rule['causa_probable'],
        'pasos':            list(rule['pasos']),
        'ejemplo_vulnerable': rule['ejemplo_vulnerable'],
        'ejemplo_corregido':  rule['ejemplo_corregido'],
        'prevencion':       list(rule['prevencion']),
        'verificacion':     rule['verificacion'],
        'referencias':      list(rule['referencias']),
    }

    # El CVE propio del finding (si lo trae) siempre se agrega a las
    # referencias, sin inventar un identificador si no vino de la herramienta.
    cve = finding.get('cve')
    if cve:
        nvd_url = f'https://nvd.nist.gov/vuln/detail/{cve}'
        if nvd_url not in guia['referencias']:
            guia['referencias'].append(nvd_url)

    return guia


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Agrega 'remediation' a cada Finding de la lista (no muta el original)."""
    out = []
    for f in findings:
        enriched = dict(f)
        enriched['remediation'] = build_remediation(f)
        out.append(enriched)
    return out
