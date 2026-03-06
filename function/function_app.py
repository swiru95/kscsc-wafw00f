import azure.functions as func
import json, logging, os, ipaddress, socket, ssl
from urllib.parse import urlparse
import requests
from wafw00f.main import WAFW00F

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# TLS version scoring (higher = better)
TLS_VERSION_SCORES = {
    'TLSv1.3': 100,
    'TLSv1.2': 80,
    'TLSv1.1': 30,
    'TLSv1': 20,
    'SSLv3': 0,
    'SSLv2': 0,
}

# Weak cipher patterns to penalize
WEAK_CIPHER_PATTERNS = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon', '3DES']

# Strong cipher suites (AEAD ciphers)
STRONG_CIPHER_PATTERNS = ['GCM', 'CHACHA20', 'POLY1305', 'CCM']

# ASVS / best-practice security headers
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'required': True,
        'description': 'HSTS - Forces HTTPS connections',
        'check': '_check_hsts',
    },
    'Content-Security-Policy': {
        'required': True,
        'description': 'CSP - Mitigates XSS and injection attacks',
        'check': '_check_csp',
    },
    'X-Content-Type-Options': {
        'required': True,
        'description': 'Prevents MIME-type sniffing',
        'expected': 'nosniff',
    },
    'X-Frame-Options': {
        'required': True,
        'description': 'Clickjacking protection',
        'expected_any': ['DENY', 'SAMEORIGIN'],
    },
    'Referrer-Policy': {
        'required': True,
        'description': 'Controls referrer information leakage',
        'expected_any': ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin',
                         'strict-origin-when-cross-origin', 'same-origin'],
    },
    'Permissions-Policy': {
        'required': True,
        'description': 'Controls browser feature access',
        'check': '_check_permissions_policy',
    },
    'Cross-Origin-Opener-Policy': {
        'required': False,
        'description': 'Isolates browsing context',
        'expected_any': ['same-origin', 'same-origin-allow-popups'],
    },
    'Cross-Origin-Resource-Policy': {
        'required': False,
        'description': 'Controls cross-origin resource loading',
        'expected_any': ['same-origin', 'same-site', 'cross-origin'],
    },
    'X-Permitted-Cross-Domain-Policies': {
        'required': False,
        'description': 'Controls Adobe cross-domain policy',
        'expected_any': ['none', 'master-only'],
    },
    'Cache-Control': {
        'required': False,
        'description': 'Prevents caching of sensitive data',
        'check': '_check_cache_control',
    },
}

# Headers that should NOT be present (information leakage)
HEADERS_TO_REMOVE = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']


def is_private_url(url: str) -> bool:
    hostname = urlparse(url).hostname
    if not hostname:
        return True
    try:
        addr = ipaddress.ip_address(socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)[0][4][0])
    except (socket.gaierror, ValueError):
        return True
    return any(addr in net for net in BLOCKED_NETWORKS)


# ── TLS validation ──────────────────────────────────────────

def check_tls(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    if parsed.scheme != 'https':
        return {
            'version': None,
            'cipher': None,
            'key_bits': None,
            'score': 'F',
            'grade': 'F',
            'issues': ['Site does not use HTTPS'],
        }

    result = {
        'version': None,
        'cipher': None,
        'key_bits': None,
        'score': 0,
        'grade': 'F',
        'issues': [],
    }

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=10),
                             server_hostname=hostname) as sock:
            result['version'] = sock.version()
            cipher_info = sock.cipher()
            if cipher_info:
                result['cipher'] = cipher_info[0]
                result['key_bits'] = cipher_info[2]
    except ssl.SSLCertVerificationError:
        result['issues'].append('Certificate verification failed')
    except (ssl.SSLError, OSError) as e:
        result['issues'].append(f'TLS connection error: {str(e)[:100]}')
        return _finalize_tls_score(result)

    # Score TLS version
    version_score = TLS_VERSION_SCORES.get(result['version'], 0)
    if version_score <= 30:
        result['issues'].append(f"Deprecated TLS version: {result['version']}")

    # Score cipher suite
    cipher_name = (result['cipher'] or '').upper()
    cipher_score = 70  # baseline

    if any(weak in cipher_name for weak in WEAK_CIPHER_PATTERNS):
        cipher_score = 20
        result['issues'].append(f"Weak cipher suite: {result['cipher']}")
    elif any(strong in cipher_name for strong in STRONG_CIPHER_PATTERNS):
        cipher_score = 100

    # Score key length
    key_bits = result['key_bits'] or 0
    if key_bits >= 256:
        key_score = 100
    elif key_bits >= 128:
        key_score = 80
    else:
        key_score = 30
        result['issues'].append(f"Weak key length: {key_bits} bits")

    # Weighted average: version 40%, cipher 35%, key 25%
    result['score'] = round(version_score * 0.40 + cipher_score * 0.35 + key_score * 0.25)

    return _finalize_tls_score(result)


def _finalize_tls_score(result: dict) -> dict:
    score = result['score']
    if score >= 90:
        result['grade'] = 'A'
    elif score >= 80:
        result['grade'] = 'B'
    elif score >= 65:
        result['grade'] = 'C'
    elif score >= 50:
        result['grade'] = 'D'
    else:
        result['grade'] = 'F'
    return result


# ── Security header validation (OWASP ASVS) ────────────────

def _check_hsts(value: str) -> tuple[bool, list[str]]:
    issues = []
    v = value.lower()
    if 'max-age=' not in v:
        return False, ['HSTS missing max-age directive']
    try:
        max_age = int(v.split('max-age=')[1].split(';')[0].strip())
        if max_age < 31536000:
            issues.append(f'HSTS max-age too low ({max_age}s), recommend >= 31536000 (1 year)')
    except (ValueError, IndexError):
        issues.append('HSTS max-age is not a valid integer')
    if 'includesubdomains' not in v:
        issues.append('HSTS missing includeSubDomains directive')
    if 'preload' not in v:
        issues.append('HSTS missing preload directive (recommended)')
    return len(issues) == 0, issues


def _check_csp(value: str) -> tuple[bool, list[str]]:
    issues = []
    v = value.lower()
    if "'unsafe-inline'" in v:
        issues.append("CSP contains 'unsafe-inline' — weakens XSS protection")
    if "'unsafe-eval'" in v:
        issues.append("CSP contains 'unsafe-eval' — allows dynamic code execution")
    if 'default-src' not in v and 'script-src' not in v:
        issues.append("CSP missing default-src or script-src directive")
    if '*' in v.split():
        issues.append("CSP uses wildcard (*) source — overly permissive")
    return len(issues) == 0, issues


def _check_permissions_policy(value: str) -> tuple[bool, list[str]]:
    issues = []
    recommended = ['camera', 'microphone', 'geolocation']
    v = value.lower()
    for feature in recommended:
        if feature not in v:
            issues.append(f"Permissions-Policy does not restrict '{feature}'")
    return len(issues) == 0, issues


def _check_cache_control(value: str) -> tuple[bool, list[str]]:
    issues = []
    v = value.lower()
    good_directives = ['no-store', 'no-cache', 'private']
    if not any(d in v for d in good_directives):
        issues.append('Cache-Control does not prevent caching of sensitive data')
    return len(issues) == 0, issues


HEADER_CHECK_FUNCTIONS = {
    '_check_hsts': _check_hsts,
    '_check_csp': _check_csp,
    '_check_permissions_policy': _check_permissions_policy,
    '_check_cache_control': _check_cache_control,
}


def check_security_headers(url: str) -> dict:
    result = {
        'score': 0,
        'grade': 'F',
        'headers': {},
        'issues': [],
        'info_leakage': [],
    }

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=True)
        headers = resp.headers
    except requests.RequestException as e:
        result['issues'].append(f'Could not fetch headers: {str(e)[:100]}')
        return result

    total_checks = 0
    passed_checks = 0

    for header_name, config in SECURITY_HEADERS.items():
        total_checks += 1
        value = headers.get(header_name)
        entry = {
            'present': value is not None,
            'value': value,
            'description': config['description'],
            'status': 'missing',
            'issues': [],
        }

        if value is None:
            if config['required']:
                entry['issues'].append(f'Missing required header: {header_name}')
                result['issues'].append(f'Missing required header: {header_name}')
            else:
                entry['status'] = 'optional-missing'
                passed_checks += 0.5  # partial credit for optional
        else:
            # Custom check function
            if 'check' in config:
                check_fn = HEADER_CHECK_FUNCTIONS[config['check']]
                ok, issues = check_fn(value)
                entry['issues'] = issues
                if ok:
                    entry['status'] = 'pass'
                    passed_checks += 1
                else:
                    entry['status'] = 'warn'
                    passed_checks += 0.5
                    result['issues'].extend(issues)
            # Expected exact value
            elif 'expected' in config:
                if value.lower() == config['expected'].lower():
                    entry['status'] = 'pass'
                    passed_checks += 1
                else:
                    entry['status'] = 'warn'
                    entry['issues'].append(f"Expected '{config['expected']}', got '{value}'")
                    passed_checks += 0.5
            # Expected one of several values
            elif 'expected_any' in config:
                if value.lower() in [v.lower() for v in config['expected_any']]:
                    entry['status'] = 'pass'
                    passed_checks += 1
                else:
                    entry['status'] = 'warn'
                    entry['issues'].append(f"Unexpected value '{value}'")
                    passed_checks += 0.5

        result['headers'][header_name] = entry

    # Check for info-leaking headers
    for leak_header in HEADERS_TO_REMOVE:
        val = headers.get(leak_header)
        if val:
            result['info_leakage'].append({
                'header': leak_header,
                'value': val,
                'recommendation': f'Remove {leak_header} header to reduce information leakage',
            })
            result['issues'].append(f'Information leakage: {leak_header} header is present')

    # Calculate score
    if total_checks > 0:
        raw_score = (passed_checks / total_checks) * 100
        # Penalize for info leakage headers
        raw_score -= len(result['info_leakage']) * 5
        result['score'] = max(0, round(raw_score))

    score = result['score']
    if score >= 90:
        result['grade'] = 'A'
    elif score >= 75:
        result['grade'] = 'B'
    elif score >= 60:
        result['grade'] = 'C'
    elif score >= 40:
        result['grade'] = 'D'
    else:
        result['grade'] = 'F'

    return result


# ── Routes ──────────────────────────────────────────────────

@app.route(
    route="health",
    methods=["GET"],
    auth_level=func.AuthLevel.FUNCTION
)
def health(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(
        "OK",
        status_code=200
    )

@app.route(
    route="openapi",
    methods=["GET"],
    auth_level=func.AuthLevel.FUNCTION
)
def get_api_spec(req: func.HttpRequest) -> func.HttpResponse:
    current_dir = os.path.dirname(os.path.realpath(__file__))
    spec_path = os.path.join(current_dir, 'api_spec.yaml')
    
    with open(spec_path, 'r') as f:
        content = f.read()
        
    return func.HttpResponse(
        content,
        mimetype="application/yaml",
        status_code=200
    )

@app.route(
    route="trigger_waf_woof",
    methods=["POST"],
    auth_level=func.AuthLevel.FUNCTION
)
def trigger_waf_woof(req: func.HttpRequest) -> func.HttpResponse:
    try:
        data = json.loads(req.get_body().decode())
        url = data.get('target', '').strip()

        if len(url) > 2048:
            return func.HttpResponse("Bad Request - URL too long", status_code=400)
        if not url or not url.startswith(('http://', 'https://')):
            return func.HttpResponse("Bad Request - Invalid URL format", status_code=400)
        if is_private_url(url):
            return func.HttpResponse("Bad Request - Internal URLs are not allowed", status_code=400)

        result = {'target': url, 'status': 'protected', 'solution': 'none'}
        attacker = WAFW00F(result['target'], debuglevel=40)

        if attacker.rq is None:
            result['status'] = 'down'
            result['tls'] = check_tls(url)
            return func.HttpResponse(json.dumps(result), status_code=200, mimetype="application/json")

        waf = attacker.identwaf(findall=True)
        if len(waf) > 0:
            result['solution'] = waf[0]
        elif attacker.genericdetect():
            result['solution'] = 'generic'
        else:
            result['status'] = 'unknown'

        result['tls'] = check_tls(url)
        result['security_headers'] = check_security_headers(url)

        return func.HttpResponse(json.dumps(result), status_code=200, mimetype="application/json")

    except (json.JSONDecodeError, KeyError, ValueError):
        return func.HttpResponse("Bad Request", status_code=400)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return func.HttpResponse("Internal Server Error", status_code=500)