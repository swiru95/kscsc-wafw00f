import azure.functions as func
import json, logging, os, ipaddress, socket
from urllib.parse import urlparse
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

def is_private_url(url: str) -> bool:
    hostname = urlparse(url).hostname
    if not hostname:
        return True
    try:
        addr = ipaddress.ip_address(socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)[0][4][0])
    except (socket.gaierror, ValueError):
        return True
    return any(addr in net for net in BLOCKED_NETWORKS)

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

        target = {'target': url, 'status': 'protected', 'solution': 'none'}
        attacker = WAFW00F(target['target'], debuglevel=40)

        if attacker.rq is None:
            target['status'] = 'down'
            return func.HttpResponse(json.dumps(target), status_code=200, mimetype="application/json")

        waf = attacker.identwaf(findall=True)
        if len(waf) > 0:
            target['solution'] = waf[0]
        elif attacker.genericdetect():
            target['solution'] = 'generic'
        else:
            target['status'] = 'unknown'

        return func.HttpResponse(json.dumps(target), status_code=200, mimetype="application/json")

    except (json.JSONDecodeError, KeyError, ValueError):
        return func.HttpResponse("Bad Request", status_code=400)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return func.HttpResponse("Internal Server Error", status_code=500)