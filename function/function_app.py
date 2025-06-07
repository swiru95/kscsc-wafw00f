import azure.functions as func
import json, os
from wafw00f.main import WAFW00F
from bleach import clean

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(
    route="test",
    methods=["GET"],
    auth_level=func.AuthLevel.FUNCTION
)
def get_api_spec(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(
        "OK",
        status_code=200
    )

@app.route(
    route="trigger_waf_woof",
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
        url = clean(url)
        if not url or not url.startswith(('http://', 'https://')):
            return func.HttpResponse("Bad Request - Invalid URL format", status_code=400)
        if len(url) > 2048:
            return func.HttpResponse("Bad Request - URL too long", status_code=400)

        target = {'target': url, 'status': 'protected', 'solution': 'none'}
        attacker = WAFW00F(target['target'], debuglevel=40)

        if attacker.rq is None:
            target['status'] = 'down'

        waf = attacker.identwaf(findall=True)
        if len(waf) > 0:
            target['solution'] = waf[0]
        elif attacker.genericdetect():
            target['solution'] = 'generic'
        else:
            target['status'] = 'unknown'

        return func.HttpResponse(json.dumps(target), status_code=200, mimetype="application/json")

    except (json.JSONDecodeError, KeyError, Exception) as e:
        return func.HttpResponse("Bad Request", status_code=400)