import azure.functions as func
import json
from wafw00f.main import WAFW00F
from bleach import clean
import os
import yaml

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

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
        #Check target param
        url=json.loads(req.get_body().decode())['target']
        url=clean(url)
        if(not url or not url.startswith(('http://', 'https://'))):
            return func.HttpResponse(f"Bad Request - Invalid URL format",status_code=400)
        
        # Dodać limit długości URL
        if len(url) > 2048:  # standardowy limit długości URL
            return func.HttpResponse(f"Bad Request - URL too long",status_code=400)
    
        #create target JSON
        target={'target':url,'status':'protected','solution':'none'}
    
        attacker = WAFW00F(target['target'],debuglevel=40)
    
        #Target ONLINE?
        if attacker.rq is None:
            target['status']='down'
        
        waf=attacker.identwaf(findall=True)
        if len(waf) > 0:
            target['solution']=waf[0]
        elif (attacker.genericdetect()):
            target['solution']='generic'        
        else:
            target['status']='unknown'
         
        return func.HttpResponse(json.dumps(target),status_code=200)
    
    except:
        return func.HttpResponse(f"Bad Request",status_code=400)