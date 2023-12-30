import azure.functions as func
import logging, json
from wafw00f.main import WAFW00F

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="trigger_waf_woof")
def trigger_waf_woof(req: func.HttpRequest) -> func.HttpResponse:
    
    #Check if POST
    if req.method!="POST":
        print(f"{req.method} is not valid.")
        return func.HttpResponse(f"Not Found", status_code=404)
    try:
        #Check target param
        url=json.loads(req.get_body().decode())['target']
        if(not url or not url.startswith('http')):
            return func.HttpResponse(f"Bad Request",status_code=400)
    except:
        return func.HttpResponse(f"Bad Request",status_code=400)
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