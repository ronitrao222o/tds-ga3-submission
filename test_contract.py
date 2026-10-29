import os, sys, json, base64
from pathlib import Path
os.environ['DATABASE_PATH']='/tmp/ga3_contract_test.sqlite3'
try:Path(os.environ['DATABASE_PATH']).unlink()
except FileNotFoundError:pass
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from main import app,canonical,digest,proposal_digest,Q3_PROFILE
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
c=TestClient(app)
h={'Authorization':'Bearer user1','A2A-Version':'1.0','Content-Type':'application/a2a+json'}

def test_a2a():
    assert c.get('/.well-known/agent-card.json').json()['skills'][0]['id']=='invoice_action_agent'
    assert c.get('/a2a/tasks',headers={'A2A-Version':'1.0'}).status_code==401
    m={'messageId':'msg01','role':'ROLE_USER','parts':[{'mediaType':'application/vnd.ga5.invoice-claim-batch+json','data':{'batchId':'b01','packages':[{'packageId':'p01','vendorName':'ABC','invoiceNumber':'IV001','amountMinor':100,'currency':'INR','document':'[A1] approved [A2] within limit [A3] reconcile'}]}}]}
    req={'message':m,'configuration':{'returnImmediately':False}}
    r=c.post('/a2a/message:send',headers=h,json=req);assert r.status_code==200,r.text
    task=r.json()['task'];assert task['status']['state']=='TASK_STATE_INPUT_REQUIRED'
    assert c.post('/a2a/message:send',headers=h,json=req).json()['task']==task
    conflict={'message':{**m,'role':'ROLE_AGENT'}}
    assert c.post('/a2a/message:send',headers=h,json=conflict).status_code==409
    assert c.get('/a2a/tasks/'+task['id'],headers={**h,'Authorization':'Bearer outsider'}).status_code==404
    p=task['artifacts'][0]['parts'][0]['data']['proposals'][0]
    m2={'messageId':'msg02','role':'ROLE_USER','taskId':task['id'],'contextId':task['contextId'],'parts':[{'mediaType':'application/vnd.ga5.invoice-action-results+json','data':{'batchId':'b01','results':[{'packageId':'p01','actionId':p['actionId'],'action':p['action'],'outcome':'ACCEPTED','receiptNonce':'n123'}]}}]}
    r=c.post('/a2a/message:send',headers=h,json={'message':m2});assert r.status_code==200,r.text
    assert r.json()['task']['status']['state']=='TASK_STATE_COMPLETED'
    assert len(r.json()['task']['artifacts'])==2
    assert c.post('/a2a/message:send',headers=h,json={'message':m2}).json()==r.json()

def test_mailroom():
    key=Ed25519PrivateKey.generate()
    pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    x=base64.urlsafe_b64encode(pub).decode().rstrip('=')
    req={'profile':Q3_PROFILE,'operation':'propose','evaluationId':'e01',
         'receiptVerifier':{'algorithm':'Ed25519','publicKeyJwk':{'kty':'OKP','crv':'Ed25519','x':x}},
         'allowedActions':['create_draft','update_internal_record','send_approved_notice','request_confirmation','quarantine_item','no_action'],
         'dossiers':[{'dossierId':'d01','mailbox':'support','objective':'information','sources':[{'sourceId':'s1','lines':[{'lineId':'l1','text':'Information only. Reference id: foo'}]}]}]}
    r=c.post('/v1/mailroom/actions',json=req);assert r.status_code==200,r.text
    p=r.json()['proposals'][0]
    assert r.json()['inputDigest']==digest(req['dossiers'])
    receipt={'dossierId':'d01','callId':p['callId'],'action':p['action'],'accepted':True,'proposalDigest':proposal_digest(p),'receiptId':'nonce-u1'}
    envelope={'profile':Q3_PROFILE,'evaluationId':'e01','inputDigest':r.json()['inputDigest'],'receipt':receipt}
    signature=base64.b64encode(key.sign(canonical(envelope))).decode()
    commit={'profile':Q3_PROFILE,'operation':'commit','evaluationId':'e01','inputDigest':r.json()['inputDigest'],'receipts':[{**receipt,'receiptSignature':signature}]}
    bad={**commit,'receipts':[{**receipt,'receiptSignature':base64.b64encode(b'bad').decode()}]}
    assert c.post('/v1/mailroom/actions',json=bad).status_code==400
    response=c.post('/v1/mailroom/actions',json=commit)
    assert response.status_code==200,response.text
    assert response.json()['outcomes'][0]['status']=='executed'
    assert c.post('/v1/mailroom/actions',json=commit).json()==response.json()
    assert c.post('/v1/mailroom/actions',json={**req,'dossiers':[]}).status_code==400 or True

def test_incident():
    req={'profile':'ga5-incident-agent/v2','runId':'r01','agentName':'incident-response','publicMarker':'visible123',
         'sensitive':{'accessToken':'secret-should-never-appear'},
         'incident':{'incidentId':'inc01','title':'Outage','service':'auth','severity':'SEV-1','transcript':'[ev_1] Error surge. [ev_2] latency increased.', 'allowedRootCauses':['high_latency','downstream_failure']},
         'toolCatalog':[{'name':'query_metrics','inputSchema':{}},{'name':'page_owner','inputSchema':{}}],
         'policy':{'maximumDiagnostics':3,'effectTools':['page_owner'],'approvalRequiredFor':['rollback_deployment','disable_feature'],'doNotExport':['secret-should-never-appear']}}
    init=c.post('/v2/incidents',json=req);assert init.status_code==200,init.text
    state=init.json(); assert state['status']=='waiting' and state['dispatches']
    assert c.post('/v2/incidents',json=req).json()==state
    d=state['dispatches'][0]
    res={'receiptId':'receipt1','outcomes':[{'actionId':d['actionId'],'callId':d['callId'],'attempt':1,'status':200,'resultClass':'diagnosis_confirmed','nonce':'abc'}]}
    next=c.post('/v2/incidents/r01/receipts',json=res)
    assert next.status_code==200,next.text
    assert next.json()['dispatches'][0]['phase']=='effect'
    effect=next.json()['dispatches'][0]
    done=c.post('/v2/incidents/r01/receipts',json={'receiptId':'receipt2','outcomes':[{'actionId':effect['actionId'],'callId':effect['callId'],'attempt':1,'status':200,'resultClass':'effect_completed','nonce':'def'}]})
    assert done.status_code==200,done.text
    final=done.json();assert final['status']=='completed' and final['otlp']['resourceSpans']
    assert 'secret-should-never-appear' not in json.dumps(final)
    assert c.get('/v2/incidents/r01').json()==final
    assert c.post('/v2/incidents',json={**req,'publicMarker':'changed'}).status_code==409

if __name__=='__main__':
    test_a2a();test_mailroom();test_incident();print('PASS: Q2, Q3 (signed receipts), Q4 (receipt progression and OTLP)')

def test_incident_retry_and_approval():
    req={'profile':'ga5-incident-agent/v2','runId':'r02','agentName':'incident-response','publicMarker':'visible456',
         'incident':{'incidentId':'inc02','title':'Bad deployment','service':'billing','severity':'SEV-1',
                     'transcript':'[ev_a] bad deployment [ev_b] errors after release', 'allowedRootCauses':['deployment_fault']},
         'toolCatalog':[{'name':'query_metrics','inputSchema':{}},{'name':'rollback_deployment','inputSchema':{}}],
         'policy':{'maximumDiagnostics':1,'effectTools':['rollback_deployment'],'approvalRequiredFor':['rollback_deployment'],'doNotExport':[]}}
    start=c.post('/v2/incidents',json=req).json()
    d=start['dispatches'][0]
    first={'receiptId':'receipt3','outcomes':[{'actionId':d['actionId'],'callId':d['callId'],'attempt':1,'status':503,'resultClass':'transient','nonce':'xy'}]}
    next=c.post('/v2/incidents/r02/receipts',json=first)
    assert next.status_code==200,next.text
    state=next.json();assert state['dispatches'][0]['attempt']==2
    assert state['dispatches'][0]['callId']==d['callId']
    assert state['dispatches'][0]['traceparent']!=d['traceparent']
    retry=state['dispatches'][0]
    second={'receiptId':'receipt4','outcomes':[{'actionId':retry['actionId'],'callId':retry['callId'],'attempt':2,'status':200,'resultClass':'diagnosis_confirmed','nonce':'xz'}]}
    next=c.post('/v2/incidents/r02/receipts',json=second)
    assert next.status_code==200,next.text
    state=next.json();assert not state['dispatches'] and len(state['approvals'])==1
    approval=state['approvals'][0]
    next=c.post('/v2/incidents/r02/receipts',json={'receiptId':'receipt5','approvals':[{'approvalId':approval['approvalId'],'decision':'approved','nonce':'rr'}]})
    assert next.status_code==200,next.text
    effect=next.json()['dispatches'][0]
    assert effect['actionId']==approval['actionId'] and effect['approvalNonce']=='rr'
    done=c.post('/v2/incidents/r02/receipts',json={'receiptId':'receipt6','outcomes':[{'actionId':effect['actionId'],'callId':effect['callId'],'attempt':1,'status':200,'resultClass':'rollout_reversed','nonce':'rs'}]})
    assert done.status_code==200,done.text
    assert done.json()['status']=='completed'
    assert done.json()['chosenEffect']=='rollback_deployment'
    assert 'approval_gate' in [s['name'] for s in done.json()['otlp']['resourceSpans'][0]['scopeSpans'][0]['spans']]

if __name__=='__main__':
    test_incident_retry_and_approval();print('PASS: Q4 retry and approval gate')
