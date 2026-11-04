"""Run inside the isolated backend container; uses its temporary MariaDB only."""
import os, json, uuid, hmac, hashlib, subprocess, time
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import urlencode
from http.cookies import SimpleCookie
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import get_connection

assert os.environ.get('OJ_INTEGRATION_TEST') == '1', 'Requires explicit isolated integration environment'
assert os.environ.get('MARIADB_HOST') == 'db', 'Never run against the host database'

results=[]
def check(name, condition, detail=''):
    results.append((name, bool(condition), str(detail)))
    print(('PASS ' if condition else 'FAIL ')+name+(' '+str(detail) if detail else ''), flush=True)
class Client:
    def __init__(self, fp=None, base='http://nginx/api', ip=None):
        # ip: act as an exam seat behind the trusted proxy (only honored on direct backend listeners).
        self.cookies={}; self.fp=fp or uuid.uuid4().hex; self.base=base; self.ip=ip
    def call(self,path,data=None,headers=None):
        hdr={'X-Client-Fingerprint':self.fp,'User-Agent':'OJ-integration','Cookie':'; '.join(k+'='+v for k,v in self.cookies.items())}
        if self.ip: hdr['X-Real-IP']=self.ip
        hdr.update(headers or {})
        req=Request(self.base+path, data=None if data is None else urlencode(data).encode(), headers=hdr)
        try: r=urlopen(req, timeout=90)
        except HTTPError as e: r=e
        for value in r.headers.get_all('Set-Cookie',[]):
            c=SimpleCookie(); c.load(value)
            self.cookies.update({k:v.value for k,v in c.items()})
        raw=r.read().decode()
        try: body=json.loads(raw)
        except ValueError: body=raw
        return r.status,body,r.headers

def register(c,headers=None):
    u='it_'+uuid.uuid4().hex[:14]
    status,b,h=c.call('/register',{'username':u,'password':'integration-password'},headers)
    assert status==200,(status,b)
    return u,b['user']['id'],h

def login(c,u,headers=None):
    return c.call('/login',{'username':u,'password':'integration-password'},headers)

def scalar(sql,args=()):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql,args); return next(iter(cur.fetchone().values()))

code='#include <stdio.h>\nint main(){long a,b;if(scanf("%ld%ld",&a,&b)==2)printf("%ld",a+b);return 0;}'
submit={'language':'c','problem_id':'1002','code':code}
a=Client()
for _ in range(120):
    try:
        if a.call('/problems')[0]==200: break
    except OSError: pass
    time.sleep(.25)
check('Nginx /api/problems',a.call('/problems')[0]==200)
u,uid,headers=register(a)
raw=a.cookies['oj_device']; ident,sig=raw.split('.')
check('registration signed cookie and HTTP cookie mode',len(sig)==64 and hmac.compare_digest(sig,hmac.new(os.environ['DEVICE_SECRET'].encode(),ident.encode(),hashlib.sha256).hexdigest()) and all('Secure' not in v for v in headers.get_all('Set-Cookie')))
s,b,_=login(a,u); check('first login',s==200 and b['login_alert'] is None)
s,b,_=login(a,u); check('repeat login preserves identity and avoids alerts',s==200 and b['login_alert'] is None and a.cookies['oj_device']==raw)
s,b,_=a.call('/submit',submit); check('C submission through Docker sandbox',s==200 and b.get('status')=='AC',b)
s,b,_=a.call('/submissions',{}); check('submission persisted in MariaDB',s==200 and len(b)==1)
s,b,h=a.call('/submit',submit); check('submission rate limit',s==429 and h.get('Retry-After') is not None)
other=Client(); _,b,_=login(other,u); check('second device raises alert',b.get('login_alert') is not None)
s,b,_=other.call('/submit',submit); check('second device cannot submit',s==403)
time.sleep(5)
s,b,_=a.call('/submit',dict(submit,problem_id='1001')); check('first device remains allowed',s==200,b)
s,b,_=login(other,u); check('second device alert persists after relogin',s==200 and b.get('login_alert') is not None)
s,b,h=a.call('/session'); check('session restore preserves first user without alert',s==200 and b['user']['id']==uid and b['login_alerts']==[] and h.get('Cache-Control')=='no-store')
s,b,_=other.call('/session'); check('session restore preserves second device warning',s==200 and bool(b['login_alerts']))
s,b,_=a.call('/login-alerts',{}); check('first device alert endpoint excludes other device warnings',s==200 and b==[])
s,b,_=Client().call('/session'); check('anonymous session restore',s==200 and b['user'] is None)
c=Client(); u2,_,_=register(c)
s,b,_=login(a,u2); check('same device cannot login to second account',s==403)
# H1: registration signs in, so it obeys the same device rule and leaves a login event.
taken='it_'+uuid.uuid4().hex[:14]
s,b,_=a.call('/register',{'username':taken,'password':'integration-password'})
check('same device cannot register a second account',s==403 and scalar('SELECT COUNT(*) FROM users WHERE username=%s',(taken,))==0,(s,b))
shooter=Client(); su,sid,_=register(shooter)
check('registration records a login event',scalar('SELECT COUNT(*) FROM login_events WHERE user_id=%s',(sid,))==1)
seat=Client(); s,b,_=login(seat,su)
check('login elsewhere after registration raises alert',s==200 and b.get('login_alert') is not None,b)
s,b,_=seat.call('/submit',submit); check('registration-alerted device cannot submit',s==403,(s,b))
# H2: a session cookie works only with the device cookie it was issued to.
thief=Client(); thief.cookies['oj_session']=a.cookies['oj_session']
s,b,_=thief.call('/submit',dict(submit,problem_id='1001')); check('copied session cookie alone cannot submit',s==401,(s,b))
s,b,_=thief.call('/session'); check('copied session cookie alone is anonymous',s==200 and b['user'] is None,b)
thief.cookies['oj_device']=c.cookies['oj_device']
s,b,_=thief.call('/submissions',{}); check('session cookie with another device cookie is rejected',s==401,(s,b))
for label,value in [('unsigned UUID',str(uuid.uuid4())),('tampered signature',raw[:-1]+('0' if raw[-1]!='0' else '1')),('non-ASCII signature',ident+'.é')]:
    c=Client(); c.cookies['oj_device']=value
    s,b,h=login(c,u)
    check(label+' is replaced without server error',s==200 and c.cookies.get('oj_device')!=value,(s, b if s!=200 else 'rotated'))
# Registration records the first login event, so send the forwarding headers there.
forged={'X-Real-IP':'203.0.113.77','X-Forwarded-For':'198.51.100.88'}
c=Client(); cu,cid,_=register(c,forged)
s,b,_=login(c,cu,forged)
ip=scalar('SELECT ip_address FROM login_events WHERE user_id=%s ORDER BY id DESC LIMIT 1',(cid,))
check('Nginx overwrites forged forwarding headers',s==200 and ip not in ['203.0.113.77','198.51.100.88'],ip)
proxied={'X-Real-IP':'192.0.2.6','X-Forwarded-For':'198.51.100.88'}
c=Client(base='http://127.0.0.1:8000'); cu,cid,_=register(c,proxied)
s,b,_=login(c,cu,proxied)
ip=scalar('SELECT ip_address FROM login_events WHERE user_id=%s ORDER BY id DESC LIMIT 1',(cid,))
check('Uvicorn preserves peer for application proxy trust',s==200 and ip=='192.0.2.6',ip)
# Database isolation guard: this is the test service, never a host database.
assert os.environ['MARIADB_HOST']=='db'
with get_connection() as conn:
    with conn.cursor() as cur:
        cur.execute('UPDATE login_security_alerts SET second_logged_in_at=NOW()-INTERVAL 4 HOUR WHERE user_id=%s',(uid,))
s,b,h=other.call('/submit',dict(submit,problem_id='1001'))
if s==429:
    time.sleep(min(int(h['Retry-After'])+1,60))
    s,b,h=other.call('/submit',dict(submit,problem_id='1001'))
check('expired alert no longer blocks submission',s==200,(s,b))
# Exercise actual application startup and HTTP Secure cookies on a separate listener.
for secret in ['', 'short']:
    env=dict(os.environ,DEVICE_SECRET=secret)
    p=subprocess.run(['uvicorn','main:app','--port','18001'],env=env,capture_output=True,text=True,timeout=15)
    check('startup refuses '+('missing' if not secret else 'short')+' secret',p.returncode!=0 and 'DEVICE_SECRET must be set' in p.stderr)
for db_password in ['', 'onlinejudge']:
    env=dict(os.environ,MARIADB_PASSWORD=db_password)
    p=subprocess.run(['uvicorn','main:app','--port','18001'],env=env,capture_output=True,text=True,timeout=15)
    check('startup refuses '+('missing' if not db_password else 'published default')+' database password',p.returncode!=0 and 'MARIADB_PASSWORD must be set' in p.stderr)
p=subprocess.Popen(['uvicorn','main:app','--host','127.0.0.1','--port','18001'],env=dict(os.environ,COOKIE_SECURE='true'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    c=Client(base='http://127.0.0.1:18001')
    for _ in range(40):
        try:
            if c.call('/')[0]==200: break
        except OSError: time.sleep(.25)
    _,_,h=register(c)
    check('HTTPS mode marks both cookies Secure and HttpOnly',len(h.get_all('Set-Cookie'))==2 and all('Secure' in v and 'HttpOnly' in v and 'SameSite=lax' in v for v in h.get_all('Set-Cookie')))
finally:
    p.terminate(); p.wait(timeout=10)
# LAN exam mode on its own listener. Each Client is one seat, identified by the X-Real-IP
# the trusted proxy (127.0.0.1 here) would forward. Fresh 10.20.0.x seats avoid earlier events.
p=subprocess.Popen(['uvicorn','main:app','--host','127.0.0.1','--port','18002','--no-proxy-headers'],env=dict(os.environ,LAN_EXAM_MODE='true'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    lan='http://127.0.0.1:18002'
    probe=Client(base=lan)
    for _ in range(40):
        try:
            if probe.call('/')[0]==200: break
        except OSError: time.sleep(.25)
    seat11=Client(base=lan,ip='10.20.0.11'); la,laid,_=register(seat11)
    seat12=Client(base=lan,ip='10.20.0.12'); lb,_,_=register(seat12)
    # H4: switching browsers on one seat does not unlock a second account.
    browser2=Client(base=lan,ip='10.20.0.11')
    s,b,_=login(browser2,lb); check('LAN: another browser on the same seat cannot login a second account',s==403,(s,b))
    s,b,_=browser2.call('/register',{'username':'it_'+uuid.uuid4().hex[:14],'password':'integration-password'})
    check('LAN: same seat cannot register a second account',s==403,(s,b))
    # H2: both cookies copied to another seat are useless there.
    copy=Client(base=lan,ip='10.20.0.14'); copy.cookies=dict(seat11.cookies)
    s,b,_=copy.call('/submit',submit); check('LAN: cookies copied to another seat cannot submit',s==401,(s,b))
    s,b,_=copy.call('/session'); check('LAN: cookies copied to another seat are anonymous',s==200 and b['user'] is None,b)
    # H3: a copied device cookie used from another seat is a different device.
    clone=Client(base=lan,ip='10.20.0.13'); clone.cookies['oj_device']=seat11.cookies['oj_device']
    s,b,_=login(clone,la)
    check('LAN: copied device cookie on another seat raises alert',s==200 and (b.get('login_alert') or {}).get('second_ip_address')=='10.20.0.13',b)
    s,b,_=clone.call('/submit',submit); check('LAN: copied device cookie seat cannot submit',s==403,(s,b))
    s,b,_=seat11.call('/submit',submit); check('LAN: original seat remains allowed',s==200,(s,b))
    s,b,_=seat11.call('/session'); check('LAN: original seat sees no warning',s==200 and b['user']['id']==laid and b['login_alerts']==[],b)
    s,b,_=clone.call('/session'); check('LAN: copied seat keeps its warning',s==200 and bool(b['login_alerts']),b)
    s,b,_=login(seat11,la); check('LAN: relogin on the original seat raises no alert',s==200 and b['login_alert'] is None,b)
finally:
    p.terminate(); p.wait(timeout=10)
print(json.dumps({'passed':sum(r[1] for r in results),'failed':sum(not r[1] for r in results)},ensure_ascii=False))
raise SystemExit(any(not r[1] for r in results))
