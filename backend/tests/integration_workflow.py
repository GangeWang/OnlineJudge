"""Run inside the isolated backend container; uses its temporary MariaDB only."""
import os, json, uuid, hmac, hashlib, subprocess, time
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import urlencode
from http.cookies import SimpleCookie
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import create_user, get_connection

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
# A login that raised a cross-device alert must not lock that device out of its own account.
flagged=Client(); s,b,_=login(flagged,u)
check('alerted login on a new device',s==200 and b.get('login_alert') is not None,b)
check('alerted login is flagged',scalar('SELECT raised_alert FROM login_events WHERE user_id=%s ORDER BY id DESC LIMIT 1',(uid,))==1)
own='it_'+uuid.uuid4().hex[:14]
s,b,_=flagged.call('/register',{'username':own,'password':'integration-password'})
check('device with only an alerted login can register its own account',s==200,(s,b))
# Logout ends this browser's session but keeps the device identity and login history.
lo=Client(); lou,louid,_=register(lo)
token=lo.cookies['oj_session']; device=lo.cookies['oj_device']
s,b,_=lo.call('/logout',{}); check('logout succeeds',s==200 and b=={'ok':True},(s,b))
check('logout deletes the session row',scalar('SELECT COUNT(*) FROM sessions WHERE user_id=%s',(louid,))==0)
check('logout keeps the device cookie',lo.cookies.get('oj_device')==device)
lo.cookies['oj_session']=token
s,b,_=lo.call('/session'); check('replayed session cookie after logout is anonymous',s==200 and b['user'] is None,b)
s,b,_=lo.call('/submit',submit); check('replayed session cookie after logout cannot submit',s==401,(s,b))
s,b,_=login(lo,lou); check('same device logs in again without alert',s==200 and b['login_alert'] is None,b)
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
    # The alerted login of la on seat 15 must not keep seat 15 from its own account.
    seat15=Client(base=lan,ip='10.20.0.15'); s,b,_=login(seat15,la)
    check('LAN: login of an account already in use elsewhere is alerted',s==200 and b.get('login_alert') is not None,b)
    s,b,_=seat15.call('/register',{'username':'it_'+uuid.uuid4().hex[:14],'password':'integration-password'})
    check('LAN: seat with only an alerted login can register its own account',s==200,(s,b))
    # Sessions created before IP binding existed have no IP and must sign in again.
    with get_connection() as conn:
        with conn.cursor() as cur: cur.execute("UPDATE sessions SET ip_address='' WHERE user_id=%s",(laid,))
    s,b,_=seat11.call('/session'); check('LAN: session without a stored IP is rejected',s==200 and b['user'] is None,b)
    s,b,_=login(seat11,la); check('LAN: signing in again restores the seat',s==200 and b['login_alert'] is None,b)
finally:
    p.terminate(); p.wait(timeout=10)
# Exam window and admin panel on a listener with a configured administrator.
admin_name='it_admin_'+uuid.uuid4().hex[:8]
proctor_name='it_proctor_'+uuid.uuid4().hex[:8]
reserved_name='it_reserved_'+uuid.uuid4().hex[:8]
# Admin accounts are created by the server operator, never through /register.
create_user(admin_name,'integration-password'); create_user(proctor_name,'integration-password')
admins=','.join([admin_name,proctor_name,reserved_name])
p=subprocess.Popen(['uvicorn','main:app','--host','127.0.0.1','--port','18003','--no-proxy-headers'],env=dict(os.environ,ADMIN_USERNAMES=admins),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    ex='http://127.0.0.1:18003'
    anon=Client(base=ex)
    for _ in range(40):
        try:
            if anon.call('/')[0]==200: break
        except OSError: time.sleep(.25)
    iso=lambda minutes:(datetime.now(timezone.utc)+timedelta(minutes=minutes)).isoformat()
    admin=Client(base=ex)
    s,b,_=login(admin,admin_name)
    check('exam: configured admin is flagged',s==200 and b['user']['is_admin'] is True,(s,b))
    for name in [reserved_name, reserved_name.upper()]:
        s,b,_=Client(base=ex).call('/register',{'username':name,'password':'integration-password'})
        check('admin name cannot be self-registered: '+('same case' if name==reserved_name else 'other case'),s==403,(s,b))
    check('reserved admin name was not created',scalar('SELECT COUNT(*) FROM users WHERE username=%s',(reserved_name,))==0)
    student=Client(base=ex); student_name,_,_=register(student)
    s,b,_=student.call('/session'); check('exam: student is not admin',s==200 and b['user']['is_admin'] is False,b)
    set_exam=lambda c,start,end:c.call('/admin/exam',{'start_at':start,'end_at':end})
    check('exam: anonymous cannot set the window',set_exam(anon,iso(60),iso(120))[0]==401)
    check('exam: student cannot set the window',set_exam(student,iso(60),iso(120))[0]==403)
    # Starts in 55 minutes: the window (one hour before the start) already covers the student's login.
    s,b,_=set_exam(admin,iso(55),iso(120)); check('exam: admin schedules a future exam',s==200 and b['phase']=='not_started',(s,b))
    s,b,_=anon.call('/exam'); check('exam: status is public and in UTC',s==200 and b['phase']=='not_started' and b['start_at'].endswith('Z'),b)
    check('exam: before start anonymous cannot read problems',anon.call('/problems')[0]==401)
    check('exam: before start student cannot read problems',student.call('/problems')[0]==403)
    s,b,_=admin.call('/problems'); check('exam: before start admin can read problems',s==200 and len(b)>0,s)
    s,b,_=student.call('/submit',submit); check('exam: before start student cannot submit',s==403 and '尚未開始' in b['detail'],(s,b))
    s,b,_=admin.call('/submit',submit); check('exam: admin can submit before start',s==200 and b.get('status')=='AC',(s,b))
    s,b,_=set_exam(admin,iso(-1),iso(60)); check('exam: admin starts the exam',s==200 and b['phase']=='running',(s,b))
    check('exam: running anonymous cannot read problems',anon.call('/problems')[0]==401)
    s,b,_=student.call('/problems'); check('exam: running student reads problems',s==200 and len(b)>0,s)
    s,b,_=student.call('/submit',submit); check('exam: running student submits',s==200 and b.get('status')=='AC',(s,b))
    s,b,_=set_exam(admin,iso(-120),iso(-60)); check('exam: admin ends the exam',s==200 and b['phase']=='ended',(s,b))
    s,b,_=student.call('/problems'); check('exam: ended problems stay readable',s==200 and len(b)>0,s)
    s,b,_=student.call('/submit',dict(submit,problem_id='1001')); check('exam: ended student cannot submit',s==403 and '已結束' in b['detail'],(s,b))
    check('exam: end before start is rejected',set_exam(admin,iso(60),iso(30))[0]==400)
    check('exam: time without offset is rejected',set_exam(admin,'2026-11-05T09:00',iso(60))[0]==400)
    s,b,_=set_exam(admin,'',''); check('exam: admin clears the exam',s==200 and b['phase']=='open',(s,b))
    check('exam: practice mode problems are public again',anon.call('/problems')[0]==200)
    # Admins are exempt from one account per device in both directions.
    proctor=Client(base=ex); proctor.cookies['oj_device']=student.cookies['oj_device']
    s,b,_=login(proctor,proctor_name); check('admin can sign in on a device a student used',s==200,(s,b))
    s,b,_=login(student,student_name); check('student signs in again after an admin used the device',s==200,(s,b))
    other=Client(base=ex); other.cookies['oj_device']=student.cookies['oj_device']
    s,b,_=other.call('/register',{'username':'it_'+uuid.uuid4().hex[:14],'password':'integration-password'})
    check('non-admin second account on that device is still refused',s==403,(s,b))
    # Admins are also exempt from cross-device alerts: several machines at once is normal for them.
    desk=Client(base=ex); s,b,_=login(desk,proctor_name)
    check('admin on another device raises no alert',s==200 and b['login_alert'] is None,(s,b))
    check('admin second device records no alert row',scalar('SELECT COUNT(*) FROM login_security_alerts a JOIN users u ON u.id=a.user_id WHERE u.username=%s',(proctor_name,))==0)
    s,b,_=desk.call('/submit',submit); check('admin second device can submit',s==200 and b.get('status')=='AC',(s,b))
    s,b,_=desk.call('/session'); check('admin second device shows no warning',s==200 and b['login_alerts']==[],b)
    # The anti-cheat window follows the exam: one hour before the start until the end.
    def age(table,column,uid,minutes):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f'UPDATE {table} SET {column}=NOW()-INTERVAL %s MINUTE WHERE user_id=%s',(minutes,uid))
    for lead,counted in [(10,True),(30,False)]:
        first=Client(base=ex); wu,wid,_=register(first); age('login_events','logged_in_at',wid,45)
        set_exam(admin,iso(lead),iso(120))
        s,b,_=login(Client(base=ex),wu)
        check(f'window: login 45 min ago {"counts" if counted else "does not count"} when the exam starts in {lead} min',
              s==200 and (b.get('login_alert') is not None)==counted,(s,b))
    longer=Client(base=ex); lu,lid,_=register(longer)
    set_exam(admin,iso(-300),iso(60))
    late=Client(base=ex); s,b,_=login(late,lu)
    check('window: second device alerted during a long exam',s==200 and b.get('login_alert') is not None,(s,b))
    age('login_events','logged_in_at',lid,240); age('login_security_alerts','second_logged_in_at',lid,240)
    s,b,_=late.call('/submit',submit)
    check('window: 4-hour-old alert still blocks inside a 5-hour exam',s==403 and '本場考試期間' in b['detail'],(s,b))
    set_exam(admin,'','')
    s,b,_=late.call('/submit',submit); check('window: the same alert has expired in practice mode',s==200,(s,b))
    set_exam(admin,iso(-120),iso(-60))
    seat=Client(base=ex); register(seat)
    s,b,_=seat.call('/register',{'username':'it_'+uuid.uuid4().hex[:14],'password':'integration-password'})
    check('window: after the exam a device may sign in another account',s==200,(s,b))
finally:
    p.terminate(); p.wait(timeout=10)
    # Never leave a schedule behind; it would apply to every listener.
    with get_connection() as conn:
        with conn.cursor() as cur: cur.execute('DELETE FROM exam_settings')
# Exam device rules must hold however a session came to exist (LAN exam mode with an administrator).
p=subprocess.Popen(['uvicorn','main:app','--host','127.0.0.1','--port','18004','--no-proxy-headers'],env=dict(os.environ,LAN_EXAM_MODE='true',ADMIN_USERNAMES=admins),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    lx='http://127.0.0.1:18004'
    for _ in range(40):
        try:
            if Client(base=lx,ip='10.77.0.250').call('/')[0]==200: break
        except OSError: time.sleep(.25)
    def account():
        name='it_'+uuid.uuid4().hex[:14]
        return name,create_user(name,'integration-password')['id']
    seat=lambda n:Client(base=lx,ip=f'10.77.0.{n}')
    boss=seat(250); s,b,_=login(boss,admin_name); check('lan exam: admin signs in',s==200 and b['user']['is_admin'] is True,(s,b))
    # 1. Signing in before the window opens (rules off) must not carry over into the exam.
    (ua,ida),(ub,idb)=account(),account()
    set_exam(boss,iso(90),iso(150))
    early_a,early_b=seat(2),seat(2)  # two browsers on one seat
    s1,_,_=login(early_a,ua); s2,_,_=login(early_b,ub)
    check('lan exam: before the window a seat may sign in two accounts',(s1,s2)==(200,200),(s1,s2))
    for uid in (ida,idb): age('login_events','logged_in_at',uid,95); age('sessions','created_at',uid,95)
    s,b,_=set_exam(boss,iso(-5),iso(55)); check('lan exam: exam is running 95 minutes later',s==200 and b['phase']=='running',(s,b))
    s,b,_=early_a.call('/session'); check('lan exam: session opened before the window is no longer accepted',s==200 and b['user'] is None,b)
    check('lan exam: such a session cannot read the problems',early_a.call('/problems')[0]==401)
    s,b,_=early_a.call('/submit',submit); check('lan exam: such a session cannot submit',s==401,(s,b))
    s,b,_=boss.call('/session'); check('lan exam: admin session survives the window opening',s==200 and b['user'] is not None,b)
    s,b,_=login(early_a,ua); check('lan exam: examinee signs in again inside the window',s==200 and b['login_alert'] is None,(s,b))
    s,b,_=login(early_b,ub); check('lan exam: second account on that seat is now refused',s==403 and '本場考試期間' in b['detail'],(s,b))
    s,b,_=early_a.call('/submit',submit); check('lan exam: the seat submits for its own account',s==200 and b.get('status')=='AC',(s,b))
    own_seat=seat(1); s,b,_=login(own_seat,ua); check('lan exam: same account on another seat is alerted',s==200 and b['login_alert'] is not None,(s,b))
    s,b,_=own_seat.call('/submit',dict(submit,problem_id='1001')); check('lan exam: the later seat cannot submit',s==403,(s,b))
    # 2. Logins made after the exam ended (rules off) must not count once the exam is extended.
    (ue,ide),(uf,idf),(ug,idg)=account(),account(),account()
    home=seat(7); s,b,_=login(home,ug); check('lan exam: examinee signs in at their seat during the exam',s==200 and b['login_alert'] is None,(s,b))
    s,b,_=set_exam(boss,iso(-70),iso(-1)); check('lan exam: exam has ended',s==200 and b['phase']=='ended',(s,b))
    late_e,late_f=seat(6),seat(6)
    s1,_,_=login(late_e,ue); s2,_,_=login(late_f,uf)
    check('lan exam: after the end a seat may sign in two accounts',(s1,s2)==(200,200),(s1,s2))
    away=seat(9); s,b,_=login(away,ug); check('lan exam: after the end another seat raises no alert',s==200 and b['login_alert'] is None,(s,b))
    s,b,_=set_exam(boss,iso(-70),iso(30)); check('lan exam: admin extends the exam',s==200 and b['phase']=='running',(s,b))
    s,b,_=late_e.call('/submit',submit); check('lan exam: first account on the seat can submit',s==200 and b.get('status')=='AC',(s,b))
    s,b,_=late_f.call('/submit',submit); check('lan exam: second account on the seat cannot submit',s==403 and '已登入其他帳號' in b['detail'],(s,b))
    s,b,_=away.call('/submit',submit); check('lan exam: account cannot submit from the later seat',s==403 and '異地登入' in b['detail'],(s,b))
    s,b,_=home.call('/submit',submit); check('lan exam: account still submits from its first seat',s==200 and b.get('status')=='AC',(s,b))
    check('lan exam: refused submissions are not stored',scalar('SELECT COUNT(*) FROM submissions WHERE user_id=%s',(idf,))==0)
    # 3. Practice mode is unchanged: the window slides and old sessions stay valid.
    set_exam(boss,'','')
    (uh,idh)=account(); practice=seat(12); login(practice,uh)
    age('login_events','logged_in_at',idh,200); age('sessions','created_at',idh,200)
    s,b,_=practice.call('/submit',submit); check('practice: a session older than the window still submits',s==200 and b.get('status')=='AC',(s,b))
finally:
    p.terminate(); p.wait(timeout=10)
    with get_connection() as conn:
        with conn.cursor() as cur: cur.execute('DELETE FROM exam_settings')
print(json.dumps({'passed':sum(r[1] for r in results),'failed':sum(not r[1] for r in results)},ensure_ascii=False))
raise SystemExit(any(not r[1] for r in results))
