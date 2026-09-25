from __future__ import annotations
import hashlib,hmac,html,json,mimetypes,os,secrets,socket,sqlite3,time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs,urlparse

ROOT=Path(__file__).resolve().parent
ASSETS=ROOT/'assets'
DB_PATH=Path(os.environ.get('VIARKA_SCORE_DB',str(ROOT/'viarka_score.db')))
HOST=os.environ.get('VIARKA_SCORE_HOST','127.0.0.1')
PORT=int(os.environ.get('PORT',os.environ.get('VIARKA_SCORE_PORT','8765')))
PAIR_TTL_SECONDS=12*60*60
SESSION_TTL_SECONDS=30*24*60*60

def database():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(DB_PATH,timeout=15);db.row_factory=sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA foreign_keys=ON')
    return db

def initialize_database():
    with database() as db: db.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT NOT NULL UNIQUE COLLATE NOCASE,display_name TEXT NOT NULL,password_hash TEXT NOT NULL,created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS pairing_codes(token TEXT PRIMARY KEY,terminal_id TEXT NOT NULL,user_id INTEGER REFERENCES users(id),session_key TEXT UNIQUE,status TEXT NOT NULL DEFAULT 'waiting',created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id),terminal_id TEXT NOT NULL,score INTEGER NOT NULL,max_multiplier REAL NOT NULL,near_misses INTEGER NOT NULL,collisions INTEGER NOT NULL,duration REAL NOT NULL,car_name TEXT NOT NULL,track_name TEXT NOT NULL,created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS web_sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS runs_user_score ON runs(user_id,score DESC);CREATE INDEX IF NOT EXISTS runs_created ON runs(created_at DESC);CREATE INDEX IF NOT EXISTS web_sessions_user ON web_sessions(user_id);''')

def password_hash(password):
    salt=secrets.token_bytes(16);digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,240000)
    return f'pbkdf2_sha256$240000${salt.hex()}${digest.hex()}'

def password_valid(password,encoded):
    try:
        algorithm,rounds,salt,digest=encoded.split('$',3)
        actual=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),int(rounds))
        return algorithm=='pbkdf2_sha256' and hmac.compare_digest(actual.hex(),digest)
    except (ValueError,TypeError): return False

def lan_ip():
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.connect(('8.8.8.8',80));value=sock.getsockname()[0];sock.close();return value
    except OSError:return '127.0.0.1'

def num(value):return f'{int(value):,}'.replace(',',' ')

def nav(active,user):
    def link(path,label,key):return f"<a class='{'active' if active==key else ''}' href='{path}'>{label}</a>"
    account='/profile' if user else '/login';label=html.escape(user['display_name']) if user else 'ВОЙТИ'
    return f"<header class='shell desktop-nav'><a class='brand' href='/'>VIARKA <span>SCORE</span></a><nav class='navlinks'>{link('/','ГЛАВНАЯ','home')}{link('/leaders','ЛИДЕРЫ','leaders')}{link('/profile','МОЯ СТАТИСТИКА','profile')}</nav><a class='btn' href='{account}'>{label}</a></header>"

def bottom(active):
    return f"<nav class='bottom-nav'><a class='{'active' if active=='home' else ''}' href='/'>ГЛАВНАЯ</a><a class='{'active' if active=='leaders' else ''}' href='/leaders'>ЛИДЕРЫ</a><a class='{'active' if active=='profile' else ''}' href='/profile'>ПРОФИЛЬ</a></nav>"

def page(title,body,active='',user=None):
    return ("<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1,viewport-fit=cover'>"+f"<title>{html.escape(title)}</title><link rel='stylesheet' href='/assets/style.css'></head><body>{nav(active,user)}{body}{bottom(active)}<script src='/assets/app.js'></script></body></html>").encode()

class Handler(BaseHTTPRequestHandler):
    server_version='VIARKAScore/0.7'
    def log_message(self,fmt,*args):print(time.strftime('%H:%M:%S'),self.client_address[0],fmt%args)
    def send_bytes(self,data,content_type,status=200,headers=None):
        self.send_response(status);self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store')
        for k,v in (headers or {}).items():self.send_header(k,v)
        self.end_headers();self.wfile.write(data)
    def send_json(self,value,status=200):self.send_bytes(json.dumps(value,ensure_ascii=False).encode(),'application/json; charset=utf-8',status)
    def redirect(self,path,cookie=None):
        headers={'Location':path}
        if cookie:headers['Set-Cookie']=cookie
        self.send_bytes(b'','text/plain',HTTPStatus.SEE_OTHER,headers)
    def body(self):return self.rfile.read(min(int(self.headers.get('Content-Length','0') or 0),1000000))
    def json_body(self):
        try:return json.loads(self.body().decode())
        except (json.JSONDecodeError,UnicodeDecodeError):return {}
    def form_body(self):return {k:v[0] for k,v in parse_qs(self.body().decode('utf-8','replace'),keep_blank_values=True).items()}
    def current_user(self):
        item=SimpleCookie(self.headers.get('Cookie','')).get('viarka_session')
        if not item:return None
        now=int(time.time())
        with database() as db:
            db.execute('DELETE FROM web_sessions WHERE expires_at<?',(now,))
            return db.execute('SELECT u.* FROM web_sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>=?',(item.value,now)).fetchone()
    def asset(self,name):
        path=ASSETS/Path(name).name
        if not path.is_file():return self.send_json({'error':'not_found'},404)
        self.send_bytes(path.read_bytes(),mimetypes.guess_type(path.name)[0] or 'application/octet-stream',headers={'Cache-Control':'public, max-age=86400'})
    def do_GET(self):
        p=urlparse(self.path);user=self.current_user()
        if p.path=='/':self.home_page(user)
        elif p.path=='/leaders':self.leaders_page(user)
        elif p.path=='/profile':self.profile_page(user)
        elif p.path=='/login':self.login_page()
        elif p.path=='/logout':self.redirect('/','viarka_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')
        elif p.path=='/pair':self.pair_page(parse_qs(p.query).get('token',[''])[0])
        elif p.path.startswith('/assets/'):self.asset(p.path.rsplit('/',1)[-1])
        elif p.path.startswith('/api/pairing/'):self.pair_status(p.path.rsplit('/',1)[-1])
        elif p.path=='/api/leaderboard':self.leaderboard_json()
        elif p.path=='/health':self.send_json({'ok':True,'service':'VIARKA Score','version':'0.7'})
        else:self.send_json({'error':'not_found'},404)
    def do_POST(self):
        p=urlparse(self.path)
        if p.path=='/api/pairing':self.create_pairing()
        elif p.path=='/pair':self.complete_pairing(self.form_body())
        elif p.path=='/login':self.complete_login(self.form_body())
        elif p.path=='/api/runs':self.save_run(self.json_body())
        else:self.send_json({'error':'not_found'},404)
    def rows(self,limit=100):
        with database() as db:return db.execute('''SELECT u.id,u.display_name,MAX(r.score) score,COUNT(r.id) runs,MAX(r.max_multiplier) max_multiplier,MAX(r.created_at) last_run FROM users u JOIN runs r ON r.user_id=u.id GROUP BY u.id ORDER BY score DESC,MIN(r.created_at) ASC LIMIT ?''',(limit,)).fetchall()
    def rank(self,user_id,rows):
        return next((i for i,r in enumerate(rows,1) if r['id']==user_id),None)
    def podium(self,rows):
        if not rows:return "<div class='panel empty'>Рейтинг появится после первого завершённого заезда.</div>"
        order=[1,0,2] if len(rows)>=3 else list(range(len(rows)));out=[]
        for source in order:
            r=rows[source];rank=source+1
            out.append(f"<article class='podium-card {'first' if rank==1 else ''}'><div class='rank'>{rank}</div><img class='avatar' src='/assets/viarka-driver.png' alt='Пилот'><h3>{html.escape(r['display_name'])}</h3><div class='big-score'>{num(r['score'])}</div><p>{r['runs']} ЗАЕЗДОВ · КОМБО ×{r['max_multiplier']:.1f}</p></article>")
        return ''.join(out)
    def home_page(self,user):
        rows=self.rows()
        with database() as db:totals=db.execute('SELECT COUNT(DISTINCT user_id) pilots,COUNT(*) runs FROM runs').fetchone()
        rank=self.rank(user['id'],rows) if user else None;score=rows[rank-1]['score'] if rank else 0;next_score=rows[rank-2]['score'] if rank and rank>1 else score
        body=f"""<section class='hero'><div class='shell hero-copy'><div class='eyebrow'>СИМ-РЕЙСИНГ · РЕАЛЬНЫЕ РЕЗУЛЬТАТЫ</div><h1 class='display'>ТВОЙ ЗАЕЗД.<em>ТВОЙ РЕКОРД.</em></h1><p class='lede'>Набирай очки, рискуй и поднимайся в общем рейтинге VIARKA.</p><div class='actions'><a class='btn primary' href='/profile'>{'МОЯ СТАТИСТИКА' if user else 'ВОЙТИ В ПРОФИЛЬ'}</a><a class='btn' href='/leaders'>СМОТРЕТЬ ЛИДЕРОВ</a></div></div></section><div class='shell season-strip'><div class='season-stat'><b>СЕЗОН <span class='blue'>01</span></b><span>ТЕКУЩИЙ СЕЗОН</span></div><div class='season-stat'><b>{totals['pilots'] or 0}</b><span>ПИЛОТОВ</span></div><div class='season-stat'><b>{num(totals['runs'] or 0)}</b><span>ЗАЕЗДОВ</span></div><div class='season-stat'><b class='blue'>{'#'+str(rank) if rank else '—'}</b><span>{'ДО СЛЕДУЮЩЕГО МЕСТА '+num(max(0,next_score-score))+' ОЧКОВ' if rank and rank>1 else 'ТВОЯ ПОЗИЦИЯ В РЕЙТИНГЕ'}</span></div></div><main class='shell'><section class='section'><div class='section-head'><div><div class='eyebrow'>ЛУЧШИЕ ИЗ ЛУЧШИХ</div><h2 class='section-title'>ЛИДЕРЫ СЕЗОНА</h2></div><a class='link-blue' href='/leaders'>СМОТРЕТЬ ВСЕХ →</a></div><div class='podium'>{self.podium(rows[:3])}</div></section></main><footer class='footer'><div class='shell footer-inner'><b>VIARKA SCORE</b><span>Каждый заезд делает тебя лучше.</span></div></footer>"""
        self.send_bytes(page('VIARKA SCORE',body,'home',user),'text/html; charset=utf-8')
    def leaders_page(self,user):
        rows=self.rows();uid=user['id'] if user else None;now=int(time.time())
        table=''.join(f"<tr class='{'you' if r['id']==uid else ''}' data-period='{'today' if now-r['last_run']<86400 else 'week'}'><td class='rank-cell'>{i}</td><td><b>{html.escape(r['display_name'])}</b></td><td class='score'>{num(r['score'])}</td><td>{r['runs']}</td><td>×{r['max_multiplier']:.1f}</td></tr>" for i,r in enumerate(rows,1)) or "<tr><td colspan='5' class='empty'>Пока нет завершённых попыток. Первый рекорд может стать твоим.</td></tr>"
        body=f"""<main><section class='leaders-hero'><div class='shell section'><div class='section-head'><div><div class='eyebrow'>ОБЩИЙ РЕЙТИНГ ПИЛОТОВ</div><h1 class='section-title'>КТО БЫСТРЕЕ.</h1></div><div class='season-stat leaders-season'><b>СЕЗОН <span class='blue'>01</span></b><span>ОБЩИЙ ЗАЧЁТ</span></div></div><div class='podium'>{self.podium(rows[:3])}</div></div></section><section class='shell section' style='padding-top:28px'><div class='filters'><button class='filter active' data-filter='all'>ОБЩИЙ</button><button class='filter' data-filter='week'>НЕДЕЛЯ</button><button class='filter' data-filter='today'>СЕГОДНЯ</button></div><div class='panel table-panel'><table class='leader-table'><thead><tr><th>МЕСТО</th><th>ПИЛОТ</th><th>РЕКОРД</th><th>ЗАЕЗДЫ</th><th>ЛУЧШЕЕ КОМБО</th></tr></thead><tbody>{table}</tbody></table></div></section></main>"""
        self.send_bytes(page('VIARKA — лидеры',body,'leaders',user),'text/html; charset=utf-8')
    def profile_page(self,user):
        if not user:return self.redirect('/login?next=/profile')
        with database() as db:runs=db.execute('SELECT * FROM runs WHERE user_id=? ORDER BY created_at DESC LIMIT 30',(user['id'],)).fetchall()
        rows=self.rows();rank=self.rank(user['id'],rows);best=max((r['score'] for r in runs),default=0);avg=sum(r['score'] for r in runs)/len(runs) if runs else 0;combo=max((r['max_multiplier'] for r in runs),default=1);near=sum(r['near_misses'] for r in runs);chart=list(reversed([r['score'] for r in runs[:12]])) or [0]
        history=''.join(f"<div class='history-row'><div><b>{html.escape(r['car_name'])}</b><small>{time.strftime('%d.%m.%Y',time.localtime(r['created_at']))}</small></div><div>{html.escape(r['track_name'])}</div><div>КОМБО ×{r['max_multiplier']:.1f}</div><b class='score'>{num(r['score'])}</b></div>" for r in runs[:6]) or "<div class='empty'>Заверши первый заезд — здесь появится его аналитика.</div>"
        start=max(0,(rank or 1)-2);rivals=rows[start:start+3]
        rival_html=''.join(f"<div class='rival-row {'you' if r['id']==user['id'] else ''}'><b>{rows.index(r)+1}</b><img src='/assets/viarka-driver.png' alt=''><span>{html.escape(r['display_name'])}</span><b>{num(r['score'])}</b></div>" for r in rivals) or "<div class='empty'>Соперники появятся вместе с рейтингом.</div>"
        body=f"""<section class='profile-hero'><div class='shell profile-intro'><img class='avatar' src='/assets/viarka-driver.png' alt='Профиль'><div><div class='profile-kicker'>ПИЛОТ VIARKA</div><h1 class='profile-name'>{html.escape(user['display_name'])}</h1><p class='profile-kicker'>МЕСТО {rank or '—'} / {len(rows) or '—'}</p></div><div class='profile-record'><span>ЛИЧНЫЙ РЕКОРД</span><strong>{num(best)}</strong></div></div></section><main class='shell'><section class='section stats-layout'><div><div class='panel chart-panel'><div class='chart-head'><h2>ДИНАМИКА ЗАЕЗДОВ</h2><span class='link-blue'>ПОСЛЕДНИЕ {len(chart)}</span></div><div class='chart-wrap'><canvas id='scoreChart' data-values='{json.dumps(chart)}'></canvas></div></div><div class='panel history'><div class='section-head' style='padding:22px 20px 0;margin-bottom:8px'><h2 style='margin:0'>ИСТОРИЯ ЗАЕЗДОВ</h2></div>{history}</div></div><aside><div class='panel metric-grid'><div class='metric'><span>СРЕДНИЙ СЧЁТ</span><strong>{num(avg)}</strong></div><div class='metric'><span>ЛУЧШЕЕ КОМБО</span><strong>×{combo:.1f}</strong></div><div class='metric'><span>ОПАСНЫЕ ОБГОНЫ</span><strong>{near}</strong></div><div class='metric'><span>ПОПЫТКИ</span><strong>{len(runs)}</strong></div></div><div class='panel rivals' style='margin-top:18px'><h2>БЛИЖАЙШИЕ СОПЕРНИКИ</h2>{rival_html}</div><a class='btn' style='width:100%;margin-top:18px' href='/logout'>ВЫЙТИ ИЗ ПРОФИЛЯ</a></aside></section></main>"""
        self.send_bytes(page('VIARKA — моя статистика',body,'profile',user),'text/html; charset=utf-8')
    def login_page(self,message=''):
        note=f"<div class='notice'>{html.escape(message)}</div>" if message else ''
        body=f"""<main class='auth-wrap'><section class='panel auth-card'><div class='eyebrow'>VIARKA SCORE</div><h1>АККАУНТ ПИЛОТА</h1><p class='section-copy'>Войди в существующий профиль или создай новый за минуту.</p>{note}<div class='auth-tabs'><button type='button' class='active' data-auth-tab='login'>ВОЙТИ</button><button type='button' data-auth-tab='register'>РЕГИСТРАЦИЯ</button></div><form method='post' action='/login' data-auth-panel='login'><input type='hidden' name='mode' value='login'><label>Почта</label><input name='email' type='email' autocomplete='email' required><label>Пароль</label><input name='password' type='password' autocomplete='current-password' minlength='4' required><button class='btn primary'>ВОЙТИ</button></form><form method='post' action='/login' data-auth-panel='register' hidden><input type='hidden' name='mode' value='register'><label>Ник в рейтинге</label><input name='display_name' maxlength='28' minlength='2' autocomplete='nickname' required><label>Почта</label><input name='email' type='email' autocomplete='email' required><label>Пароль</label><input name='password' type='password' autocomplete='new-password' minlength='4' required><small class='field-help'>Минимум 4 символа — сложные требования не нужны.</small><button class='btn primary'>СОЗДАТЬ АККАУНТ</button></form></section></main>"""
        self.send_bytes(page('VIARKA — вход',body),'text/html; charset=utf-8')
    def complete_login(self,form):
        email=form.get('email','').strip().lower();password=form.get('password','');mode=form.get('mode','login');now=int(time.time())
        if not email or len(password)<4:return self.login_page('Проверь почту и пароль: минимум 4 символа.')
        with database() as db:
            if mode=='register':
                name=form.get('display_name','').strip()[:28]
                if len(name)<2:return self.login_page('Ник должен содержать минимум 2 символа.')
                try:uid=db.execute('INSERT INTO users(email,display_name,password_hash,created_at) VALUES(?,?,?,?)',(email,name,password_hash(password),now)).lastrowid
                except sqlite3.IntegrityError:return self.login_page('Аккаунт с такой почтой уже существует.')
            else:
                user=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
                if not user or not password_valid(password,user['password_hash']):return self.login_page('Неверная почта или пароль.')
                uid=user['id']
            token=secrets.token_urlsafe(32);db.execute('INSERT INTO web_sessions VALUES(?,?,?,?)',(token,uid,now,now+SESSION_TTL_SECONDS))
        secure='; Secure' if self.headers.get('X-Forwarded-Proto','').lower()=='https' else ''
        self.redirect('/profile',f'viarka_session={token}; Path=/; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; SameSite=Lax{secure}')
    def create_pairing(self):
        terminal=str(self.json_body().get('terminal_id','unknown'))[:80];now=int(time.time());token=secrets.token_urlsafe(18)
        with database() as db:db.execute('DELETE FROM pairing_codes WHERE expires_at<?',(now,));db.execute('INSERT INTO pairing_codes(token,terminal_id,created_at,expires_at) VALUES(?,?,?,?)',(token,terminal,now,now+PAIR_TTL_SECONDS))
        base=os.environ.get('VIARKA_SCORE_PUBLIC_URL','').rstrip('/')
        if not base:
            proto=self.headers.get('X-Forwarded-Proto','http').split(',')[0].strip();host=self.headers.get('X-Forwarded-Host',self.headers.get('Host','')).split(',')[0].strip();base=f'{proto}://{host}' if host else f'http://{lan_ip()}:{PORT}'
        self.send_json({'token':token,'pair_url':f'{base}/pair?token={token}','expires_in':PAIR_TTL_SECONDS})
    def pair_status(self,token):
        with database() as db:r=db.execute('''SELECT p.status,p.session_key,p.expires_at,u.display_name,COALESCE(MAX(r.score),0) best_score FROM pairing_codes p LEFT JOIN users u ON u.id=p.user_id LEFT JOIN runs r ON r.user_id=u.id WHERE p.token=? GROUP BY p.token''',(token,)).fetchone()
        if not r or r['expires_at']<int(time.time()):return self.send_json({'status':'expired'},410)
        result={'status':r['status']}
        if r['status']=='paired':result.update(session_key=r['session_key'],display_name=r['display_name'],best_score=r['best_score'])
        self.send_json(result)
    def pair_page(self,token,message=''):
        with database() as db:pair=db.execute('SELECT status,expires_at FROM pairing_codes WHERE token=?',(token,)).fetchone()
        if not pair or pair['expires_at']<int(time.time()):return self.send_bytes(page('Код истёк',"<main class='auth-wrap'><section class='panel auth-card'><h1>QR-КОД ИСТЁК</h1><p>Получи новый код в игре.</p></section></main>"),'text/html; charset=utf-8',410)
        if pair['status']=='paired':return self.send_bytes(page('Готово',"<main class='auth-wrap'><section class='panel auth-card'><h1>АККАУНТ ПОДКЛЮЧЁН</h1><p>Можно вернуться к симулятору.</p></section></main>"),'text/html; charset=utf-8')
        note=f"<div class='notice'>{html.escape(message)}</div>" if message else ''
        def fields(mode,title,name=''):return f"<form method='post' action='/pair'><h2>{title}</h2><input type='hidden' name='token' value='{html.escape(token)}'><input type='hidden' name='mode' value='{mode}'>{name}<label>Почта</label><input name='email' type='email' required><label>Пароль</label><input name='password' type='password' minlength='4' required><button class='btn {'primary' if mode=='register' else ''}' style='width:100%;margin-top:18px'>{'СОЗДАТЬ И ПОДКЛЮЧИТЬ' if mode=='register' else 'ВОЙТИ И ПОДКЛЮЧИТЬ'}</button></form>"
        registration="<label>Имя в рейтинге</label><input name='display_name' maxlength='28' required>"
        body=f"<main class='auth-wrap'><section class='panel' style='width:min(900px,calc(100% - 28px));padding:28px'><div class='eyebrow'>VIARKA SCORE</div><h1>ПОДКЛЮЧИТЬ ИГРОКА</h1>{note}<div class='pair-grid'>{fields('register','РЕГИСТРАЦИЯ',registration)}{fields('login','УЖЕ ЕСТЬ АККАУНТ')}</div></section></main>"
        self.send_bytes(page('Подключение игрока',body),'text/html; charset=utf-8')
    def complete_pairing(self,form):
        token=form.get('token','');email=form.get('email','').strip().lower();password=form.get('password','');now=int(time.time())
        if not email or len(password)<4:return self.pair_page(token,'Проверь почту и пароль: минимум 4 символа.')
        try:
            with database() as db:
                pair=db.execute('SELECT * FROM pairing_codes WHERE token=?',(token,)).fetchone()
                if not pair or pair['status']!='waiting' or pair['expires_at']<now:return self.pair_page(token,'Код недействителен или уже использован.')
                if form.get('mode')=='register':
                    name=form.get('display_name','').strip()[:28]
                    if len(name)<2:return self.pair_page(token,'Введи отображаемое имя.')
                    uid=db.execute('INSERT INTO users(email,display_name,password_hash,created_at) VALUES(?,?,?,?)',(email,name,password_hash(password),now)).lastrowid
                else:
                    user=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
                    if not user or not password_valid(password,user['password_hash']):return self.pair_page(token,'Неверная почта или пароль.')
                    uid=user['id']
                db.execute("UPDATE pairing_codes SET user_id=?,session_key=?,status='paired' WHERE token=?",(uid,secrets.token_urlsafe(32),token))
        except sqlite3.IntegrityError:return self.pair_page(token,'Аккаунт с такой почтой уже существует.')
        self.pair_page(token)
    def save_run(self,data):
        with database() as db:
            pair=db.execute("SELECT user_id,terminal_id FROM pairing_codes WHERE session_key=? AND status='paired'",(str(data.get('session_key','')),)).fetchone()
            if not pair:return self.send_json({'error':'unauthorized'},401)
            score=max(0,min(int(data.get('score',0)),2000000000));previous=db.execute('SELECT COALESCE(MAX(score),0) best FROM runs WHERE user_id=?',(pair['user_id'],)).fetchone()['best']
            values=(pair['user_id'],pair['terminal_id'],score,max(1,min(float(data.get('max_multiplier',1)),100)),max(0,int(data.get('near_misses',0))),max(0,int(data.get('collisions',0))),max(0,min(float(data.get('duration',0)),86400)),str(data.get('car_name','Unknown'))[:100],str(data.get('track_name','Unknown'))[:100],int(time.time()))
            db.execute('INSERT INTO runs(user_id,terminal_id,score,max_multiplier,near_misses,collisions,duration,car_name,track_name,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',values)
        self.send_json({'ok':True,'best_score':max(score,previous),'new_record':score>previous})
    def leaderboard_json(self):self.send_json([dict(rank=i+1,**dict(r)) for i,r in enumerate(self.rows())])

if __name__=='__main__':
    initialize_database();print(f'VIARKA Score server: http://127.0.0.1:{PORT}');print(f'On local network: http://{lan_ip()}:{PORT}');ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
