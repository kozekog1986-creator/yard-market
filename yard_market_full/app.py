import os, sqlite3, secrets, smtplib, ssl, re
from email.message import EmailMessage
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

BASE=os.path.dirname(os.path.abspath(__file__))
app=Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', MAX_CONTENT_LENGTH=3*1024*1024)
DB=os.path.join(BASE,'market.db')
CATEGORIES=['Электроника','Одежда и обувь','Дом и быт','Хобби','Спорт','Транспорт','Другое']

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c

def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, username TEXT NOT NULL, password_hash TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, verify_hash TEXT, verify_exp TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS listings(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL, price INTEGER NOT NULL, location TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE, sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE INDEX IF NOT EXISTS idx_listing_created ON listings(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id,receiver_id,listing_id);
        ''')
init_db()

def current_user():
    uid=session.get('user_id')
    if not uid:return None
    with db() as c:return c.execute('SELECT id,email,username,verified FROM users WHERE id=?',(uid,)).fetchone()
def login_required(fn):
    @wraps(fn)
    def w(*a,**kw):
        if not current_user(): flash('Войдите в аккаунт.'); return redirect(url_for('login'))
        return fn(*a,**kw)
    return w
@app.context_processor
def inject(): return {'me':current_user(),'categories':CATEGORIES}

def send_verification(email,token):
    host=os.environ.get('SMTP_HOST'); user=os.environ.get('SMTP_USER'); password=os.environ.get('SMTP_PASSWORD'); sender=os.environ.get('MAIL_FROM') or user
    link=url_for('verify',token=token,_external=True)
    if not (host and user and password and sender):
        app.logger.warning('DEV VERIFICATION for %s: %s',email,link)
        return False
    msg=EmailMessage(); msg['Subject']='Подтверждение регистрации YARD'; msg['From']=sender; msg['To']=email
    msg.set_content(f'Здравствуйте! Подтвердите адрес электронной почты, перейдя по ссылке (действует 30 минут):\n{link}\nЕсли вы не регистрировались, проигнорируйте письмо.')
    with smtplib.SMTP(host,int(os.environ.get('SMTP_PORT','587')),timeout=20) as s:
        s.starttls(context=ssl.create_default_context()); s.login(user,password); s.send_message(msg)
    return True

def safe_return(default='index'):
    nxt=request.form.get('next','')
    if nxt.startswith('/') and not nxt.startswith('//'): return nxt
    return url_for(default)

@app.route('/')
def index():
    q=request.args.get('q','').strip()[:100]; cat=request.args.get('category',''); sort=request.args.get('sort','new')
    sql='SELECT l.*,u.username FROM listings l JOIN users u ON u.id=l.user_id WHERE u.verified=1'; args=[]
    if q: sql+=' AND (l.title LIKE ? OR l.description LIKE ? OR l.location LIKE ?)'; args += [f'%{q}%',f'%{q}%',f'%{q}%']
    if cat in CATEGORIES: sql+=' AND l.category=?'; args.append(cat)
    sql += ' ORDER BY l.price ASC' if sort=='cheap' else (' ORDER BY l.price DESC' if sort=='expensive' else ' ORDER BY l.id DESC')
    with db() as c: items=c.execute(sql+' LIMIT 120',args).fetchall()
    return render_template('index.html',items=items,q=q,cat=cat,sort=sort)

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower(); name=request.form.get('username','').strip(); password=request.form.get('password','')
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email) or len(email)>254: flash('Введите корректную почту.')
        elif len(name)<2 or len(name)>40: flash('Имя должно содержать от 2 до 40 символов.')
        elif len(password)<8: flash('Пароль должен быть не короче 8 символов.')
        else:
            token=secrets.token_urlsafe(32); now=datetime.utcnow()
            try:
                with db() as c:
                    c.execute('INSERT INTO users(email,username,password_hash,verify_hash,verify_exp) VALUES(?,?,?,?,?)',(email,name,generate_password_hash(password),generate_password_hash(token),(now+timedelta(minutes=30)).isoformat()))
                try:
                    real=send_verification(email,token)
                    flash('Письмо отправлено. Проверьте почту и подтвердите регистрацию.' if real else 'Тестовый режим: ссылка подтверждения записана в консоль, где запущен сайт. Настройте SMTP для отправки писем.')
                except Exception:
                    app.logger.exception('Email send failed'); flash('Аккаунт создан, но письмо не отправлено. Настройте SMTP и повторите регистрацию с другим адресом либо обратитесь к администратору.')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError: flash('Аккаунт с такой почтой уже существует.')
    return render_template('auth.html',mode='register')

@app.route('/verify/<token>')
def verify(token):
    with db() as c: rows=c.execute('SELECT id,verify_hash,verify_exp FROM users WHERE verified=0 AND verify_hash IS NOT NULL').fetchall()
    for u in rows:
        if u['verify_exp'] and datetime.fromisoformat(u['verify_exp'])>=datetime.utcnow() and check_password_hash(u['verify_hash'],token):
            with db() as c:c.execute('UPDATE users SET verified=1,verify_hash=NULL,verify_exp=NULL WHERE id=?',(u['id'],))
            flash('Почта подтверждена. Теперь можно войти.'); return redirect(url_for('login'))
    return render_template('message.html',heading='Ссылка недействительна',message='Ссылка могла истечь или уже быть использована.'),400

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
        with db() as c:u=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        if not u or not check_password_hash(u['password_hash'],password): flash('Неверная почта или пароль.')
        elif not u['verified']: flash('Сначала подтвердите почту по ссылке из письма.')
        else: session.clear(); session['user_id']=u['id']; return redirect(url_for('index'))
    return render_template('auth.html',mode='login')
@app.route('/logout',methods=['POST'])
def logout():session.clear();return redirect(url_for('index'))

@app.route('/new',methods=['GET','POST'])
@login_required
def new_listing():
    if not me_verified(): return redirect(url_for('unverified'))
    if request.method=='POST':
        title=request.form.get('title','').strip(); desc=request.form.get('description','').strip(); cat=request.form.get('category',''); loc=request.form.get('location','').strip()[:80]
        try:price=int(request.form.get('price',''))
        except ValueError:price=-1
        if not title or len(title)>100 or not desc or len(desc)>3000 or cat not in CATEGORIES or not 0<=price<=100000000:flash('Проверьте заполнение полей.')
        else:
            with db() as c:c.execute('INSERT INTO listings(user_id,title,description,category,price,location) VALUES(?,?,?,?,?,?)',(session['user_id'],title,desc,cat,price,loc))
            flash('Объявление опубликовано.');return redirect(url_for('index'))
    return render_template('listing_form.html',item=None)
def me_verified():
    u=current_user();return bool(u and u['verified'])
@app.route('/unverified')
@login_required
def unverified():return render_template('message.html',heading='Подтвердите почту',message='Для публикации и сообщений нужно подтвердить адрес электронной почты.')

@app.route('/listing/<int:item_id>')
def listing(item_id):
    with db() as c:item=c.execute('SELECT l.*,u.username FROM listings l JOIN users u ON u.id=l.user_id WHERE l.id=?',(item_id,)).fetchone()
    if not item:abort(404)
    return render_template('listing.html',item=item)
@app.route('/listing/<int:item_id>/edit',methods=['GET','POST'])
@login_required
def edit_listing(item_id):
    with db() as c:item=c.execute('SELECT * FROM listings WHERE id=? AND user_id=?',(item_id,session['user_id'])).fetchone()
    if not item:abort(404)
    if request.method=='POST':
        title=request.form.get('title','').strip();desc=request.form.get('description','').strip();cat=request.form.get('category','');loc=request.form.get('location','').strip()[:80]
        try:price=int(request.form.get('price',''))
        except ValueError:price=-1
        if not title or len(title)>100 or not desc or len(desc)>3000 or cat not in CATEGORIES or not 0<=price<=100000000:flash('Проверьте поля.')
        else:
            with db() as c:c.execute('UPDATE listings SET title=?,description=?,category=?,price=?,location=? WHERE id=? AND user_id=?',(title,desc,cat,price,loc,item_id,session['user_id']))
            flash('Объявление обновлено.');return redirect(url_for('listing',item_id=item_id))
    return render_template('listing_form.html',item=item)
@app.route('/listing/<int:item_id>/delete',methods=['POST'])
@login_required
def delete_listing(item_id):
    with db() as c:c.execute('DELETE FROM listings WHERE id=? AND user_id=?',(item_id,session['user_id']))
    flash('Объявление удалено, если оно принадлежало вам.');return redirect(url_for('profile'))

@app.route('/profile',methods=['GET','POST'])
@login_required
def profile():
    if request.method=='POST':
        name=request.form.get('username','').strip()
        if len(name)<2 or len(name)>40:flash('Имя должно содержать от 2 до 40 символов.')
        else:
            with db() as c:c.execute('UPDATE users SET username=? WHERE id=?',(name,session['user_id']))
            flash('Профиль обновлён.')
        return redirect(url_for('profile'))
    with db() as c:
        u=c.execute('SELECT * FROM users WHERE id=?',(session['user_id'],)).fetchone()
        items=c.execute('SELECT * FROM listings WHERE user_id=? ORDER BY id DESC',(session['user_id'],)).fetchall()
    return render_template('profile.html',user=u,items=items)

@app.route('/message/<int:item_id>',methods=['POST'])
@login_required
def send_message(item_id):
    body=request.form.get('body','').strip()
    with db() as c:item=c.execute('SELECT user_id FROM listings WHERE id=?',(item_id,)).fetchone()
    if not item:abort(404)
    if item['user_id']==session['user_id']:flash('Нельзя написать самому себе.')
    elif not me_verified():flash('Подтвердите почту, чтобы отправлять сообщения.')
    elif not body or len(body)>2000:flash('Сообщение должно содержать от 1 до 2000 символов.')
    else:
        with db() as c:c.execute('INSERT INTO messages(listing_id,sender_id,receiver_id,body) VALUES(?,?,?,?)',(item_id,session['user_id'],item['user_id'],body))
        flash('Сообщение отправлено.')
    return redirect(url_for('listing',item_id=item_id))
@app.route('/inbox')
@login_required
def inbox():
    with db() as c:
        rows=c.execute('''SELECT m.*, l.title, u.username AS other_name, u.id AS other_id FROM messages m JOIN listings l ON l.id=m.listing_id JOIN users u ON u.id=CASE WHEN m.sender_id=? THEN m.receiver_id ELSE m.sender_id END WHERE m.sender_id=? OR m.receiver_id=? ORDER BY m.id DESC''',(session['user_id'],session['user_id'],session['user_id'])).fetchall()
    return render_template('inbox.html',messages=rows)
@app.errorhandler(404)
def missing(e):return render_template('message.html',heading='Страница не найдена',message='Такой страницы или объявления нет.'),404
if __name__=='__main__':app.run(host='127.0.0.1',port=int(os.environ.get('PORT','5000')),debug=False)
