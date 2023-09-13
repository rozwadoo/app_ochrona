from flask import Flask, render_template, request, redirect, abort, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import markdown
from passlib.hash import pbkdf2_sha256
import sqlite3
import bleach
import time
import cryptocode
from myapp.validation import passwordValidation, nameValidation, emailValidation, entropy, generate_password
import secrets
import string


app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
ip_ban_list = list()
app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"
DATABASE = "./sqlite3.db"
ALLOWED_TAGS = ['a', 'strong', 'h1', 'h2', 'h3', 'h4', 'h5', 'img', 'em', 'ul', 'ol', 'li', 'blockquote', 'p']

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    cmd = "SELECT username, password, ip, fails, email FROM user WHERE username = ?"
    sql.execute(cmd, (username,))
    row = sql.fetchone()
    try:
        username, password, ip, fails, email = row
    except:
        return None
    user = User()
    user.id = username
    user.password = password
    user.ip = ip
    user.fails = fails
    user.email = email
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user


@app.route("/home", methods=["GET"])
def home():
    logout_user()
    ip = request.remote_addr
    if ip in ip_ban_list:
        abort(403)
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    cmd = "SELECT id, title, username FROM notes WHERE public == 1"
    sql.execute(cmd)
    notes = sql.fetchall()
    return render_template("home.html", notes=notes)

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "GET":
        logout_user()
        ip = request.remote_addr
        if ip in ip_ban_list:
            abort(403)
        return render_template("index.html")
    if request.method == "POST":
        time.sleep(2)
        ip = request.remote_addr
        if ip in ip_ban_list:
            abort(403)
        username = request.form.get("username")
        password = request.form.get("password")
        if not passwordValidation(password) or not nameValidation(username):
            flash(f'Username can consist only of letters and numbers.\n \
                  Password can consist only of letters, numbers and special characters !, @, #, $, %, ^, &, *, (, ), _, +, [, ], :, ;, ,, ., ?, ~, , /, -.\n \
                The username has to consist of 2-16 characters.\n \
                    Password needs to contain at least one small letter, capital letter, number and a special character. \n \
                        It has to consist of 8-16 characters.')
            return redirect('/')
        if ((username == "ferry3" and password == "Dks34.34") or (username == "gamer555" and password == "384Njn,;,") or (username == "m00m" and password == "Lk34lk.,3") or (username == "bomy9" and password == "Pooo121.")):
            ip_ban_list.append(ip)
            db = sqlite3.connect(DATABASE)
            sql = db.cursor()
            cmd = f"INSERT INTO sus (ip) VALUES (?)"
            sql.execute(cmd, (ip,))
            db.commit()
            return redirect('/')
        user = user_loader(username)
        if user is None:
            flash('Incorrect username or password')
            return redirect('/')
        if pbkdf2_sha256.verify(password, user.password):
            login_user(user)
            db = sqlite3.connect(DATABASE)
            sql = db.cursor()
            cmd = f"UPDATE user SET fails = 0"
            sql.execute(cmd)
            db.commit()
            if ip != user.ip:
                print(f"Sent notification about a login from new ip address {ip} to {user.email}. The old address was {user.ip}")
                cmd = f"UPDATE user SET ip = ? WHERE username = ?"
                sql.execute(cmd, (ip, user.id))
                db.commit()
            return redirect('/hello')
        else:
            db = sqlite3.connect(DATABASE)
            sql = db.cursor()
            cmd = f"UPDATE user SET fails = ? WHERE username = ? "
            sql.execute(cmd, (user.fails +1,user.id))
            db.commit()
            if user.fails == 10:
                ip_ban_list.append(ip)
                db = sqlite3.connect(DATABASE)
                sql = db.cursor()
                cmd = f"INSERT INTO sus (ip) VALUES (?)"
                sql.execute(cmd, (ip,))
                db.commit()
            flash('Incorrect username or password')
            return redirect('/')


@app.route("/hello/<rendered_id>")
@login_required
def ver(rendered_id):
    ip = request.remote_addr
    if ip in ip_ban_list:
        abort(403)
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    cmd = "SELECT username FROM notes WHERE id == ?"
    sql.execute(cmd, (rendered_id,))
    name = sql.fetchone()[0]
    if name != username:
        return redirect('/')
    session['id'] = rendered_id
    return redirect("/verify")

@app.route("/hello", methods=['GET'])
@login_required
def hello():
    ip = request.remote_addr
    if ip in ip_ban_list:
        abort(403)
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    cmd = "SELECT id, title, public FROM notes WHERE username == ?"
    sql.execute(cmd, (username,))
    notes = sql.fetchall()
    return render_template("hello.html", username=username, notes=notes)

@app.route("/render", methods=['POST'])
@login_required
def render():
    ip = request.remote_addr
    if ip in ip_ban_list:
        abort(403)
    md = request.form.get("markdown")
    rendered = bleach.clean(markdown.markdown(md), tags = ALLOWED_TAGS)
    title = request.form.get("title")
    password = request.form.get("password")
    if not nameValidation(title):
            flash(f'Title can consist only of letters and numbers.\n \
                The title has to consist of 2-16 characters.')
            return redirect('/hello')
    if password and (not passwordValidation(password)):
            flash(f'Password can consist only of letters, numbers and special characters !, @, #, $, %, ^, &, *, (, ), _, +, [, ], :, ;, ,, ., ?, ~, , /, -.\n \
                Password needs to contain at least one small letter, capital letter, number and a special character. \n \
                        It has to consist of 8-16 characters.')
            return redirect('/hello')
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    if not password:
        cmd = f"INSERT INTO notes (username, title, note, public) VALUES (?, ?, ?, 1)"
        sql.execute(cmd, (username, title, rendered))
    else:
        if entropy(password) < 3:
            flash(f'Try a stronger password')
            return redirect('/hello')
        rendered = cryptocode.encrypt(rendered, password)
        cmd = f"INSERT INTO notes (username, title, note, public) VALUES (?, ?, ?, 0)"
        sql.execute(cmd, (username, title, rendered))
    db.commit()
    return redirect('/hello')

@app.route("/verify", methods=['GET', 'POST'])
@login_required
def verify():
    if request.method == "GET":
        ip = request.remote_addr
        if ip in ip_ban_list:
            abort(403)
        return render_template("verification.html")
    if request.method == "POST":
        ip = request.remote_addr
        if ip in ip_ban_list:
            abort(403)
        username = current_user.id
        id = session.get('id', None)
        if id is None:
            return redirect('/') 
        else:
            db = sqlite3.connect(DATABASE)
            sql = db.cursor()
            cmd = "SELECT note FROM notes WHERE id = CAST(? AS int)"
            sql.execute(cmd, (str(id),))
            try:
                note = sql.fetchone()[0]
            except:
                return "Note not found", 404
            pas2 = request.form.get("pas2")
            if not passwordValidation(pas2):
                flash('Incorrect password')
                return redirect('/hello')
            elif cryptocode.decrypt(note, pas2):
                pas4 = generate_password(16)
                pas3 = cryptocode.encrypt(pas2, pas4)
                session['name'] = pas4
                db = sqlite3.connect(DATABASE)
                sql = db.cursor()
                cmd = f"INSERT INTO session (name, password) VALUES (?, ?)"
                sql.execute(cmd, (username + ip, pas3))
                db.commit()
                return redirect(f"/render/{id}")
            else:
                flash('Incorrect password')
                return redirect('/hello')



@app.route("/home/<rendered_id>")
def render_old_public(rendered_id):
    ip = request.remote_addr
    if ip in ip_ban_list:
        abort(403)
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    cmd = f"SELECT note, title, public FROM notes WHERE id == ?"
    sql.execute(cmd, (rendered_id,))
    try:
        rendered, title, publ = sql.fetchone()
        rendered = bleach.clean(markdown.markdown(rendered), tags = ALLOWED_TAGS)
        if publ == 0:
            return "Note not found", 404
        return render_template(f"markdown.html", rendered=rendered, title=title, pub="1")
    except:
        return "Note not found", 404

@app.route("/render/<rendered_id>")
@login_required
def render_old(rendered_id):
    ip = request.remote_addr
    if ip in ip_ban_list:
        abort(403)
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    cmd = f"SELECT username, note, title, public FROM notes WHERE id == ?"
    sql.execute(cmd, (rendered_id,))

    username, rendered, title, public = sql.fetchone()
    if username != current_user.id:
        return "Access to note forbidden", 403
    if public == 1:
        return render_template(f"markdown.html", rendered=rendered, title=title, pub="0")
    else:
        pas4 = session.get('name', None)
        sql = db.cursor()
        cmd = f"SELECT name, password FROM session WHERE name == ?"
        sql.execute(cmd, (username + ip,))
        try:
            pas3 = sql.fetchone()[1]
        except:
            return redirect('/')     
        if (pas3 or pas4) is None:
            return redirect('/')  
        else:
            pas2 = cryptocode.decrypt(pas3, pas4)
            if pas2:
                session.pop('name', None)
                sql = db.cursor()
                cmd = f"DELETE FROM session WHERE name == ?"
                sql.execute(cmd, (username + ip,))
                rendered = cryptocode.decrypt(rendered, pas2)
                rendered = bleach.clean(markdown.markdown(rendered), tags = ALLOWED_TAGS)
                db.commit()
                if rendered:
                    return render_template(f"markdown.html", rendered=rendered, title=title, pub="0")
                else:
                    flash('Incorrect password')
                    return redirect('/hello')    
            else:
                return redirect('/')    


@app.route('/signup', methods=["GET","POST"])
def signup():
    if request.method == "GET":
        logout_user()
        ip = request.remote_addr
        if ip in ip_ban_list:
            abort(403)
        return render_template("signup.html")
    if request.method == "POST":
        ip = request.remote_addr
        if ip in ip_ban_list:
            abort(403)
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        if not emailValidation(email):
            flash('Invalid email.')
            return redirect('/signup')
        if not nameValidation(username):
            flash(f'Username can consist only of letters and numbers.\n \
                The username has to consist of 2-16 characters.')
            return redirect('/signup')
        if not passwordValidation(password):
            flash(f'Password can consist only of letters, numbers and special characters !, @, #, $, %, ^, &, *, (, ), _, +, [, ], :, ;, ,, ., ?, ~, , /, -.\n \
                Password needs to contain at least one small letter, capital letter, number and a special character. \n \
                        It has to consist of 8-16 characters.')
            return redirect('/signup')
        if entropy(password) < 3:
            flash(f'Try a stronger password')
            return redirect('/signup')
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        cmd = "SELECT username, email FROM user WHERE username = ? or email = ?"
        sql.execute(cmd, (username, email))
        row = sql.fetchone()
        try:
            username1, email1 = row
        except:
            username1 = None

        if username1 is None:
            db = sqlite3.connect(DATABASE)
            sql = db.cursor()
            cmd = f"INSERT INTO user (username, password, ip, email, fails) VALUES (?, ?, ?, ?, 0)"
            sql.execute(cmd, (username, pbkdf2_sha256.hash(password), ip, email))
            db.commit()
            return redirect('/')
        else:
            if username == username1:
                flash('An account with that username already exists.')
            if email == email1:
                flash('An account with that email already exists.')
            return redirect('/signup')

@app.route('/recover', methods=["GET","POST"])
def recover():
    if request.method == "GET":
        logout_user()
        ip = request.remote_addr
        if ip in ip_ban_list:
            abort(403)
        return render_template("recover.html")
    if request.method == "POST":
        ip = request.remote_addr
        if ip in ip_ban_list:
            abort(403)
        email = request.form.get("email")
        username = request.form.get("username")
        if not emailValidation(email):
            flash('This user does not exist')
            return redirect('/recover')
        if not nameValidation(username):
            flash(f'This user does not exist')
            return redirect('/recover')
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        cmd = "SELECT username, email FROM user WHERE username = ? and email = ?"
        sql.execute(cmd, (username, email))
        row = sql.fetchone()
        try:
            username1, email1 = row
        except:
            username1 = None

        if username1 is None:
            flash(f'This user does not exist')
            return redirect('/recover')
        else:
            db = sqlite3.connect(DATABASE)
            sql = db.cursor()
            cmd = f"UPDATE user SET password = ? WHERE username = ?"
            password = generate_password(16)
            print(f"Sent new password: {password} to {email1}.")
            sql.execute(cmd, (pbkdf2_sha256.hash(password),username1))
            db.commit()
            flash(f'New password has been sent to your email.')
            return redirect('/recover')

    


if __name__ == "__main__":
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("DROP TABLE IF EXISTS user;")
    sql.execute("CREATE TABLE user (username VARCHAR(32), password VARCHAR(128), input VARCHAR(128), last INTEGER, ip VARCHAR(64), fails INTEGER, email VARCHAR(64));")
    sql.execute("DELETE FROM user;")
    sql.execute("INSERT INTO user (username, password, fails, email) VALUES ('Bro12345', '$pbkdf2-sha256$29000$p/Qeg3Cudc5Zay3lPAcAAA$Yp7uNo2WReHDF.RAHMI3ARMJbr/v2NnwIborqIiJS/Y', 0, 'bro@gmail.com');")
    sql.execute("INSERT INTO user (username, password, fails, email) VALUES ('Admin123', '$pbkdf2-sha256$29000$z1lLac259/5/z/n///./Fw$J2AhlpKfj6m12oyDqOWm8H1MYPlnGUbcedlpXNlGfiM', 0, 'admin@gmail.com');")
    #honeypots
    sql.execute("INSERT INTO user (username, password, fails, email) VALUES ('ferry3', '$pbkdf2-sha256$29000$kRLifM.5lzJGaA3hPAfAmA$jwctl6ZGAg/EVL0hnOSR9VjShVE.dzexn6EjFHNWnKQ', 0, 'fer@gmail.com');")
    sql.execute("INSERT INTO user (username, password, fails, email) VALUES ('gamer555', '$pbkdf2-sha256$29000$oFRKKSWEsBYCgHAOoTSG8A$jVYHO49IJ0Xt2Wx2ZGN3.6dRLeuSVY78ZbE2hMjjNS8', 0, 'gem@gmail.com');")
    sql.execute("INSERT INTO user (username, password, fails, email) VALUES ('m00m', '$pbkdf2-sha256$29000$ROj9XwsBwFhrzTlnbI1xLg$v8yEwj0JT87U9nHacPa11J4LsO0saDa.7rKWRpFpxoI', 0, 'moom@gmail.com');")
    sql.execute("INSERT INTO user (username, password, fails, email) VALUES ('bomy9', '$pbkdf2-sha256$29000$ltK6l1JK6R0DQMg5h/AeAw$MWrXmyMCvj8IVnywZfiMG5RLLcilFOQraRrikDnj5Ik', 0, 'bomy@gmail.com');")

    sql.execute("DROP TABLE IF EXISTS notes;")
    sql.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), title VARCHAR(32), public BINARY, note VARCHAR(256), password VARCHAR(128));")
    sql.execute("DELETE FROM notes;")
    sql.execute("INSERT INTO notes (username, title, public, note, id) VALUES ('Bro12345', 'my first note', 1, 'Public note', 1);")
    sql.execute("INSERT INTO notes (username, title, public, note, id) VALUES ('Bro12345', 'my second note', 1, 'Public note2', 2);")

    sql.execute("DROP TABLE IF EXISTS sus;")
    sql.execute("CREATE TABLE sus (id INTEGER PRIMARY KEY, ip VARCHAR(64));")
    sql.execute("DELETE FROM sus;")

    sql.execute("DROP TABLE IF EXISTS session;")
    sql.execute("CREATE TABLE session (name VARCHAR(32), password VARCHAR(128));")
    sql.execute("DELETE FROM session;")


    db.commit()

    app.run("0.0.0.0", port=5000, ssl_context=('./nginx/cert.pem', './nginx/key.pem'))
    #app.run("0.0.0.0", port=5000)