# <----------------------------------------->
# !IMPORTS!
import random
import sqlite3  # module for sqlite
from datetime import datetime
from flask import Flask, render_template_string, render_template, request, make_response, send_from_directory, redirect  # modules for flask app
import jwt  # for JWT token
from lxml import etree

# <----------------------------------------->
# !NEET TO GENERATE PIN!
from itertools import chain
import typing as t
import getpass
import hashlib
import uuid
import sys
import os
import re

# <----------------------------------------->
app = Flask(__name__)
# <----------------------------------------->
# !FLAGS!
app.flag_getbrute = ["flag{G3T_l0g1n_p4g3_15_700_e45y_70_brut3}", 50]
app.flag_postbrute = ["flag{P057_l0g1n_p4g3_15_700_e45y_70_brut3}", 60]
app.flag_base64brute = ["flag{b45364_l0g1n_p4g3_15_700_e45y_70_brut3}", 75]
app.flag_fuzzing = ["flag{4lw4y5_fuzz_su861r5_70_f1n6_s7h_1n73r3571n9}", 100]
app.flag_sqli = ["flag{UN10N_b4s3d_SQL1_d3t3c3d}", 300]
app.flag_ssti = ["flag{Fl4sk_4nd_J1nj4_15_s0_c00l}", 75]
app.flag_jwt = ["flag{J50n_w3b_t0k3n_n0t_s0_s3cur3}", 400]
app.flag_idor = ["flag{1D0R_15_v3ry_s1mpl3_70_expl017}", 100]
app.flag_werkzuger = ["flag{W3rkz3ug3r_P1N_g3n3r4ted_S1dn3yJ0b_g3n1u5}", 700]
app.flag_ReflectedXSS = ["flag{R3fl3cted_X55_1s_v3ry_345y}", 25]
app.flag_StoredXSS = ["flag{DB_c4n_c0nt41n_y0ur_p4y10ad}", 25]
app.flag_XXE = ["flag{XX3_3xpl01736}", 350]
# <----------------------------------------->
all_attr=dir(app)
all_attr_flags = []

app.flags = []
app.tasks = []

for i in all_attr:
    if "flag" in i:
        all_attr_flags.append(i)
        app.flags.append(getattr(app, i))
        
for i in range(len(app.flags)):
    app.tasks.append([all_attr_flags[i].split('flag_')[1],app.flags[i][1]])
# <----------------------------------------->
# !CONFIG!
app.config['secret'] = "RealStrongSecretJWTKey"
app.config['flag'] = app.flag_ssti[0]
app.db_name = 'sqli.db'
#app.debug = True  # OFF!
host = '0.0.0.0'  # set 0.0.0.0 to forward in global net
port = 5001
app.score = 0
app.username = 'YouWillNeverGuessThisU53rn4m3'
app.password = 'ButP@ssw0rdIsVeryStr0ng'

# <----------------------------------------->
# !DISABLE LOGGING REQUESTS!
# import logging

# app.logger.disabled = True
# log = logging.getLogger('werkzeug')
# log.disabled = True
# <----------------------------------------->

# !FUNCTIONS!
def generate_jwt():
    tasks = {}
    app.score = 0
    
    for i in all_attr_flags:
        tasks[i]=False
        
    tasks['Time'] = str(datetime.now())
    tasks['user'] = "user_" + gen_random_string(16)
    tasks['Score'] = app.score
    
    token = jwt.encode(tasks, app.score_key, algorithm="HS256")

    return token

def check_score(request):
    if not request.cookies.get('score'):
        res = make_response(render_template("index.html"))
        res.set_cookie('score', generate_jwt())
        
        print('[+] Set cookie!')
        return res
    
    else:
        try:
            token = request.cookies.get('score')
            score = jwt.decode(token, app.score_key, algorithms=["HS256"])['Score']
            app.score = score
        except:
            return render_template("403.html", reason="Invalid JWT token!"), 403
        
        return score


def get_login():
    return render_template("login.html", score = app.score)


def getbrute_login():
    username = request.args.get('username')
    password = request.args.get('password')
    if username and password:
        if username == 'admin' and password == 'musiclover':
            return render_template("flag.html", message="Good job, my friend! Nice GET brute. Take your flag:",
                                   flag=app.flag_getbrute[0], score = app.score)
        else:
            return render_template("getbrute.html", error_message="Incorrect credentials", score = app.score)

    else:
        return render_template("getbrute.html", score = app.score)


def postbrute_login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username and password:
        if username == 'ansible' and password == 'newcastle':
            return render_template("flag.html", message="Good job! Nice POST brute. Take your flag:",
                                   flag=app.flag_postbrute[0], score = app.score)
        else:
            return render_template("postbrute.html", error_message="Incorrect credentials", score = app.score)

    else:
        return render_template("postbrute.html", score = app.score)


def base64brute_login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username and password:
        if username == 'YWRtaW4=' and password == 'Y2hpY2tlbm51Z2dldA==':  # admin + chickennugget
            return render_template("flag.html", message="Good job! Nice Base64 POST brute. Take your flag:",
                                   flag=app.flag_base64brute[0], score = app.score)
        else:
            return render_template("base64brute.html", error_message="Incorrect credentials", score = app.score)

    else:
        return render_template("base64brute.html", score = app.score)


def post_login():
    con = sqlite3.connect(app.db_name)
    cur = con.cursor()
    username = request.form.get('username')
    password = request.form.get('password')
    result = cur.execute(f"SELECT username,password FROM users WHERE username='{username}' and password='{password}'")
    creds = result.fetchall()
    if creds:
        token = jwt.encode({"username": creds[0][0], "isAdmin": False}, app.config['secret'], algorithm="HS256")
        print(token)
        print(jwt.decode(token, app.config['secret'], algorithms=["HS256"]))
        resp = make_response(render_template("profile.html", name=creds[0][0], score = app.score))
        resp.set_cookie('token', token)
        return resp
    else:
        return render_template("login.html", function="alert", error_message="Invalid credentials", score = app.score)  # generates
        # login.html with alert JS



# <----------------------------------------->
# !TECHNICAL FUNCTUONS!
def gen_random_string(lenght):
    chars = 'abcdefghijklnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    string = ''
    
    for i in range(lenght):
        string += random.choice(chars)
    return string


def multiple_queryes_to_db(query, cursor, conn):
    st = ''

    for i in query:
        cursor.execute(i)
        conn.commit()

        st = st + ''.join(cursor.fetchall())
    return st


def prepare_db():
    if os.path.exists(app.db_name):
        os.remove(app.db_name)

    conn = sqlite3.connect(app.db_name)
    cursor = conn.cursor()

    queryes = ["""
CREATE TABLE IF NOT EXISTS "users" (
        "id"    INTEGER NOT NULL UNIQUE,
        "username"      TEXT(3, 50) NOT NULL UNIQUE,
        "password"      TEXT(3, 50) NOT NULL,
        PRIMARY KEY("id" AUTOINCREMENT)
);""",
               F'CREATE TABLE IF NOT EXISTS "flag" ("flag_value"    TEXT(50));',
               f'INSERT INTO "users" ("id","username","password") VALUES (1,"Oidaho","Oidaho1");',
               f'INSERT INTO "users" ("id","username","password") VALUES (2,"cherepawwka","P@ssw0rd");',
               f'INSERT INTO "flag" ("flag_value") VALUES ("{app.flag_sqli[0]}");'
               ]

    data = multiple_queryes_to_db(queryes, cursor, conn)
    cursor.close()
    print('[+] Database_sqli was created!')



def prepare_db_comments():
    if os.path.exists("comments.db"):
        os.remove("comments.db")

    conn = sqlite3.connect('comments.db')
    cursor = conn.cursor()
    
    cursor.execute('CREATE TABLE IF NOT EXISTS comments '
                        '(id INTEGER PRIMARY KEY, '
                        'comment TEXT)')
    conn.commit()
    print('[+] Database_comments was created!')




#++++++++++++++++++++++++++++++++++++++++++++++++++++++++
def connect_db():
    db = sqlite3.connect('comments.db')
    return db


def add_comment(comment):
    db = connect_db()
    db.cursor().execute('INSERT INTO comments (comment) '
                        'VALUES (?)', (comment,))
    db.commit()


def get_comments(search_query=None):
    db = connect_db()
    results = []
    get_all_query = 'SELECT comment FROM comments'
    for (comment,) in db.cursor().execute(get_all_query).fetchall():
        if search_query is None or search_query in comment:
            results.append(comment)
    return results




def get_machine_id() -> str | bytes | None:
    def _generate() -> str | bytes | None:
        linux = b""

        # machine-id is stable across boots, boot_id is not.
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
            try:
                with open(filename, "rb") as f:
                    value = f.readline().strip()
            except OSError:
                continue

            if value:
                linux += value
                break

        # Containers share the same machine id, add some cgroup
        # information. This is used outside containers too but should be
        # relatively stable across boots.
        try:
            with open("/proc/self/cgroup", "rb") as f:
                linux += f.readline().strip().rpartition(b"/")[2]
        except OSError:
            pass

        if linux:
            return linux
        try:
            from subprocess import Popen, PIPE

            dump = Popen(
                ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"], stdout=PIPE
            ).communicate()[0]
            match = re.search(b'"serial-number" = <([^>]+)', dump)

            if match is not None:
                return match.group(1)
        except (OSError, ImportError):
            pass
        if sys.platform == "win32":
            import winreg

            try:
                with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        "SOFTWARE\\Microsoft\\Cryptography",
                        0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
                ) as rk:
                    guid: str | bytes
                    guid_type: int
                    guid, guid_type = winreg.QueryValueEx(rk, "MachineGuid")

                    if guid_type == winreg.REG_SZ:
                        return guid.encode("utf-8")

                    return guid
            except OSError:
                pass

        return None

    _machine_id = _generate()
    return _machine_id


def get_pin():
    modname = getattr(app, "__module__", t.cast(object, app).__class__.__module__)
    username = getpass.getuser()
    mod = sys.modules.get(modname)
    pin = os.environ.get("WERKZEUG_DEBUG_PIN")
    rv = None
    num = None

    probably_public_bits = [username, modname, getattr(app, "__name__", type(app).__name__),
                            getattr(mod, "__file__", None)]
    private_bits = [str(uuid.getnode()), get_machine_id()]

    h = hashlib.sha1()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")

    if num is None:
        h.update(b"pinsalt")
        num = f"{int(h.hexdigest(), 16):09d}"[:9]

    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = "-".join(
                    num[x: x + group_size].rjust(group_size, "0")
                    for x in range(0, len(num), group_size))
                break
        else:
            rv = num
    return rv

def prepare_creds():
    if os.path.exists("creds.txt"):
        os.remove("creds.txt")
    with open('creds.txt', 'w') as f:
        f.write(f'My uncrackable creds: {app.username}:{app.password}')


def prepare():
    prepare_db()
    prepare_db_comments()
    prepare_creds()
