from settings import *

# <----------------------------------------->
# !Some settings!
app.score_key = gen_random_string(128)
# app.score_key = 'ergergadlasjkldgfkusadbvluasygvsdfsdgDFASDFGASDGVwefsdfg'
secret_param = 'usefilename'
app.slash = '/'

# <----------------------------------------->
# !ROUTES!


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route("/")
def hello():
    res = make_response(render_template("index.html", score=app.score))
    return res # render index.html based on base.html


@app.route("/template/<user>")  # function vulnerable to SSTI
def render(user=None):
    template = f'Hello {user}!'  # cause of SSTI, render string with name
    return render_template("templates.html", score=app.score, template=render_template_string(template))


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return get_login()

    else:
        return post_login()


@app.route("/private")  # can access only with valid json token
def private():
    if request.cookies.get('token'):
        try:
            token = request.cookies.get('token')
            decoded_token = jwt.decode(token, app.config['secret'], algorithms=["HS256"])  # parsed JSON object
            username = decoded_token["username"]  # get username from JSON
            
            con = sqlite3.connect(app.db_name)
            cur = con.cursor()
            result = cur.execute(f"SELECT id,username FROM users WHERE username='{username}'")
            user_exists = result.fetchall()
            
            print(user_exists)
            if user_exists and decoded_token["isAdmin"]:
                return render_template("private.html", score = app.score, username=username, text="Welcome back to the private area, "
                                                                               "mr. Admin! Take your flag:",
                                       flag=app.flag_jwt[0])
            elif user_exists and not decoded_token["isAdmin"]:
                return render_template("private.html", username=username, score = app.score, text="This is the private area, but only "
                                                                               "admin can get the flag!")
            else:
                return render_template("403.html", reason="You can't access this area without auth! Go to /login page"), 403

        except:
            return render_template_string("Invalid JSON token!")
    else:
        return render_template("403.html", reason="JSON web token is missing or incorrect"), 403


@app.route('/corridor')
def corridor():
    return render_template("corridor.html", score = app.score)  # render index.html based on base.html


@app.route('/corridor/cfcd208495d565ef66e7dff9f98764da')
def corridor_room0():
    return render_template("corridor_room.html", number=0, img="/static/room0.jpg",
                           flag=app.flag_idor[0], score = app.score)


@app.route('/corridor/c4ca4238a0b923820dcc509a6f75849b')
def corridor_room1():
    return render_template("corridor_room.html", number=1, img="/static/room1.jpg", score = app.score)


@app.route('/corridor/c81e728d9d4c2f636f067f89cc14862c')
def corridor_room2():
    return render_template("corridor_room.html", number=2, img="/static/room2.jpg", score = app.score)


@app.route('/corridor/eccbc87e4b5ce2fe28308fd9f2a7baf3')
def corridor_room3():
    return render_template("corridor_room.html", number=3, img="/static/room3.jpg", score = app.score)


@app.route('/corridor/a87ff679a2f3e71d9181a67b7542122c')
def corridor_room4():
    return render_template("corridor_room.html", number=4, img="/static/room4.jpg", score = app.score)


@app.route('/corridor/e4da3b7fbbce2345d7772b0674a318d5')
def corridor_room5():
    return render_template("corridor_room.html", number=5, img="/static/room5.png", score = app.score)


@app.route('/secret', methods=['GET'])
def secret():
    file = ''
    
    modname = getattr(app, "__module__", t.cast(object, app).__class__.__module__)
    mod = sys.modules.get(modname)
    
    
    
    if request.method == "GET":
        value = request.args.get(secret_param)
        pin_check = request.args.get("pin")

    if value != None:
        if __file__.split(app.slash)[-1] in value:
            return render_template("403.html", reason="Don't try to read application source code!"), 403
        
        value = value.replace('../', '')
        value = os.getcwd() + "/" + value
        
        try:
            file = open(value).read()
        except:
            file = 'Some error!'

    if pin_check == get_pin():
        pin_ans = True
    else:
        pin_ans = False

    res = make_response(render_template('pin.html', file=file, pin=pin_ans, flag=app.flag_werkzuger[0], score = app.score, path=getattr(mod, "__file__", None)), 200)

    return res


@app.route('/console', methods=['GET'])
def console():
    return 'Imagine that there is an interactive console werkzeug'


@app.route('/getbrute', methods=['GET'])
def getbrute():
    if request.method == 'GET':
        return getbrute_login()


@app.route('/postbrute', methods=['GET', 'POST'])
def postbrute():
    if request.method == 'GET':
        return render_template("postbrute.html", score = app.score)
    else:
        return postbrute_login()


@app.route('/base64brute', methods=['GET', 'POST'])
def base64brute():
    if request.method == 'GET':
        return render_template("base64brute.html", score = app.score)
    else:
        return base64brute_login()


@app.route('/fuzzing', methods=['GET'])
def fuzzing_first():
    return render_template("flag.html", message="FUZZ ME!", score = app.score)


@app.route('/fuzzing/security_info', methods=['GET'])
def fuzzing_second():
    return render_template("flag.html", message="Go deeper!", score = app.score)


@app.route('/fuzzing/security_info/mysecret.txt', methods=['GET'])
def fuzzing_third():
    return render_template("flag.html", message="You found it!", flag=app.flag_fuzzing[0], score = app.score)


@app.route('/scoreboard', methods = ['GET', 'POST'])
def scoreboard():
    status = ''    
    token = request.cookies.get("score")
    token_decoded = jwt.decode(token, app.score_key, algorithms=["HS256"])


    if request.args.get("flag"):        
        flag = request.args.get("flag")
        correct = 0
        
        for i in range(len(app.flags)):
            if flag == app.flags[i][0]:
                correct = app.tasks[i]
                print(f'[+] Solved task [{app.tasks[i][0]}]')
        
        if not correct:
            status = status.join("Wrong flag!")
            
        else:
            token_decoded = jwt.decode(token, app.score_key, algorithms=["HS256"])

            if not token_decoded["flag_"+correct[0]]:
                token_decoded["flag_"+correct[0]]=True
                token_decoded['Score'] = token_decoded['Score'] + correct[1]
                app.score = app.score + correct[1]
                token = jwt.encode(token_decoded, app.score_key, algorithm="HS256")
                status = status.join(f'Solved! +{correct[1]}')
                
                res = make_response(render_template('scoreboard.html', status=status, solve=token_decoded, tasks=app.tasks, score=app.score), 200)
                res.set_cookie('score', token) 
                return res
            
            else:
                status = status.join('Already submitted!')
    
    
    res = make_response(render_template('scoreboard.html', solve=token_decoded, status=status, tasks=app.tasks, score=app.score), 200)
    return res


@app.route("/another_login")
def home():
    return render_template("xxe_login.html", score=app.score)


@app.route("/doLogin", methods=['POST', 'GET'])
def doLogin():
    try:
        tree = etree.fromstring(request.data)
        for item in tree:
            if item.tag == "username":
                username = item.text
            if item.tag == "password":
                password = item.text
        if username == app.username and password == app.password:
            result = f"<result><code>{1}</code><message>{username}</message><flag>{app.flag_XXE[0]}</flag></result>"
        else:
            result = f"<result><code>{0}</code><message>{username}</message></result>"
    except Exception as Ex:
        result = "<result><code>%d</code><message>%s</message></result>" % (3, str(Ex))
    return result, {'Content-Type': 'text/xml;charset=UTF-8'}


@app.route('/blog', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        add_comment(request.form['comment'])

    search_query = request.args.get('query')
    if search_query:
        search_query = search_query.replace("script", "")
        print(search_query)
    comments = get_comments(search_query)

    return render_template('xss.html', comments=comments, search_query=search_query, score=app.score, flagr=app.flag_ReflectedXSS[0], flags=app.flag_StoredXSS[0])


@app.route('/reset_commentdb', methods=['POST', 'GET'])
def reset_commentdb():
    prepare_db_comments()
    return redirect('/blog', 302)


@app.before_request
def prepare_request():
    # Check JWT and set score
    try:
        score = int(check_score(request))
    except:
        return check_score(request)
    
    app.score = score
    # +++++++++++++++++WAF++++++++++++++++++++++
    nice = 1
    not_nice_mass = [__file__.split(app.slash)[-1], 'script',
                     'subclasses', 'builtins', 'mro', 'exec',
                     'system', 'import', 'RUNCMD', 'popen', '__']
    
    def check(val,exclude):
        counter = 0
        
        for i in exclude:
            if i in val:
                print(f'[\/] Detected hacker attack! payload: [{i}]')
                counter += 1
        return counter
    
    if request.method == "GET":
        value = dict(request.args)
           
    elif request.method == "POST":
        value = dict(request.form)
        value2 = request.data.decode('UTF-8')
        nice -= check(value2,not_nice_mass)

    #print(value, request.method, request.data.decode('UTF-8'))
    # Check all data
    for i in value:
        nice -= check(i,not_nice_mass)
        nice -= check(value[i],not_nice_mass)
    
    # Check url
    nice -= check(request.url,not_nice_mass)

    
    if nice != 1:
        return render_template("403.html", reason="WAF! WAF!"), 403
    
    
if __name__ == "__main__":
    print(f"PIN: {get_pin()}")
    prepare()
    app.run(host=host, port=port)