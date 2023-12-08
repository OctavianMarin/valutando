from flask import Flask, render_template, make_response, request, redirect, url_for, session, send_file
import pymongo
import hashlib
from random import choices
import smtplib
from email.mime.text import MIMEText
import datetime
import os

from email.mime.multipart import MIMEMultipart
import string

app = Flask(__name__, template_folder='templates/')
app.secret_key = ":)"
app.config['UPLOAD_FOLDER'] = "upload"
images_dir = "images/"
elements_dir = "elements/"
style_path = 'templates/style.css'
client = pymongo.MongoClient(
    ":)"
)
db = client.valutando


class Utils:
    @staticmethod
    def check_account():
        if 'username' and 'password' in session:
            user = db.users.find_one({'username': session['username']})
            if user is not None:
                if hashlib.sha3_512(session['password'].encode()).hexdigest() == user['password']:
                    return True
        return False

    @staticmethod
    def load_cookies():
        username = request.cookies.get('username', None)
        password = request.cookies.get('password', None)
        if username is not None and password is not None:
            session['username'] = username
            session['password'] = password
            session['accept_cookie'] = True
        if 'info' not in session:
            session['info'] = False

    @staticmethod
    def send_validation_mail(addr, validation_key):
        message = MIMEMultipart("alternative")
        message["Subject"] = "Validation Key"
        message.attach(MIMEText(
            f"Questa è la tua chiave di validazione: {validation_key}. Speriamo di vederti presto sul sito!",
            'plain'
        ))
        server = smtplib.SMTP_SSL(':)')
        server.ehlo()
        server.login(':)', ':)')
        server.sendmail(':)', addr, message.as_string())

    @staticmethod
    def detect_mobile():
        agent = request.headers.get('User-Agent')
        phones = ["iphone", "android", "blackberry"]
        return any(phone in agent.lower() for phone in phones)

    @staticmethod
    def device_template_for(template):
        if Utils.detect_mobile():
            return template + '_mob.html'
        return template + '.html'

    @staticmethod
    def hash(password):
        return hashlib.sha3_512(password.encode()).hexdigest()


class Check:
    @staticmethod
    def username(value):
        errors = []
        if len(value) < 3:
            errors.append("L'username deve essere lungo almeno 3 caratteri")
        if db.users.find_one({'username': value}) is not None:
            errors.append("Questo username è già stato preso")
        if '@' in value:
            errors.append("L'username non può contenere @")
        return errors

    @staticmethod
    def email(value):
        errors = []
        if db.users.find_one({'email': value}) is not None:
            errors.append("Questa email è già stata usata")
        return errors

    @staticmethod
    def password(value, confirm_value):
        errors = []
        if value != confirm_value:
            errors.append("Le password non corrispondono")
        if len(value) < 4:
            errors.append("La password deve essere lunga almeno 4 caratteri")
        return errors


@app.route('/style/', methods=['GET'])
def styler():
    return send_file(style_path)


@app.route('/signup/', methods=['POST', 'GET'])
def signup():
    Utils.load_cookies()
    errors = []
    email = ''
    username = ''
    if request.method == 'POST':
        if 'info' in request.form:
            session['info'] = not session['info']
        if 'account' in request.form:
            return redirect(url_for('account', username=session['username']))
        if 'login' in request.form:
            return redirect(url_for('login'))
        if 'signup_sub' in request.form:
            errors += Check.username(request.form['username'])
            errors += Check.email(request.form['email'])
            errors += Check.password(request.form['password'], request.form['confirm_password'])
            if not errors:
                validation_key = ''.join(choices(
                    string.ascii_letters + string.digits,
                    k=32
                ))
                db.users.insert_one({
                    'email': request.form['email'],
                    'username': request.form['username'],
                    'password': Utils.hash(request.form['password']),
                    'validation_key': validation_key,
                    'valid': False
                })

                Utils.send_validation_mail(request.form['email'], validation_key)

                session['username'] = request.form['username']
                session['password'] = request.form['password']
                if 'accept_cookie' in session:
                    if request.form['remember'] and session['accept_cookie']:
                        resp = make_response(redirect(url_for('validation', username=request.form['username'])))
                        resp.set_cookie('username', request.form['username'])
                        resp.set_cookie('password', request.form['password'])
                        return resp
                return redirect(url_for('validation', username=request.form['username']))
            else:
                email = request.form['email']
                username = request.form['username']
        if 'accept_cookie' in request.form:
            session['accept_cookie'] = request.form['accept_cookie']
    return render_template(
        Utils.device_template_for('signup'),
        errors=errors,
        email=email,
        username=username,
        title="Sign Up"
    )


@app.route('/<username>/validation/', methods=['POST', 'GET'])
def validation(username):
    Utils.load_cookies()
    if not Utils.check_account():
        return redirect(url_for('login'))
    if username != session['username']:
        return redirect(url_for('validation', username=session['username']))
    user = db.users.find_one({'username': username})
    if request.method == 'POST':
        if 'info' in request.form:
            session['info'] = not session['info']
        if 'account' in request.form:
            return redirect(url_for('account', username=session['username']))
        if 'login' in request.form:
            return redirect(url_for('login'))
        if 'accept_cookie' in request.form:
            session['accept_cookie'] = request.form['accept_cookie']
        if 'validation_sub' in request.form:
            errors = []
            if user['valid']:
                errors.append("Il tuo account è già valido. Perché sei ancora qui?")
            if request.form['code'] != user['validation_key']:
                errors.append("Sembra che tu abbia inserito una chiave errata.")
            if errors:
                return render_template('validation.html', email=user['email'], valid=user['valid'], errors=errors)
            else:
                db.users.update_one({'username': username}, {'$set': {'valid': True}})
                return redirect(url_for('home', username=username))
    return render_template(
        Utils.device_template_for('validation'),
        email=user['email'],
        valid=user['valid'],
        logged=Utils.check_account(),
        title="Validation Mail"
    )


@app.route('/login/', methods=['POST', 'GET'])
def login():
    Utils.load_cookies()
    if Utils.check_account():
        return redirect(url_for('home'))
    errors = []
    username_email = ''
    if request.method == 'POST':
        if 'info' in request.form:
            session['info'] = not session['info']
        if 'account' in request.form:
            return redirect(url_for('account', username=session['username']))
        if 'login' in request.form:
            return redirect(url_for('login'))
        if 'register' in request.form:
            return redirect(url_for('signup'))
        if 'accept_cookie' in request.form:
            session['accept_cookie'] = request.form['accept_cookie']
        if 'login_sub' in request.form:
            username_email = request.form['username_email']
            errors = []
            if '@' in request.form['username_email']:
                user = db.users.find_one({'email': request.form['username_email']})
                if user is None:
                    errors.append("Sembra che tu abbia inserito un'email errata")
            else:
                user = db.users.find_one({'username': request.form['username_email']})
                if user is None:
                    errors.append("Sembra che tua abbia inserito un username sbagliato")
            if user is not None:
                if Utils.hash(request.form['password']) != user['password']:
                    errors.append("La password inserita sembra errata.")
                else:
                    session['username'] = user['username']
                    session['password'] = request.form['password']
                    if 'accept_cookie' in session:
                        if 'remember' in request.form and session['accept_cookie']:
                            if user['valid']:
                                resp = make_response(redirect(url_for('home')))
                            else:
                                return redirect(url_for('validation', username=user['username']))
                            resp.set_cookie('username', user['username'])
                            resp.set_cookie('password', request.form['password'])
                            return resp
                    if user['valid']:
                        return redirect(url_for('home'))
                    else:
                        return redirect(url_for('validation', username=user['username']))
    return render_template(
        Utils.device_template_for('login'),
        errors=errors,
        logged=Utils.check_account(),
        username_email=username_email,
        title="Log In"
    )


@app.route('/user/<username>/', methods=['POST', 'GET'])
def account(username):
    Utils.load_cookies()
    if not Utils.check_account():
        return redirect(url_for('login'))
    ownership = session['username'] == username
    user = db.users.find_one({'username': username})
    if request.args.get('extend_actions') is not None:
        extend_actions = eval(request.args.get('extend_actions'))
    else:
        extend_actions = False
    errors = []
    if request.method == 'POST':
        if 'info' in request.form:
            session['info'] = not session['info']
        if 'account' in request.form:
            return redirect(url_for('account', username=session['username']))
        if 'accept_cookie' in request.form:
            session['accept_cookie'] = request.form['accept_cookie']
        if 'email_mod' in request.form:
            errors += Check.email(request.form['email'])
        if 'password_mod' in request.form:
            errors += Check.password(request.form['password'], request.form['password'])
        if 'cancel' in request.form:
            del session['actions']
        if 'confirm' in request.form:
            if request.form['password'] == session['password']:
                if 'email' in session['actions']:
                    errors += Check.email(session['actions']['email'])
                    if not errors:
                        validation_key = ''.join(choices(
                            string.ascii_letters + string.digits,
                            k=32
                        ))
                        db.users.update_one(
                            {'username': session['username']},
                            {'$set': {
                                'email': session['actions']['email'],
                                'validation_key': validation_key,
                                'valid': False
                            }}
                        )
                        Utils.send_validation_mail(session['actions']['email'], validation_key)
                        del session['actions']['email']
                        return redirect(url_for('validation', username=session['username']))
                if 'password' in session['actions']:
                    errors += Check.password(session['actions']['password'], session['actions']['password'])
                    if not errors:
                        session['password'] = session['actions']['password']
                        db.users.update_one(
                            {'username': session['username']},
                            {'$set': {
                                'password': Utils.hash(session['actions']['password'])
                            }}
                        )
                        if 'accept_cookie' in session:
                            if session['accept_cookie']:
                                passwd = session['actions']['password']
                                resp = make_response(redirect(url_for('account', username=username)))
                                del session['actions']['password']
                                resp.set_cookie('password', passwd)
                                return resp
                        del session['actions']['password']
            else:
                errors.append('Devi confermare con la password corretta')
        if not errors:
            session['actions'] = {}
            if 'email_mod' in request.form:
                session['actions']['email'] = request.form['email']
            if 'password_mod' in request.form:
                session['actions']['password'] = request.form['password']
    return render_template(
        Utils.device_template_for('account'),
        logged=Utils.check_account(),
        user=user,
        ownership=ownership,
        extend_actions=extend_actions,
        errors=errors,
        title=f"{username} Account"
    )


class Prof:
    def __init__(self, coll):
        self.coll = coll

    def get_age(self):
        today = datetime.date.today()
        birth = datetime.datetime.strptime(self.coll['birth'], '%Y-%m-%d')
        return today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))

    def get_valuation(self):
        summary = 0
        tot = 0
        for review in self.coll['reviews']:
            summary += review['value'] * max(len(review['likes'][0]) - len(review['likes'][1]), 0)
            tot += max(len(review['likes'][0]) - len(review['likes'][1]), 0)
        return round(summary / max(tot, 1), 1)

    def get_color(self):
        colors = ['#B7094C', '#A01A58', '#892B64', '#723C70', '#5C4D7D', '#455E89', '#2E6F95', '#1780A1', '#0091AD']
        return "background-color:" + colors[int((self.get_valuation() - 1) / 4 * 9)] + ";"


@app.route('/', methods=['POST', 'GET'])
def home():
    Utils.load_cookies()
    if request.method == 'POST':
        if 'info' in request.form:
            session['info'] = not session['info']
        if 'account' in request.form:
            return redirect(url_for('account', username=session['username']))
        if 'add_prof' in request.form:
            return redirect(url_for('add_prof'))
        if 'login' in request.form:
            return redirect(url_for('login'))
        if 'accept_cookie' in request.form:
            session['accept_cookie'] = request.form['accept_cookie']
    profs = []
    for prof in db.profs.find():
        prof_ = Prof(prof)
        if prof['valid']:
            profs.append({
                'username': prof['surname'] + ' ' + prof['name'],
                'img_username': prof['surname'] + '_' + prof['name'],
                'age': prof_.get_age(),
                'valuation': prof_.get_valuation(),
                'color': prof_.get_color()
            })
    return render_template(
        Utils.device_template_for('home'),
        logged=Utils.check_account(),
        profs=profs,
        title='Home'
    )


@app.route('/prof/<username>/image/', methods=['GET'])
def prof_image(username):
    files = os.listdir(images_dir)
    for file in files:
        if file.__contains__(username + '.'):
            return send_file(images_dir + file)
    return send_file(images_dir + 'anon.png')


@app.route('/image/<element>/', methods=['GET'])
def element_image(element):
    images = {
        'like': 'like.png',
        'dislike': 'dislike.png',
        'home': 'home.jpg',
        'info': 'info.png',
        'flask': 'flask.png',
        'mongodb': 'mongodb.png'
    }
    return send_file(elements_dir + images[element])


@app.route('/prof/<username>/reviews/', methods=['GET', 'POST'])
def prof_reviews(username):
    Utils.load_cookies()
    surname, name = tuple(username.split('_'))
    prof = db.profs.find_one({'surname': surname, 'name': name})
    reviews = prof['reviews']
    prof_ = Prof(prof)
    info = {
        'birth': prof['birth'],
        'age': prof_.get_age(),
        'color': prof_.get_color(),
        'username': prof['surname'] + ' ' + prof['name'],
        'img_username': prof['surname'] + '_' + prof['name'],
        'valuation': prof_.get_valuation()
    }
    errors = []
    review_popup = False
    if request.method == 'POST':
        if 'info' in request.form:
            session['info'] = not session['info']
        if 'account' in request.form:
            return redirect(url_for('account', username=session['username']))
        if 'accept_cookie' in request.form:
            session['accept_cookie'] = request.form['accept_cookie']
        if 'login' in request.form:
            return redirect(url_for('login'))
        if 'add_review' in request.form:
            if Utils.check_account():
                review_popup = True
            else:
                return redirect(url_for('login'))
        if 'submit_nrev' in request.form:
            if Utils.check_account():
                if not (1 <= int(request.form['value_nrev']) <= 5):
                    errors.append("Devi dare una valutazione compresa tra 1 e 5")
                if len(request.form['text_nrev']) < 32:
                    errors.append("La tua recensione deve essere lunga almeno 32 caratteri")
                if not errors:
                    reviews.append({
                        'committer': session['username'],
                        'time': str(datetime.datetime.now()),
                        'value': int(request.form['value_nrev']),
                        'text': request.form['text_nrev'],
                        'likes': [[session['username']], []]
                    })
                    db.profs.update_one(
                        {'surname': surname, 'name': name},
                        {'$set': {'reviews': reviews}}
                    )
            else:
                return redirect(url_for('login'))
        if 'like' in request.form or 'dislike' in request.form:
            if 'like' in request.form:
                idx = int(request.form['like']) - 1
                o = [0, 1]
            else:
                idx = int(request.form['dislike']) - 1
                o = [1, 0]
            if Utils.check_account():
                if session['username'] in reviews[idx]['likes'][o[0]]:
                    reviews[idx]['likes'][o[0]].remove(session['username'])
                else:
                    reviews[idx]['likes'][o[0]].append(session['username'])
                if session['username'] in reviews[idx]['likes'][o[1]]:
                    reviews[idx]['likes'][o[1]].remove(session['username'])
                db.profs.update_one(
                    {'surname': surname, 'name': name},
                    {'$set': {'reviews': reviews}}
                )
            else:
                return redirect(url_for('login'))
    for i, review in enumerate(reviews):
        reviews[i]['text'] = review['text'].split('\n')
        reviews[i]['clicked'] = [False, False]
        if Utils.check_account():
            reviews[i]['clicked'] = [session['username'] in review['likes'][0],
                                     session['username'] in review['likes'][1]]
        reviews[i]['likes'] = [len(review['likes'][0]), len(review['likes'][1])]
    return render_template(
        Utils.device_template_for('prof'),
        info=info,
        logged=Utils.check_account(),
        review_popup=review_popup,
        errors=errors,
        reviews=reviews,
        title=info['username']
    )


@app.route('/add_prof/', methods=['POST', 'GET'])
def add_prof():
    Utils.load_cookies()
    if not Utils.check_account():
        return redirect(url_for('login'))
    else:
        errors = []
        prof_added = ''
        if request.method == 'POST':
            if 'info' in request.form:
                session['info'] = not session['info']
            if 'account' in request.form:
                return redirect(url_for('account', username=session['username']))
            if 'login' in request.form:
                return redirect(url_for('login'))
            if 'accept_cookie' in request.form:
                session['accept_cookie'] = request.form['accept_cookie']
            if 'add_prof' in request.form:
                if '_' in request.form['name'] or '_' in request.form['surname']:
                    errors.append("Professor's name and surname cannot contain '_'")
                if len(request.form['name']) < 3 or len(request.form['surname']) < 3:
                    errors.append("Professor's name and surname must be at least 3 characters long")
                if 'birth' not in request.form:
                    errors.append("You must insert the date of birth of the professor")
                if not errors:
                    db.profs.insert_one({
                        'surname': request.form['surname'],
                        'name': request.form['name'],
                        'birth': request.form['birth'],
                        'reviews': [],
                        'valid': False
                    })
                    if 'image' in request.files:
                        request.files['image'].save(
                            images_dir + request.form['surname'] + '_' + request.form['name'] + '.jpg'
                        )
                    prof_added = request.form['surname'] + ' ' + request.form['name']
        return render_template(
            Utils.device_template_for('add_prof'),
            errors=errors,
            logged=Utils.check_account(),
            prof_added=prof_added,
            title="Add Prof"
        )


if __name__ == '__main__':
    app.run()
