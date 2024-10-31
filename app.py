import threading
import cv2
from deepface import DeepFace

import os

import time
import pyotp

import smtplib

from datetime import datetime,timedelta
from cs50 import SQL
from flask import Flask, flash, redirect, jsonify, render_template, request, session, Response, g, url_for
from flask_session import Session
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
import uuid

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Custom filter

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///OQTrainAndAssess.db")
db.execute("PRAGMA foreign_keys = ON")

app.secret_key = 'hello'

csrf = CSRFProtect(app)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    question_sets = db.execute(
        "SELECT * FROM question_sets WHERE set_type = 'train' OR set_type = 'assess'"
        )

    return render_template("index.html", question_sets = question_sets)


@app.route("/executeset", methods=["POST"])
@login_required
def executeSet():
    """Show portfolio of stocks"""
    if request.method == "POST":
        question_set_id = request.form.get("question_set_id")

        question_set = db.execute(
            "SELECT * FROM questions WHERE question_set_id = ?", question_set_id
        )
        
        set_info = db.execute(
            "SELECT question_set_id, title, duration FROM question_sets WHERE question_set_id = ?", question_set_id
        )

        set_duration = int(set_info[0]["duration"])
        set_title = set_info[0]["title"]
        set_id = set_info[0]["question_set_id"]
        user_timer = db.execute("SELECT expiration_time, question_set_id FROM user_timers WHERE user_id = ?", session["user_id"])

        if not user_timer[0]['question_set_id']:
            expiration_time = datetime.now() + timedelta(minutes=set_duration)
            db.execute("UPDATE user_timers SET expiration_time = ?, question_set_id = ? WHERE user_id = ?", 
                       expiration_time.isoformat(), set_id, session["user_id"])
        elif user_timer[0]['question_set_id'] == set_id:
            return render_template("executeset.html", question_set = question_set, 
                        set_duration = set_duration, set_title = set_title,
                        set_id = set_id)
        else:
            flash("A question set is still running, please submit it!")
            return redirect("/")

        return render_template("executeset.html", question_set = question_set, 
                               set_duration = set_duration, set_title = set_title,
                               set_id = set_id)


@app.route("/addquestionset", methods=["GET", "POST"])
@login_required
def addQuestionSet():
    """Buy shares of stock"""

    if request.method == "POST":
        title = request.form.get("title")
        total_question = request.form.get("total_question")
        total_score = request.form.get("total_score")
        duration = request.form.get("duration")
        set_type = request.form.get("set_type")

        if not title:
            return apology("must provide title")
        if not total_question:
            return apology("must provide total question")
        if not total_score:
            return apology("must provide total total_score")
        if not duration:
            return apology("must provide total duration")
        if not total_question.isdigit():
            return apology("num of total question not valid")
        if not total_score.isdigit():
            return apology("num of total score not valid")
        if not duration.isdigit():
            return apology("num of duration not valid")

        total_question = int(total_question)
        total_score = float(total_score)
        duration = int(duration)

        if total_question <= 0:
            return apology("num of total question not valid")
        if total_score <= 0:
            return apology("num of total score not valid")
        if duration <= 0:
            return apology("num of duration not valid")
        
        db.execute(
            "INSERT INTO question_sets (title, total_question, total_score, duration, set_type, user_id) \
            VALUES (?, ?, ?, ?, ?, ?)",
            title,
            total_question,
            total_score,
            duration,
            set_type,
            session["user_id"]
        )

        flash("Question set adding completed successfully!")

        return redirect("/")

    return render_template("addquestionset.html")


@app.route("/attemptshistory", methods=["GET", "POST"])
@login_required
def attemptsHistory():
    """Show history of transactions"""
    if request.method == "POST":
        title = request.form.get("title")
        score = request.form.get("score")
        duration = request.form.get("duration")
        question_set_id = request.form.get("question_set_id")

        db.execute(
            "INSERT INTO attempts_history (title, score, duration, question_set_id, user_id) \
            VALUES (?, ?, ?, ?, ?)",
            title,
            score,
            duration,
            question_set_id,
            session["user_id"]
        )

        user_id = session["user_id"]
        attempts_history = db.execute("\
            SELECT \
                ah.attempt_id,\
                ah.title AS attempt_title,\
                ah.score,\
                ah.duration AS attempt_duration,\
                ah.date_created,\
                qs.question_set_id,\
                qs.title AS question_set_title,\
                qs.total_question,\
                qs.total_score,\
                qs.duration AS set_duration,\
                qs.user_id AS question_set_owner_id,\
                ah.user_id AS attempt_user_id\
            FROM \
                attempts_history AS ah\
            JOIN\
                question_sets AS qs \
            ON \
                ah.question_set_id = qs.question_set_id\
            WHERE\
                ah.user_id = ? OR qs.user_id = ?\
            ORDER BY\
                ah.date_created DESC;\
        ", user_id, user_id)

        db.execute("UPDATE user_timers SET expiration_time = NULL, question_set_id = NULL WHERE user_id = ?", session["user_id"])
        
        return render_template("attemptshistory.html", attempts_history = attempts_history)
    
    user_id = session["user_id"]
    attempts_history = db.execute("\
        SELECT \
            ah.attempt_id, \
            ah.title AS attempt_title, \
            ah.score,\
            ah.duration AS attempt_duration,\
            ah.date_created,\
            qs.question_set_id,\
            qs.title AS question_set_title,\
            qs.total_question,\
            qs.total_score,\
            qs.duration AS set_duration,\
            qs.user_id AS question_set_owner_id,\
            ah.user_id AS attempt_user_id\
        FROM\
            attempts_history AS ah\
        JOIN \
            question_sets AS qs \
        ON \
            ah.question_set_id = qs.question_set_id\
        WHERE \
            ah.user_id = ? OR qs.user_id = ?\
        ORDER BY \
            ah.date_created DESC;", user_id, user_id)


    return render_template("attemptshistory.html", attempts_history = attempts_history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            return apology("must provide username")

        # Ensure password was submitted
        if not password:
            return apology("must provide password")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", username
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], password
        ):
            return apology("invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["face_check"] = False
        session['otp_check'] = False

        # Redirect user to home page
        return redirect("/facecheck")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    db.execute("UPDATE user_authentications SET face_status = 'False' WHERE user_id = ?", session["user_id"])
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username")
        if not password:
            return apology("must provide password")
        if not confirmation:
            return apology("must confirm password")
        if password != confirmation:
            return apology("password and confirmation do not match")

        existing_users = db.execute(
            "SELECT id FROM users WHERE username = ?", username
        )

        if len(existing_users) >= 1:
            return apology("Username already exists")

        password_hash = generate_password_hash(password)
        user_type = "member"

        db.execute(
            "INSERT INTO users (username, hash, user_type) VALUES (?, ?, ?)", username, password_hash, user_type
        )

        user_id = db.execute(
            "SELECT id FROM users WHERE username = ?", username
        )

        user_id = user_id[0]['id']
        otp_secret = pyotp.random_base32()

        db.execute(
            "INSERT INTO user_timers (expiration_time, question_set_id, user_id) VALUES (NULL, NULL, ?)", user_id
        )

        db.execute(
            "INSERT INTO user_authentications (face_status, code_status, user_id) VALUES ('False', ?, ?)", otp_secret, user_id
        )

        return redirect(url_for('takeIndex', username=username))

    return render_template("register.html")


@app.route("/addquestion", methods=["GET", "POST"])
@login_required
def addQuestion():
    """Add cash to account"""

    if request.method == "POST":
        question_set_id = request.form.get("question_set_id")
        question = request.form.get("question")
        question_type = request.form.get("question_type")
        option_one = request.form.get("option_one")
        option_two = request.form.get("option_two")
        option_three = request.form.get("option_three")
        option_four = request.form.get("option_four")
        right_option = request.form.get("right_option")
        score = request.form.get("score")

        if question_type == "multiple choice":
            db.execute(
                "INSERT INTO questions (question, option_one, option_two, \
                option_three, option_four, right_option, question_type, score, question_set_id) \
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                question,
                option_one,
                option_two,
                option_three,
                option_four,
                right_option,
                question_type,
                score,
                question_set_id
            )
        else:
            return redirect("/addquestion")

        flash("Question adding completed successfully!")

        return redirect("/addquestion")

    return render_template("addQuestion.html")


@app.route("/deleteset", methods=["GET", "POST"])
@login_required
def deleteQuestionSet():

    if request.method == "POST":
        question_set_id = request.form.get("question_set_id")
        questions = db.execute("SELECT * FROM questions WHERE question_set_id = ?", question_set_id)
        if questions is not None:
            db.execute("DELETE FROM questions WHERE question_set_id = ?", question_set_id)
        db.execute("DELETE FROM question_sets WHERE question_set_id = ?", question_set_id)

        flash("Set deleting completed successfully!")

        return redirect("/")

    question_sets = db.execute(
        "SELECT * FROM question_sets WHERE user_id = ?", session["user_id"]
        )
    

    return render_template("deletequestionset.html", question_sets=question_sets)


@app.route('/time')
def homeTime():
    return render_template('home.html')


def get_remaining_time_in_seconds():
    expiration_time = db.execute("SELECT expiration_time FROM user_timers WHERE user_id = ?", session["user_id"])
    expiration_time = datetime.fromisoformat(expiration_time[0]['expiration_time'])
    remaining_time = expiration_time - datetime.now()
    remaining_time_in_seconds = remaining_time.total_seconds()
    return remaining_time_in_seconds


@app.route('/remaining_time')
def remaining_time():
    remaining_time_in_seconds = get_remaining_time_in_seconds()
    return jsonify({'remaining_time_in_seconds': remaining_time_in_seconds})


@app.route('/reset', methods=['POST'])
def reset():
    if request.method == 'POST':
        app.config['expiration_time'] = datetime.now() + timedelta(minutes=10)
        return render_template('home.html')


@app.route("/deletequestion", methods=["GET", "POST"])
@login_required
def deleteQuestion():

    if request.method == "POST":
        question_set_id = request.form.get("question_set_id")

        questions = db.execute(
            "SELECT * FROM questions WHERE question_set_id = ?", question_set_id
        )

        return render_template("deletequestion.html", questions=questions)


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():

    if request.method == "POST":
        question_id = request.form.get("question_id")
        question_set_id = request.form.get("question_set_id")

        questions = db.execute(
            "DELETE FROM questions WHERE question_id = ?", question_id
            )

        flash("Question deleting completed successfully!")

        return redirect("/deleteset")


@app.route('/take',  methods=["GET", "POST"])
def takeIndex():
    username = request.args.get('username')
    return render_template('upload.html', username=username)


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part'
    
    file = request.files['file']
    
    if file.filename == '':
        return 'No selected file'
    
    full_name = request.form.get("full_name")
    date_of_birth = request.form.get("date_of_birth")
    identification = request.form.get("identification")
    gmail = request.form.get("gmail")
    username = request.form.get("username")
    user_id = db.execute("SELECT id FROM users WHERE username = ?", username)
    user_id = user_id[0]["id"]
    face_image = f"uploads/{user_id}.jpg"

    db.execute(
        "INSERT INTO user_info (full_name, date_of_birth, identification, gmail, face_image, user_id) \
        VALUES (?, ?, ?, ?, ?, ?)",
        full_name,
        date_of_birth,
        identification,
        gmail,
        face_image,
        user_id
    )
    
    if file and file.filename.endswith('.jpg'):
        # Generate a new unique filename with UUID
        new_filename = f"{user_id}.jpg"
        file.save(os.path.join('uploads', new_filename))  # Save the file with the new name
        return f'File uploaded successfully as {new_filename}'
    
    return 'Invalid file format'


def generate_frames(user_id):
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

    counter = 0
    face_match = False
    reference_img = cv2.imread(f"uploads/{user_id}.jpg")

    def check_face(frame):
        nonlocal face_match
        try:
            if DeepFace.verify(frame, reference_img.copy())['verified']:
                face_match = True
            else:
                face_match = False
        except ValueError:
            face_match = False

    while True:
        ret, frame = cap.read()

        if not ret:
            break

        if counter % 30 == 0:
            try:
                threading.Thread(target=check_face, args=(frame.copy(),)).start()
            except ValueError:
                pass

        counter += 1

        if face_match:
            cv2.putText(frame, "MATCH!", (20, 450), cv2.FONT_HERSHEY_SIMPLEX, 2, (0, 255, 0), 3)
            face_status = db.execute("SELECT face_status FROM user_authentications WHERE user_id = ?", user_id)
            if face_status[0]["face_status"] == "False":
                db.execute("UPDATE user_authentications SET face_status = 'True' WHERE user_id = ?", user_id)
        else:
            cv2.putText(frame, "NO MATCH!", (20, 450), cv2.FONT_HERSHEY_SIMPLEX, 2, (0, 0, 255), 3)

        # Encode the frame in JPEG format
        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()

        # Yield the frame in byte format as part of a multipart response
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    cap.release()
    

@app.route('/facecheck')
def faceCheck():
    # Renders the HTML page
    return render_template('facecheck.html')


@app.route('/video_feed')
def video_feed():
    # Return the response generated by the frame generator
    user_id = session.get('user_id')
    return Response(generate_frames(user_id), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/facecheckverify', methods=["GET"])
def faceCheckVerify():
    # Renders the HTML page
    face_status = db.execute("SELECT face_status FROM user_authentications WHERE user_id = ?", session["user_id"])
    if face_status[0]["face_status"] == 'True':
        session["face_check"] = True
        return redirect("/otpcheck")
    return redirect("/facecheck")


@app.route("/otpcheck", methods=["GET", "POST"])
def otpCheck():
    # Get user ID from session
    user_id = session.get("user_id")

    # Handle POST request (OTP verification)
    if request.method == "POST":
        expiration_time = session["otp_timer"]
        remaining_time = expiration_time - datetime.now()
        if remaining_time.total_seconds() <= 0:
            redirect("/otpcheck")
        otp_user = request.form.get("otp")
        if otp_user == session["otp_temp"]:
            session['otp_check'] = True
            return redirect("/")
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return render_template('otpcheck.html')

    # Generate OTP code and send email in GET request
    key = db.execute("SELECT code_status FROM user_authentications WHERE user_id = ?", user_id)
    key = key[0]["code_status"]
    totp = pyotp.TOTP(key)
    otp_code = totp.now()  # Generate the OTP code
    session["otp_temp"] = otp_code
    # Retrieve the user's email
    email_sent = db.execute("SELECT gmail FROM user_info WHERE user_id = ?", user_id)
    recipient_email = email_sent[0]['gmail']
    sender_email = 'cybertestcybertest111@gmail.com'
    sender_password = 'qujhjnxdwvxlbqgl'

    # Set up email headers and content
    subject = "Your OTP Code"
    mail_content = f"Subject: {subject}\n\nYour OTP code is: {otp_code}"

    # Send the email
    with smtplib.SMTP('smtp.gmail.com', 587) as temp:
        temp.starttls()
        temp.login(sender_email, sender_password)
        temp.sendmail(sender_email, recipient_email, mail_content)
        temp.quit()

    session["otp_timer"] = datetime.now() + timedelta(seconds=30)

    return render_template('otpcheck.html')


