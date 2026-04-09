from json import load
from operator import truth
import os #operational system
from datetime import datetime, timedelta #to apply time for functions

from re import error
from sqlite3 import IntegrityError
from turtle import right #to deal with database errors
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, render_template_string, request, session, current_app, url_for
from flask_mail import Mail
from flask_session import Session
from sqlalchemy import Null, exists, null
from werkzeug.security import check_password_hash, generate_password_hash #used to generate and check encrypted passwords
from email_validator import validate_email, EmailNotValidError 
from dotenv import load_dotenv 

from helpers import apology, login_required, informations, generate_token, send_email, verify_token, questions_list #local library that contains essential functions

#Config App
app = Flask(__name__)

#strong secret key
app.secret_key = os.urandom(24)

#Session using filesystem and not being permanent
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

#Config app to send emails
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config['MAIL_USERNAME'] = load_dotenv("EMAIL_USER")
app.config['MAIL_PASSWORD'] = load_dotenv("EMAIL_PASS")
app.config['MAIL_DEFAULT_SENDER'] = load_dotenv("EMAIL_USER")

mail = Mail(app)

#define database
db = SQL("sqlite:///new.db")

#clean cache
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

#index section
@app.route("/")
@login_required
def dashboard():
    #select informations
    user = session.get("user_id")
    active_plans = db.execute("SELECT COUNT (*) AS total FROM user_plans WHERE user_id = ? AND completed = ?", user, False)[0]["total"]
    completed_plans = db.execute("SELECT COUNT (*) AS total FROM plans_history WHERE user_id = ? AND operation = ?", user, "completed")[0]["total"]
    incompleted_quizzes = db.execute("SELECT COUNT (*) AS total FROM user_quizzes_results WHERE user_id = ? AND completed = ? AND completed_questions > ?", user, False, 0)[0]["total"]
    completed_quizzes = db.execute("SELECT COUNT (*) AS total FROM user_quizzes_results WHERE user_id = ? AND completed = ?", user, True)[0]["total"]
    plans = db.execute("SELECT user.completed_parts, plans.name, plans.parts FROM user_plans AS user JOIN reading_plans AS plans ON user.plan_id = plans.id WHERE user.user_id = ?", user)
    plans_list = []
    #calculate how much the user has completed of the plan
    for plan in plans:
        plan_data = {
            "name": plan["name"],
            "percentage": round((plan["completed_parts"]*100)/plan["parts"])
        }
        plans_list.append(plan_data)
    #get the data to make the chart of correct and incorrect answers of the quiz
    right_answers = db.execute("SELECT SUM (right_answers) AS total FROM user_quizzes_results WHERE user_id = ?", user)[0]["total"] or 0
    total_answers = db.execute("SELECT SUM (completed_questions) AS total FROM user_quizzes_results WHERE user_id = ?", user)[0]["total"] or 0

    wrong_answers = total_answers - right_answers
    streak = db.execute("SELECT quiz_streak FROM users WHERE id = ?", user)[0]["quiz_streak"]

    return render_template("index.html", active_plans=active_plans, completed_plans=completed_plans, incompleted_quizzes=incompleted_quizzes, completed_quizzes=completed_quizzes, plans=plans_list, right=right_answers, wrong=wrong_answers, total_answers=total_answers, streak=streak)

#login section
@app.route("/login", methods=["GET", "POST"])
def login():

    #forget any user_id
    session.clear()

    #if the form was submitted by the user
    if request.method == "POST":
        identifier = request.form.get("identifier")
        password = request.form.get("password")

        if not identifier or not password:
            return apology("Invalid data", "Please fill all the gaps")
        
        #seeing if the identifier is an email or an username, after that looking for the user
        if "@" in identifier:
            verification = db.execute("SELECT * FROM users WHERE email = ?", identifier)
        else:
            verification = db.execute("SELECT * FROM users WHERE username = ?", identifier)

        #checking wether the username and password match
        if len(verification) != 1 or not check_password_hash(verification[0]["hash"], password):
            return apology("Invalid data", "Passwords don't match")
         
        #remember the user
        session["user_id"] = verification[0]["id"]

        #if the checkbox "Remember me" is marked, enable the session to be permanent for 30 days
        remember = request.form.get("remember")
        if remember == "on":
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=30)

        return redirect("/")
    
    #if the user entered the site
    else:
        return render_template("login.html")

#logout section
@app.route("/logout")
def logout():
    #forget any user_id
    session.clear()

    #redirect user
    return redirect("/login")

#register section
@app.route("/register", methods=["GET", "POST"])
def register():

    #if the form was submitted by the user
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        #assert that all the data is not none
        if not all([username, email, password, confirmation]):
            return apology("Invalid data", "please fill all the gaps")
        assert username and email and password and confirmation is not None

        #ensure that the username is not an email
        if "@" in username:
            return apology("Invalid data", "Don't use @ in username")
        
        if password != confirmation:
            return apology("Invalid data", "Password and confirmation don't match")
        
        #valid email?
        try:
            valid = validate_email(email, check_deliverability=True)
            email = valid.email
        except EmailNotValidError:
            return apology("invalid data", "invalid email")
        
        #check if user was already registered
        if db.execute("SELECT * FROM users WHERE username = ?", username):
            return apology("Invalid data", "username already exists")
        if db.execute("SELECT * FROM users WHERE email = ?", email):
            return apology("Invalid data", "email already registered")

        #registrate user
        try:
            db.execute("INSERT INTO users (username, email, hash) VALUES (?, ?, ?)", username, email, generate_password_hash(password))
            return redirect('/')
        except IntegrityError as error:
            error_msg = str(error)
            if "username" in error_msg:
                return apology("Invalid data", "username already exists")
            elif "email" in error_msg:
                return apology("Invalid data", "email already registered")
            else:
                return apology("Error", "fail to register the user")

    #if the user entered the site
    else:
        return render_template("register.html")
    
#forgot password section
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    
    if request.method == "POST":
        identifier = request.form.get("email")
        if not identifier:
            return apology("Invalid data", "Must contain email")
        
        user = db.execute("SELECT * FROM users WHERE email = ?", identifier)
        if not user:
            return apology("Invalid data", "user not found")
        print("Enviando email para:", identifier)
        #generates token and sends the email
        try:
            token = generate_token(identifier)
            reset_url = url_for("reset_password", token=token, _external=True)
        except:
            return apology("Error", "error in token")
        
        if send_email(identifier, reset_url, mail):
            flash("email sent successfully", "success")
        else:
            return apology("Email", "Failed to send email")
        return redirect("/login")
    else:
        return render_template("forgot_password.html")
        
#reset the user_password, gets to the site by the link sent to email
@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):

    #check if the password is valid or not
    email = verify_token(token)
    if not email:
        return redirect("/login")
    
    if request.method == "POST":

        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        if not new_password or not confirmation:
            return apology("Invalid data", "fill all the gaps")
        if new_password != confirmation:
            return apology("Invalid data", "fields don't match")
        
        db.execute("UPDATE users SET hash = ? WHERE email = ?", generate_password_hash(new_password), email)

        flash("password updated succssfully", "success")
        print("resetada")
        return redirect("/login")
    
    else:
        return render_template("reset_password.html", token=token)
    
#change user password section
@app.route("/my_account", methods=["GET", "POST"])
def change():

    #if the form was submitted by the user
    if request.method == "POST":
        user = session.get("user_id")
        type = request.form.get("submit_type")
        if type == "change_password":
            old_password = request.form.get("old_password")
            new_password = request.form.get("new_password")
            confirmation = request.form.get("confirmation")

            if not all([old_password, new_password, confirmation]):
                return apology("Invalid data", "Please fill all the gaps")
            assert old_password and new_password and confirmation is not None

            verification = db.execute("SELECT hash FROM users WHERE id = ?", user)

            if not check_password_hash(verification[0]["hash"], old_password):
                return apology("Invalid data", "Wrong password")
            
            #set new password in the database
            db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_password), user)
        
        elif type == "change_username":
            username = request.form.get("username")
            if not username:
                return apology("Invalid data", "Please fill all the gaps")
            #set new username in the database
            db.execute("UPDATE users SET username = ? WHERE id = ?", username, user)
        return redirect("/my_account")
            
            
    #if the user entered the site
    else:
        return render_template("my_account.html")

#show reading plans to guide the user
@app.route("/plans", methods=["GET", "POST"])
@login_required
def plans():
    user = session.get("user_id")
    if request.method == "POST":
        
        plan_id = request.form.get("plan_id")
        try:
            db.execute("INSERT INTO user_plans (user_id, plan_id) VALUES (?, ?)", user, plan_id)
            db.execute("INSERT INTO plans_history (user_id, operation, plan_id) VALUES (?, ?, ?)", user, "started", plan_id)
            return redirect("/plans")
        except Exception as e:
            return apology("error", str(e))


    else:

        #separate the plans
        plans = db.execute("SELECT * FROM reading_plans WHERE id NOT IN (SELECT plan_id FROM user_plans WHERE user_id = ?)", user)
        all_plans = [plan for plan in plans if "Whole" in plan["name"]]
        old_test_plans = [plan for plan in plans if "Old" in plan["name"]]
        new_test_plans = [plan for plan in plans if "New" in plan["name"]]
        general_plans = [plan for plan in plans if all(name not in plan["name"] for name in ["Old", "New", "Whole"])]
        return render_template("plans.html", all_plans=all_plans, old_test_plans=old_test_plans, new_test_plans=new_test_plans, general_plans=general_plans)

@app.route("/my_plans", methods=["GET", "POST"])
@login_required
def my_plans():
    user = session.get("user_id")
    if request.method == "POST":
        #identify whether the user want to delete a plan or mark "ok" on a part of the plan
        type = request.form.get("submit_type")

        plan_id = request.form.get("plan_id")

        if type == "ok":
            part_id = request.form.get("part_id")

            exists = db.execute("SELECT 1 FROM reading_parts WHERE id = ? AND plan_id = ?", part_id, plan_id)
            if not exists:
                return apology("Invalid data", "Try again")

            db.execute("INSERT INTO parts_history (user_id, part_id, plan_id) VALUES (?, ?, ?)", user, part_id, plan_id)
            db.execute("UPDATE user_plans SET completed_parts = completed_parts + 1 WHERE user_id = ? AND plan_id = ?", user, plan_id)
            
            #check whether the user completed all the parts of the plan
            parts = db.execute("SELECT parts FROM reading_plans WHERE id = ?", plan_id)[0]["parts"]
            completed_parts = db.execute("SELECT completed_parts FROM user_plans WHERE user_id = ? AND plan_id = ?", user, plan_id)[0]["completed_parts"]
            if parts == completed_parts:
                db.execute("INSERT INTO plans_history (user_id, operation, plan_id) VALUES (?, ?, ?)", user, "completed", plan_id)
                db.execute("UPDATE user_plans SET completed = ? WHERE user_id = ? AND plan_id = ?", True, user, plan_id)
        
        elif type == "delete":
            db.execute("DELETE FROM user_plans WHERE user_id = ? AND plan_id = ?", user, plan_id)
            db.execute("INSERT INTO plans_history (user_id, operation, plan_id) VALUES (?, ?, ?)", user, "deleted", plan_id)
        return redirect("/my_plans")
    else:
        user_plans = db.execute("SELECT user_plans.plan_id, reading_plans.name, reading_plans.description, reading_plans.duration FROM reading_plans JOIN user_plans ON reading_plans.id=user_plans.plan_id WHERE user_plans.user_id = ? AND user_plans.completed = ?", user, False)
        parts_not_completed = db.execute("SELECT * FROM reading_parts where id NOT IN( SELECT part_id FROM parts_history WHERE user_id = ?)", user)
        return render_template("my_plans.html", user_plans=user_plans, parts=parts_not_completed)

#show history of the user
@app.route("/history")
@login_required
def history():
    user = session.get("user_id")
    parts_history = db.execute("SELECT reading_plans.name AS plan_name, reading_parts.name, parts_history.time FROM parts_history JOIN reading_plans ON parts_history.plan_id=reading_plans.id JOIN reading_parts ON parts_history.part_id=reading_parts.id WHERE user_id = ?", user)
    plans_history = db.execute("SELECT * FROM plans_history JOIN reading_plans ON plans_history.plan_id=reading_plans.id WHERE plans_history.user_id = ?", user)
    return render_template("history.html", parts=parts_history, plans=plans_history)

#quiz section
@app.route("/quiz", methods=["GET", "POST"])
@login_required
def quiz():
    user = session.get("user_id")
    if request.method == "POST":
        type = request.form.get("submit_type")
        quiz_id = request.form.get("quiz_id")

        exists = db.execute("SELECT 1 FROM quizzes WHERE id = ?", quiz_id)
        if not exists:
            return apology("Error", "Quiz doesn't exists")
                
        if type == "start":
            db.execute("INSERT INTO user_quizzes_results (user_id, quiz_id) VALUES (?, ?)", user, quiz_id)
            db.execute("INSERT INTO user_questions_results (user_id, quiz_id, question_id) SELECT ?, ?, id FROM quiz_questions WHERE quiz_id = ?", user, quiz_id, quiz_id)
        if type == "restart":
            db.execute("UPDATE user_quizzes_results SET completed = ?, completed_questions = ?, right_answers = ? WHERE user_id = ? AND quiz_id = ?", False, 0, 0, user, quiz_id)
            db.execute("UPDATE user_questions_results SET completed = ? WHERE user_id = ? AND quiz_id = ?", False, user, quiz_id)
        if type not in ["start", "restart", "continue"]:
            return apology("Error", "Submission type not valid")
        return redirect(url_for("questions", type=type, quiz_id=quiz_id))
    else:
        quizzes = db.execute("SELECT DISTINCT quizzes.id, quizzes.book, quizzes.total_questions, COALESCE(user_quizzes_results.completed, 0) AS completed, COALESCE(user_quizzes_results.completed_questions, 0) AS completed_questions FROM quizzes LEFT JOIN user_quizzes_results ON quizzes.id=user_quizzes_results.quiz_id AND user_quizzes_results.user_id = ?", user)

        return render_template("quiz.html", quizzes=quizzes)
    
#show questions of the quiz
@app.route("/questions", methods=["GET", "POST"])
@login_required
def questions():
    user = session.get("user_id")
    
    if request.method == "GET":
        type = request.args.get("type")
        quiz_id = request.args.get("quiz_id")
        exists = db.execute("SELECT 1 FROM quizzes WHERE id = ?", quiz_id)
        if not exists:
            return apology("Error", "Quiz doesn't exists")
        quiz_name = db.execute("SELECT book FROM quizzes WHERE id = ?", quiz_id)[0]["book"]
        if type in ["start", "continue"]:

            quiz_questions = db.execute("SELECT DISTINCT quiz_questions.id AS question_id, quiz_questions.question, quiz_questions.question_number, quiz_options.id AS option_id, quiz_options.option, quiz_options.is_correct FROM quiz_questions JOIN quiz_options ON quiz_questions.id = quiz_options.question_id JOIN user_questions_results AS results ON quiz_questions.id = results.question_id WHERE results.user_id = ? AND results.completed = ? AND quiz_questions.quiz_id = ? ORDER BY quiz_questions.id, quiz_options.id", user, False, quiz_id)


        elif type == "restart":

            quiz_questions = db.execute("SELECT DISTINCT questions.id AS question_id, questions.question, options.id AS option_id, options.option, options.is_correct FROM quiz_questions AS questions JOIN quiz_options AS options ON questions.id=options.question_id WHERE questions.quiz_id = ? ORDER BY questions.id, options.id", quiz_id)

        else:
            return apology("Error", "Type not valid")

        questions = questions_list(quiz_questions)
        
        return render_template("questions.html", questions=questions, quiz_name=quiz_name, quiz_id=quiz_id)
    else:
        quiz_id = request.form.get("quiz_id")
        answer = request.form.get("answer")
        question_id = request.form.get("question_id")
        db.execute("UPDATE user_questions_results SET completed = ? WHERE question_id = ? AND user_id = ? AND quiz_id = ?", True, question_id, user, quiz_id)
        if answer == "1":
            db.execute("UPDATE user_quizzes_results SET completed_questions = completed_questions + 1, right_answers = right_answers + 1 WHERE user_id = ? AND quiz_id = ?", user, quiz_id)
            db.execute("UPDATE users SET quiz_streak = quiz_streak + 1 WHERE id = ?", user) 
        elif answer == "0":
            db.execute("UPDATE user_quizzes_results SET completed_questions = completed_questions + 1 WHERE user_id = ? AND quiz_id = ?", user, quiz_id)
            db.execute("UPDATE users SET quiz_streak = ? WHERE id = ?", 0, user) 

        total_questions = db.execute("SELECT total_questions FROM quizzes WHERE id =?", quiz_id)[0]["total_questions"]
        completed_questions = db.execute("SELECT completed_questions FROM user_quizzes_results WHERE user_id = ? AND quiz_id = ?", user, quiz_id)[0]["completed_questions"]
        if total_questions == completed_questions:
            db.execute("UPDATE user_quizzes_results SET completed = ? WHERE user_id = ? AND quiz_id = ?", True, user, quiz_id)
        return "", 204


#return information of the user to the navbar
@app.context_processor
def user_information():
    return dict(informations=informations())

#enable debugger
if __name__ == "__main__":
    app.run(debug=True)