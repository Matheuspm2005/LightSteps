from flask import current_app, request, redirect, render_template, session, request
from functools import wraps
from itsdangerous import Serializer, URLSafeTimedSerializer #to generate tokens
from flask_mail import Message #used to send emails to the user
import random #to shuffle the options of the quiz

#Render message as an apology to user.
def apology(error, type, code=400):

    #Get the URL from where user was before the error
    back = request.referrer or "/"

    return render_template("apology.html", top=code, bottom= error, type= type, back = back), code

#verify if the user is logged in
def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

#get the username and image to show in the navbar
def informations():
    if not session.get("user_id"):
        return None
    from app import db #to manipulate database
    informations = db.execute("SELECT username, user_image FROM users WHERE id = ?", session.get("user_id"))
    return informations[0]

#generate tokens for users to reset password
def generate_token(identifier):
    serializer = URLSafeTimedSerializer(str(current_app.secret_key))
    token = serializer.dumps(identifier, salt="password_reset_salt")
    return token

#send email with the token and the link to the user
def send_email(to_email, reset_url, mail):
    try:
        msg = Message(subject="Password Reset Request", recipients=[to_email], sender=current_app.config["MAIL_USERNAME"])
        msg.html = render_template("email_reset.html", reset_url=reset_url)
        mail.send(msg)
        print("Função send_email foi chamada")
        return True
    except Exception as e:
        print("Erro ao enviar e-mail:", e)
        return False

#verify if the token is valid
def verify_token(token, max_age=900):
    serializer = URLSafeTimedSerializer(str(current_app.secret_key))
    try:
        email = serializer.loads(token, salt="password_reset_salt", max_age=max_age)
        return email
    except:
        return None
    
#make a list grouping the options with the questions
def questions_list(quiz_questions):
    questions_dict = {}

    if not quiz_questions:
        return []

    
    for question in quiz_questions:
        #check whether is a new question
        if question["question_id"] not in questions_dict:

            questions_dict[question["question_id"]] = {
                "id": question["question_id"],
                "question": question["question"],
                "number": question["question_number"],
                "options": [] #create a list to allocate the options
            }

        questions_dict[question["question_id"]]["options"].append({
            "id": question["option_id"],
            "option": question["option"],
            "is_correct": question["is_correct"]
        })
    
    for question in questions_dict.values():
        random.shuffle(question["options"])

    return list(questions_dict.values())
