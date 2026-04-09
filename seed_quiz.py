from cs50 import SQL
import random

db = SQL("sqlite:///new.db")  # coloca o nome do seu banco aqui

def insert_question(quiz_id, question, number, options):
    random.shuffle(options)
    q_id = db.execute(
        "INSERT INTO quiz_questions (quiz_id, question, question_number) VALUES (?, ?, ?)",
        quiz_id, question, number
    )

    for option_text, is_correct in options:
        db.execute(
            "INSERT INTO quiz_options (question_id, option, is_correct) VALUES (?, ?, ?)",
            q_id, option_text, is_correct
        )
    