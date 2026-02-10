from flask import Flask, request, session
import sqlite3

app = Flask(__name__)
app.secret_key = "weak_key"

def get_db():
    return sqlite3.connect("users.db")

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = get_db()
    cursor = conn.cursor()

    # Vulnerable code (SQL Injection)
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        session['user'] = username
        return "Login successful"
    else:
        return "Invalid credentials"

if __name__ == '__main__':
    app.run(debug=True)

