from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# In-memory SQLite database
conn = sqlite3.connect(':memory:', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
c.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
conn.commit()

@app.route('/')
def index():
    return render_template_string('''
        <h1>Vulnerable Web Application</h1>
        <form action="/login" method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        <br>
        <h2>Try some pen testing!</h2>
    ''')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Vulnerable SQL Injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    c.execute(query)
    user = c.fetchone()
    
    if user:
        return f"Welcome, {username}!"
    else:
        return "Invalid credentials!"

@app.route('/xss', methods=['GET'])
def xss():
    return render_template_string('''
        <h1>Test XSS</h1>
        <form action="/xss" method="POST">
            <label for="message">Enter a message:</label><br>
            <input type="text" id="message" name="message"><br>
            <input type="submit" value="Submit">
        </form>
    ''')

@app.route('/xss', methods=['POST'])
def xss_post():
    message = request.form['message']
    # This is vulnerable to reflected XSS
    return f"<h1>Your message: {message}</h1>"

if __name__ == '__main__':
    app.run(debug=True)
@app.route('/profile/<int:user_id>')
def profile(user_id):
    # Insecure Direct Object Reference
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    if user:
        return f"Profile of {user[1]}"  # Display user details
    else:
        return "User not found!"
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        # Assume this changes the password without proper verification
        return f"Password changed to {new_password}."
    return '''
        <h1>Change Password</h1>
        <form action="/change-password" method="POST">
            New Password: <input type="password" name="new_password"><br>
            <input type="submit" value="Change Password">
        </form>
    '''
import os

@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        ip_address = request.form['ip']
        # Vulnerable to command injection
        result = os.popen(f'ping -c 4 {ip_address}').read()
        return f"<pre>{result}</pre>"
    return '''
        <h1>Ping a server</h1>
        <form action="/ping" method="POST">
            IP Address: <input type="text" name="ip"><br>
            <input type="submit" value="Ping">
        </form>
    '''
from werkzeug.utils import secure_filename
import os

app.config['UPLOAD_FOLDER'] = './uploads'

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return "File uploaded successfully!"
    return '''
        <h1>Upload a file</h1>
        <form action="/upload" method="POST" enctype="multipart/form-data">
            File: <input type="file" name="file"><br>
            <input type="submit" value="Upload">
        </form>
    '''
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Store password in plaintext (not secure)
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    return "User added successfully!"