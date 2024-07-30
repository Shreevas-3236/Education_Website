from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a real secret key
bcrypt = Bcrypt(app)

# In-memory user storage (replace with a database in production)
users = {}

@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = users.get(username)
        
        if hashed_password and bcrypt.check_password_hash(hashed_password, password):
            session['username'] = username
            return redirect(url_for('home'))
        return 'Invalid username or password.'
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return 'Username already exists.'
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users[username] = hashed_password
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        if new_password != confirm_new_password:
            return 'Passwords do not match.'
        
        if username in users:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            users[username] = hashed_password
            return redirect(url_for('login'))
        return 'Username not found.'
    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/courses')
def courses():
    if 'username' in session:
        return render_template('courses.html')
    return redirect(url_for('login'))

@app.route('/enroll')
def enroll():
    if 'username' in session:
        return render_template('enroll.html')
    return redirect(url_for('login'))

@app.route('/forum')
def forum():
    if 'username' in session:
        return render_template('forum.html')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
