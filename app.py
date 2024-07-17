from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import bcrypt
from sql_connection import get_sql_connection

app = Flask(__name__)
app.secret_key = 'tousiftamboli'  # Replace with your actual secret key

# Initialize SQL connection
connection = get_sql_connection()


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        # Check if the email already exists
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Email already exists. Please use a different email.')
            return redirect(url_for('register'))

        # If email does not exist, proceed with registration
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
        connection.commit()
        cursor.close()

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password.")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            return render_template('dashboard.html', user=user)

    flash('Please log in to access this page.')
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
