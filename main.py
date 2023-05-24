from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

current_user = None

# CREATE TABLE IN DB


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.form:
        new_user = User(email=request.form['email'], name=request.form['name'], password=request.form['password'])
        db.session.add(new_user)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        return redirect(url_for('login'))
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    global current_user
    if request.form:
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user != None and user.password == password:
            current_user = user
            return redirect(url_for('secrets'))
    return render_template("login.html")


@app.route('/secrets')
def secrets():
    global current_user
    if current_user != None:
        return render_template("secrets.html", user=current_user)
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    pass


if __name__ == "__main__":
    app.run(debug=True)
