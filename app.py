from flask import  render_template,redirect, url_for
from forms import RegisterForm, MessageForm, LoginForm
from flask_login import login_user, logout_user, current_user, login_required
from extensions import app
from models import User
from werkzeug.security import check_password_hash, generate_password_hash



@app.route("/")
def index():
    return render_template("index.html")

@app.route("/contact", methods=["GET", "POST"])  # Correct placement of methods argument
def contact():
    form = MessageForm()
    if form.validate_on_submit():
        print(form.message.data)
    return render_template("contact.html", form=form)


@app.route("/author")
def author():
    return render_template("author.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("index")) 
    return render_template("login.html", form=form)


@app.route("/poem")
def poem():
    return render_template("poem.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        user = User(
            username=form.username.data,
            password=form.password.data,
            birthday=form.birthday.data,
            country=form.country.data,
            gender=form.gender.data
        )
        user.create()
        return redirect(url_for("login"))
        print(form.errors)
    return render_template("register.html", form=form)

if __name__ == "__main__":  
    app.run(debug=True)
