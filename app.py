from flask import  render_template,redirect, url_for, flash
from forms import RegisterForm, MessageForm, LoginForm,UpdateForm
from flask_login import login_user, logout_user, current_user, login_required
from extensions import app
from models import User
from werkzeug.security import check_password_hash, generate_password_hash

@app.route("/admin/users")
@login_required
def view_users():
    if current_user.id == 1:  # მხოლოდ თუ ადმინისტრატორი
        users = User.query.all()  # ყველა მომხმარებლის გამოტანა
        return render_template("admin_users.html", users=users, title="მონაცემების ხილვა")
    else:
        flash("Sorry, you are not authorized to view this page.")
        return redirect(url_for('index'))


@app.route("/admin")
@login_required
def admin():
    id = current_user.id
    if id == 1:
      return render_template("admin.html", title="ადმინის გვერდი - ვეფხისტყაოსანი")
    else:
        flash("Sorry but you are not the admin")
        return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html', title="404 - ვეფხისტყაოსანი"), 404

@app.route("/")
def index():
    return render_template("index.html", title="ვეფხისტყაოსანი")

@app.route("/update", methods=["GET", "POST"])
def update():
    form = UpdateForm()
    if form.validate_on_submit():
        print(form.update.data)
    return render_template("update.html", form=form, title="გააგრძელე - ვეფხისტყაოსანი")


@app.route("/about")
def about():
    return render_template("about.html", title="პროექტის შესახებ - ვეფხისტყაოსანი")

@app.route("/contact", methods=["GET", "POST"])  # Correct placement of methods argument
def contact():
    form = MessageForm()
    if form.validate_on_submit():
        print(form.message.data)
    return render_template("contact.html", form=form, title="კონტაქტი - ვეფხისტყაოსანი")


@app.route("/author")
def author():
    return render_template("author.html", title="ავტორის შესახებ - ვეფხისტყაოსანი")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("index")) 
    return render_template("login.html", form=form, title="ავტორიზაცია - ვეფხისტყაოსანი")


@app.route("/poem")
def poem():
    return render_template("poem.html", title="პოემა - ვეფხისტყაოსანი")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index', title="ავტორიზაცია - ვეფხისტყაოსანი"))



@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", title="პროფილი - ვეფხისტყაოსანი" )

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
    return render_template("register.html", form=form, title="რეგისტრაცია - ვეფხისტყაოსანი")

if __name__ == "__main__":  
    app.run(debug=True)
