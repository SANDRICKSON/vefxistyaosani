from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import  SignatureExpired, BadTimeSignature
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
from extensions import app, mail,db
from werkzeug.utils import secure_filename
import os

from models import User, ContactMessage
from forms import RegisterForm, MessageForm, LoginForm, UpdateForm, ForgotPasswordForm,ResetPasswordForm, FormUpdateForm

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    form = FormUpdateForm(obj=current_user)

    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.birthday = form.birthday.data
        current_user.country = form.country.data
        current_user.gender = form.gender.data

        if form.password.data:
            current_user.password = generate_password_hash(form.password.data)

        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                current_user.avatar = filename

        db.session.commit()
        flash("მონაცემები წარმატებით განახლდა!", "success")
        return redirect(url_for("profile"))

    return render_template("settings.html", form=form, title="პარამეტრები - ვეფხისტყაოსანი")

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('პაროლის აღდგენა', recipients=[user.email])
            msg.body = f"პაროლის აღსადგენად დააჭირეთ ამ ბმულს: {reset_url}"
            mail.send(msg)
            flash('ელ.ფოსტა გაგზავნილია!', 'success')
            return redirect(url_for('login'))
        else:
            flash('ამ ელ.ფოსტით მომხმარებელი არ მოიძებნა.', 'danger')
    return render_template('forgot_password.html', form=form, title="პაროლის აღდგენა - ვეფხისტყაოსანი")

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash('ბმული არასწორია ან ვადა გაუვიდა!', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('მომხმარებელი ვერ მოიძებნა!', 'danger')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('პაროლი წარმატებით განახლდა!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)

@app.errorhandler(401)
def unauthorized(error):
    return render_template('401.html', title="არაავტორიზირებული მომხმარებელი - ვეფხისტყაოსანი"), 401

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html', title="სერვერის შეცდომა - ვეფხისტყაოსანი"), 500

@app.errorhandler(502)
def bad_gateway(error):
    return render_template('502.html',title="ცუდი კარიბჭე - ვეფხისტყაოსანი"), 502

@app.errorhandler(503)
def service_unavailable(error):
    return render_template('503.html', title="მიუწვდომელი სერვისი - ვეფხისტყაოსანი"), 503

@app.errorhandler(504)
def gateway_timeout(error):
    return render_template('504.html', title="სესიის დრო ამოიწურა - ვეფხისტყაოსანი"), 504

@app.route("/403")
@login_required
def noadmin():
    return render_template("403.html", title="აკრძალული წვდომა - ვეფხისტყაოსანი")

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html', title="გვერდი არ მოიძებნა - ვეფხისტყაოსანი"), 404

def send_verification_email(user_email):
    token = generate_verification_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Email Verification"
    message_body = f"მოგესალმებით, {user.username}! 😊\n\nმადლობა, რომ დაინტერესდით ჩემი პროექტით. თქვენი ანგარიში წარმატებით შეიქმნა! გთხოვთ, გაიარეთ ვერიფიკაცია შემდეგ ბმულზე:\n\n{confirm_url}\n\nმადლობა ყურადღებისთვის! 🙌"

    msg = Message(
        subject=subject,
        recipients=[user_email],
        body=message_body,
        sender="vepkkhistyaosaniproject@gmail.com"
    )

    mail.send(msg)
def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')

def confirm_verification_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return email

def send_verification_email(user_email):
    token = generate_verification_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Email Verification"
    message_body = f"დააჭირეთ ამ ბმულს თქვენი ემაილის ვერიფიკაციისთვის: {confirm_url}"

    msg = Message(subject=subject, recipients=[user_email], body=message_body)
    mail.send(msg)

@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_verification_token(token)
    if not email:
        flash("ვერიფიკაციის ბმული არასწორია ან ვადა გაუვიდა!", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        user.is_verified = True
        user.save()
        flash("თქვენი ემაილი წარმატებით ვერიფიცირდა!", "success")
    elif user and user.is_verified:
        flash("თქვენი ემაილი უკვე ვერიფიცირებულია!", "info")

    return redirect(url_for('login'))

@app.route("/admin/users")
@login_required
def view_users():
    if current_user.username == "sandroqatamadze":
        users = User.query.all()
        return render_template("admin_users.html", users=users, title="მონაცემების ხილვა")
    else:
        flash("Sorry, you are not authorized to view this page.")
        return redirect(url_for('noadmin'))

@app.route("/chatbot")
def chatbot():
    return render_template("chatbot.html",title="ჩეთბოტი - ვეფხისტყაოსანი")

@app.route("/admin")
@login_required
def admin():
    if current_user.username == "sandroqatamadze":
        return render_template("admin.html", title="ადმინის გვერდი - ვეფხისტყაოსანი")
    else:
        flash("Sorry but you are not the admin")
        return redirect(url_for('noadmin'))

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

@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = MessageForm()
    if form.validate_on_submit():

        new_message = ContactMessage(
            name=form.name.data,
            email=form.email.data,
            message=form.message.data
        )
        db.session.add(new_message)
        db.session.commit()

        msg = Message(
            subject="ახალი კონტაქტის შეტყობინება",
            sender="vepkhistyaosaniproject@gmail.com",
            recipients=["vepkhistyaosaniproject@gmail.com"],
            body=f"მომხმარებელი: {form.name.data}\nელფოსტა: {form.email.data}\n\nშეტყობინება:\n{form.message.data}"
        )
        mail.send(msg)

        flash("შეტყობინება წარმატებით გაიგზავნა!", "success")
        return redirect(url_for("contact"))

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
            if not user.is_verified:
                send_verification_email(user.email)
                flash("თქვენს ელ-ფოსტაზე ვერიფიკაციის ბმული გაგზავნილია!", "warning")
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for("index"))
    return render_template("login.html", form=form, title="ავტორიზაცია - ვეფხისტყაოსანი")


CHAPTERS_DIR = "chapters"  # ფოლდერის სახელი


@app.route("/poem")
def poem():
    chapters = sorted([
        f for f in os.listdir(CHAPTERS_DIR) if f.endswith(".txt")
    ], key=lambda x: int(x.replace(".txt", "")))

    return render_template("poem.html", chapters=chapters,title="პოემა - ვეფხისტყაოსანი")


@app.route("/poem/chapter/<int:chapter_id>")
def chapter_page(chapter_id):
    filename = os.path.join(CHAPTERS_DIR, f"{chapter_id}.txt")
    if not os.path.exists(filename):
        os.abort(404)
    with open(filename, encoding="utf-8") as f:
        content = f.read()
    page_title = f"თავი {chapter_id} - ვეფხისტყაოსანი"
    return render_template("chapter.html", chapter_id=chapter_id, content=content, page_title=page_title)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", title="პროფილი - ვეფხისტყაოსანი")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        existing_email = User.query.filter_by(email=form.email.data).first()

        if existing_user:
            form.username.errors.append("ეს სახელი უკვე გამოყენებულია.")
            return render_template("register.html", form=form,title="რეგისტრაცია - ვეფხისტყაოსანი")

        if existing_email:
            form.email.errors.append("ეს ელფოსტა უკვე გამოყენებულია.")
            return render_template("register.html", form=form,title="რეგისტრაცია - ვეფხისტყაოსანი")

        # თუ არ არსებობს, შექმნე
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            birthday=form.birthday.data,
            country=form.country.data,
            gender=form.gender.data,
            is_verified=False
        )
        user.create()
        send_verification_email(user.email)
        flash("თქვენს ელფოსტაზე გაგზავნილია ვერიფიკაციის ბმული!", "info")
        return redirect(url_for("login"))
    return render_template("register.html", form=form,title="რეგისტრაცია - ვეფხისტყაოსანი")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html", title="უსაფრთხოების პოლიტიკა - ვეფხისტყაოსანი")

@app.route("/admin/messages")
@login_required
def view_messages():
    if current_user.username != "sandroqatamadze":
        flash("არ გაქვთ წვდომა!", "danger")
        return redirect(url_for("noadmin"))

    messages = ContactMessage.query.order_by(ContactMessage.id.desc()).all()
    return render_template("admin_messages.html", messages=messages, title="კონტაქტის შეტყობინებები")

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):

    if current_user.username != "sandroqatamadze":
        flash("თქვენ არ გაქვთ წაშლის უფლება.", "danger")
        return redirect(url_for('view_users'))

    user = User.query.get_or_404(user_id)

    if user.username == "sandroqatamadze":
        flash("ადმინის ანგარიშის წაშლა არ შეიძლება.", "warning")
        return redirect(url_for('view_users'))

    try:

        msg = Message(
            subject="ანგარიშის წაშლა",
            recipients=[user.email],
            sender="vepkkhistyaosaniproject@gmail.com",
            body=(
                f"გამარჯობა, {user.username}!\n\n"
                "ვწუხვართ, რომ თქვენი ანგარიში ადმინისტრატორის გადაწყვეტილებით წაიშალა.\n"
                "თუ გაქვთ კითხვები, დაგვიკავშირდით.\n\n"
                "გმადლობთ,\n პატივისცემით - სანდრო ქათამაძე პროექტის ავტორი"
            )
        )
        mail.send(msg)

        db.session.delete(user)
        db.session.commit()

        flash(f"მომხმარებელი {user.username} წარმატებით წაშლილია და ინფორმირებული იქნა მეილზე.", "success")

    except Exception as e:
        app.logger.error(f"Error deleting user or sending email: {e}")
        flash("შეცდომა მოხდა მომხმარებლის წაშლის ან მეილის გაგზავნის დროს.", "danger")

    return redirect(url_for('view_users'))


@app.route('/admin/change_role/<int:user_id>', methods=['POST'])
@login_required
def change_role(user_id):
    if current_user.username != "sandroqatamadze":
        flash("თქვენ არ გაქვთ როლის შეცვლის უფლება.", "danger")
        return redirect(url_for('view_users'))

    user = User.query.get_or_404(user_id)

    if user.username == "sandroqatamadze":
        flash("თქვენ არ შეგიძლიათ თქვენი როლის შეცვლა.", "warning")
        return redirect(url_for('view_users'))

    new_role = request.form.get('new_role')

    if new_role not in ['user', 'admin']:
        flash("არასწორი როლი.", "danger")
        return redirect(url_for('view_users'))

    previous_role = user.role
    user.role = new_role
    db.session.commit()

    # თუ როლი შეიცვალა, ვუგზავნით მეილს
    if previous_role != new_role:
        subject = "თქვენი როლი შეიცვალა"
        body = f"""
გამარჯობა, {user.username}!

საიტის ადმინისტრატორის გადაწყვეტილებით, თქვენი როლი შეიცვალა და თქვენ გახდით **{new_role}**.

თუ თქვენ გახდით **ადმინი**, გეძლევათ წვდომა შემდეგზე:
• მომხმარებლების წაშლა  
• მათი შეტყობინებების ნახვა  
• ადმინისტრატორის სხვა ფუნქციების გამოყენება

თუ გაქვთ შეკითხვები, გთხოვთ დაგვიკავშირდეთ.

პატივისცემით,  
სანდრო ქათამაძე  
პროექტის ავტორი
"""

        try:
            msg = Message(
                subject=subject,
                recipients=[user.email],
                body=body,
                sender="vepkkhistyaosaniproject@gmail.com"
            )
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"მეილის გაგზავნის შეცდომა: {e}")
            flash("როლი შეიცვალა, მაგრამ მეილის გაგზავნისას მოხდა შეცდომა.", "warning")
            return redirect(url_for('view_users'))

    flash(f"{user.username} ახლა არის {new_role} და ინფორმირებულია ელფოსტით.", "success")
    return redirect(url_for('view_users'))



@app.route('/admin/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    if current_user.username != "sandroqatamadze":
        flash("არ გაქვთ წვდომა!", "danger")
        return redirect(url_for('view_messages'))

    message = ContactMessage.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()
    flash("შეტყობინება წარმატებით წაიშალა!", "success")
    return redirect(url_for('view_messages'))


if __name__ == "__main__":
    app.run(debug=True)