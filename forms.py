from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField, RadioField, EmailField,TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo

class RegisterForm(FlaskForm):
    username = StringField("შეიყვანეთ სახელი", validators=[DataRequired(), Length(min=8, max=64)])

    password = PasswordField("შეიყვანეთ პაროლი", validators=[DataRequired(), Length(min=8, max=64)])
    repeat_password = PasswordField("გაიმეორეთ პაროლი", validators=[EqualTo("password", message="პაროლები არ ემთხვევა")])

    submit = SubmitField("რეგისტრაცია")

    birthday = DateField("დაბადების თარიღი")

    country = SelectField("აირჩიეთ ქვეყანა", choices=[
        ("Georgia", "საქართველო/Georgia"), 
        ("United States", "აშშ/United States"), 
        ("France", "საფრანგეთი/France"), 
        ("Germany", "გერმანია/Germany"), 
        ("Italy", "იტალია/Italy"), 
        ("England", "ინგლისი/England")
    ])

    gender = RadioField("აირჩიეთ სქესი", choices=[("male", "კაცი"), ("female", "ქალი"), ("other", "არ არის მითითებული")])

class MessageForm(FlaskForm):
    message = StringField("დაწერეთ მესიჯი")
    submit = SubmitField("გაგზავნეთ მესიჯი")

class LoginForm(FlaskForm):
       username = StringField("შეიყვანეთ სახელი", validators=[DataRequired(), Length(min=8, max=64)])

       password = PasswordField("შეიყვანეთ პაროლი", validators=[DataRequired(), Length(min=8, max=64)])
       submit = SubmitField("ავტორიზაცია")


class UpdateForm(FlaskForm):
    username = StringField("შეიყვანეთ სახელი", validators=[DataRequired(), Length(min=8, max=64)])
    message = TextAreaField("დაწერეთ თქვენეული გაგრძელება")
    submit = SubmitField("გაგზავნა")
