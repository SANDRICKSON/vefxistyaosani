from wtforms.validators import Optional
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField, RadioField, EmailField, \
    TextAreaField, FileField
from wtforms.validators import DataRequired, Length, EqualTo, Email



class RegisterForm(FlaskForm):
    username = StringField("შეიყვანეთ სახელი", validators=[DataRequired(), Length(min=8, max=64)])
    email = EmailField("შეიყვანეთ ელ. ფოსტა", validators=[DataRequired(), Email()])
    password = PasswordField("შეიყვანეთ პაროლი", validators=[DataRequired(), Length(min=8, max=64)])
    repeat_password = PasswordField("გაიმეორეთ პაროლი",
                                    validators=[EqualTo("password", message="პაროლები არ ემთხვევა")])
    birthday = DateField("დაბადების თარიღი")
    country = SelectField("აირჩიეთ ქვეყანა", choices=[
        ("Georgia", "საქართველო/Georgia"),
        ("United States", "აშშ/United States"),
        ("France", "საფრანგეთი/France"),
        ("Germany", "გერმანია/Germany"),
        ("Italy", "იტალია/Italy"),
        ("England", "ინგლისი/England")
    ])
    gender = RadioField("აირჩიეთ სქესი",
                        choices=[("male", "კაცი"), ("female", "ქალი"), ("other", "არ არის მითითებული")])


    submit = SubmitField("რეგისტრაცია")



class MessageForm(FlaskForm):
    name = StringField('სახელი', validators=[DataRequired()])
    email = StringField('ელფოსტა', validators=[DataRequired(), Email()])
    message = TextAreaField('შეტყობინება', validators=[DataRequired()])
    submit = SubmitField('გაგზავნა')


class LoginForm(FlaskForm):
    username = StringField("შეიყვანეთ მომხმარებლის სახელი ან ელფოსტა", validators=[DataRequired()])


    password = PasswordField("შეიყვანეთ პაროლი", validators=[DataRequired(), Length(min=8, max=64)])
    submit = SubmitField("ავტორიზაცია")


class FormUpdateForm(FlaskForm):
    username = StringField("მომხმარებლის სახელი", validators=[DataRequired()])

    country = SelectField("აირჩიეთ ქვეყანა", choices=[
        ("Georgia", "საქართველო/Georgia"),
        ("United States", "აშშ/United States"),
        ("France", "საფრანგეთი/France"),
        ("Germany", "გერმანია/Germany"),
        ("Italy", "იტალია/Italy"),
        ("England", "ინგლისი/England")
    ], validators=[Optional()])

    gender = RadioField("აირჩიეთ სქესი", choices=[
        ("male", "კაცი"),
        ("female", "ქალი"),
        ("other", "არ არის მითითებული")
    ], validators=[Optional()])

    email = StringField("ელ-ფოსტა", validators=[DataRequired(), Email()])
    birthday = DateField("დაბადების თარიღი", format="%Y-%m-%d", validators=[Optional()])

    password = PasswordField("ახალი პაროლი", validators=[Optional()])
    confirm_password = PasswordField("გაიმეორეთ პაროლი",
                                     validators=[Optional(), EqualTo('password', message="პაროლები არ ემთხვევა")])
    avatar = FileField("პროფილის სურათი")
    submit = SubmitField("განახლება")
