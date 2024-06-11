from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length
from wtforms.widgets import PasswordInput


class RegistrationForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(3, 30)])
    email = StringField("Email", validators=[DataRequired(), Length(5, 40)])
    password = StringField(
        "Password",
        widget=PasswordInput(hide_value=False),
        validators=[DataRequired(), Length(5, 40)],
    )
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(5, 40)])
    password = StringField(
        "Password",
        widget=PasswordInput(hide_value=False),
        validators=[DataRequired(), Length(5, 40)],
    )
    submit = SubmitField("Submit")
