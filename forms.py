from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField,FloatField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo

# --- REGISTRATION FORM (Sign Up) ---
class RegistrationForm(FlaskForm):
    # Username: Khali nahi ho sakta, 2 se 20 letters ka hona chahiye
    username = StringField('Username', 
                           validators=[DataRequired(), Length(min=2, max=20)])
    
    # Email: @ aur sahi format check karega
    email = StringField('Email', 
                        validators=[DataRequired(), Email()])
    
    # Password: Khali nahi ho sakta
    password = PasswordField('Password', validators=[DataRequired()])
    
    # Confirm Password: Upar wale password se match hona chahiye
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(), EqualTo('password')])
    
    submit = SubmitField('Sign Up')


# --- LOGIN FORM (Sign In) ---
class LoginForm(FlaskForm):
    # Login ke liye sirf Email aur Password chahiye
    email = StringField('Email', validators=[DataRequired(), Email()])
    
    password = PasswordField('Password', validators=[DataRequired()])
    
    # "Remember Me" wala chota tick box
    remember = BooleanField('Remember Me')
    
    submit = SubmitField('Login')

# --- EXPENSE FORM (Naya Code) ---
class ExpenseForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('Food', 'Food'), 
        ('Travel', 'Travel'), 
        ('Shopping', 'Shopping'), 
        ('Bills', 'Bills'), 
        ('Others', 'Others')
    ], validators=[DataRequired()])
    submit = SubmitField('Add Expense')