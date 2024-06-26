from wtforms import Form, StringField, PasswordField, RadioField, SelectField, TextAreaField, validators, EmailField, \
    ValidationError, FileField, IntegerField, BooleanField
from flask_wtf.file import FileField, FileAllowed
from wtforms.fields import EmailField, DateField, SubmitField, TelField
from flask_wtf import FlaskForm


class CreateProductForm(FlaskForm):
    idproducts = IntegerField('Product ID', render_kw={'readonly': True})
    name = StringField(' Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    price = StringField('Price', [validators.Length(min=1, max=150), validators.DataRequired()])
    category = StringField('Category', [validators.Length(min=1, max=150), validators.DataRequired()])
    image = FileField('Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    description = TextAreaField('Description', [validators.Length(min=1, max=400), validators.DataRequired()])
    ingredients_info = TextAreaField('Ingredients Info', [validators.Length(min=1, max=600), validators.DataRequired()])

    is_recommended = BooleanField('Display in Recommended?')

    # function to validate price entered to make sure that the price entered is either integers or float
    def validate_price(form, field):
        try:
            # Attempt to convert the input from the above field, price, to a float
            float_value = float(field.data)
        except ValueError:
            raise validators.ValidationError('Price must be a valid number.')

    def validate_category(form, field):
        # Check if the field being validated is 'category'
        if field.name == 'category':
            # Convert the input to lowercase
            field.data = field.data.lower()


class SearchForm(FlaskForm):
    search_query = StringField(render_kw={'placeholder':'Search for a product'})
    submit = SubmitField('Search')


class deliveryOptionForm(FlaskForm):
    option = RadioField('Delivery Options', choices=[('Delivery', 'Delivery'), ('Dine-In', 'Dine-In'), ('Pick-Up', 'Pick-Up')],)

class SubscriptionForm(FlaskForm):
    name = StringField('Name', [validators.Length(min=1, max=100), validators.DataRequired()])
    email = EmailField('Email', [ validators.DataRequired()])
    address = StringField('Address', [validators.Length(min=1, max=255), validators.DataRequired()])
    phone = StringField('Phone Number', [validators.Length(min=8, max=15), validators.DataRequired()])
    subscription_type = SelectField('Subscription Type', choices=[('monthly', 'Monthly'), ('yearly', 'Yearly')], default='monthly', validators=[validators.DataRequired()])
    card_number = StringField('Card Number', [validators.Length(min=16, max=16), validators.DataRequired()])
    card_expiry = StringField('Card Expiry (MM/YY)', [validators.Length(min=5, max=5), validators.DataRequired()])
    card_cvc = StringField('Card CVC', [validators.Length(min=3, max=3), validators.DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    submit = SubmitField('Login')