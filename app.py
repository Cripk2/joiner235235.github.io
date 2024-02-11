import requests
import nacl
import nacl.encoding
import nacl.signing

import logging
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

import hashlib
import hmac
import json

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from datetime import datetime
from flask_migrate import Migrate
import stripe

from flask.cli import AppGroup
import click

from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

stripe.api_key = 'sk_test_51OaihiGzQg45HleNEdb2greMNq5aPdb7dcQ8SGCafS5ZVwQfG5Z2RHgvYzddAhCUWU2jR2ykf3BGPImRcepSy2D700sv57EdbW'


# Dictionary to store bot tokens
bot_instances = {}

class Unauthorized(Exception):
    def __init__(self, message="Unauthorized"):
        self.message = message
        super().__init__(self.message)

import nacl.encoding
import nacl.signing

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    membership = db.Column(db.String(50), nullable=False, default='Free')
    bot_name = db.Column(db.String(255), nullable=True)
    bot_token = db.Column(db.String(255), nullable=True)
    bot_public_key = db.Column(db.String(255), nullable=True)
    tokens = db.Column(db.String(255), nullable=True)


class BotInstance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bot_token = db.Column(db.String(255), unique=True, nullable=False)
    public_key = db.Column(db.String(255), nullable=True)

with app.app_context():
    db.create_all()

user_cli = AppGroup('user')

@user_cli.command('update-plan')
@click.argument('username')
@click.argument('new_plan')
def update_user_plan(username, new_plan):
    user = User.query.filter_by(username=username).first()
    if user:
        user.membership = new_plan
        db.session.commit()
        print(f"User {username}'s plan updated to {new_plan}")
    else:
        print(f"User {username} not found")

app.cli.add_command(user_cli)

class AddTokensForm(FlaskForm):
    tokens = TextAreaField('Tokens (one per line)', validators=[DataRequired()], render_kw={"placeholder": "Enter tokens here"})
    submit = SubmitField('Add Tokens')

@app.route('/addstock')
def add_stock():
    form = AddTokensForm()
    user_id = session.get('user_id')
    user = User.query.get_or_404(user_id)
    membership = user.membership
    return render_template('addstock.html', form=form, current_user=user, membership=membership)

@app.route('/addtokens', methods=['POST'])
def add_tokens():
    form = AddTokensForm(request.form)
    user = None  # Initialize user with None
    membership = None

    if form.validate_on_submit():
        tokens = form.tokens.data.split('\n')  # Split tokens by line

        # Get the current user's ID using Flask-Login
        user_id = session.get('user_id')

        # Assuming you have the user available
        user = User.query.get_or_404(user_id)
        membership = user.membership

        if user:
            # Ensure user.tokens is not None, initialize as an empty string if needed
            user.tokens = user.tokens or ''

            # Update the user's tokens in the database
            user.tokens += '\n'.join(tokens)
            db.session.commit()

            # Print for demonstration purposes
            print(f"Tokens added for user {user.username} (ID: {user.id}):")
            for token in tokens:
                print(token)

            # You can redirect to the home page or any other page after processing the tokens
            return redirect(url_for('home'))

    # If form validation fails or user not found, you might want to handle it accordingly
    return render_template('addstock.html', form=form, current_user=user, membership=membership)



def validate_request(request):
    signature = request.headers.get('X-Signature-Ed25519')
    timestamp = request.headers.get('X-Signature-Timestamp')
    body = request.data.decode('utf-8')

    if not (signature and timestamp and body):
        raise Unauthorized('Invalid request signature')

    data = timestamp + body
    signature_bin = bytes.fromhex(signature)

    public_keys = BotInstance.query.with_entities(BotInstance.public_key).all()
    
    for public_key in public_keys:
        public_key_bin = public_key[0].encode('utf-8') 

        try:
            verify_key = nacl.signing.VerifyKey(public_key_bin, encoder=nacl.encoding.HexEncoder)
            verify_key.verify(data.encode('utf-8'), signature_bin)
            return 
        except nacl.exceptions.BadSignatureError:
            pass 

    raise Unauthorized('Invalid request signature')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/upgrade', methods=['GET', 'POST'])
def upgrade():
    user_id = session.get('user_id')
    
    user = User.query.get_or_404(user_id)


    membership = user.membership

    if request.method == 'POST':
        # Handle the Stripe payment
        token = request.form['stripeToken']
        try:
            # Create a charge using Stripe
            charge = stripe.Charge.create(
                amount=500,  # Set the amount in cents or any other currency
                currency='usd',
                description='Membership Upgrade',
                source=token,
            )

            # Update the user's membership in the database
            user.membership = 'Premium'
            db.session.commit()

            return redirect(url_for('home'))

        except stripe.error.CardError as e:
            # Handle card errors
            error_msg = e.error.message
            return render_template('upgrade.html', error_msg=error_msg)

    return render_template('upgrade.html',  current_user=user, membership=membership)

@app.route('/success')
def success_page():
    return "Payment successful! Thank you for upgrading your membership."

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if the user is already logged in
    if 'user_id' in session:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    # Clear the session data
    session.clear()

    # Flash a logout message
    flash('You have been logged out.', 'info')

    # Redirect to the login page
    return redirect(url_for('login'))


@app.route('/dashboard')
def home():
    user_id = session.get('user_id')

    if user_id is not None:
        user = User.query.get_or_404(user_id)
        membership = user.membership

        return render_template('dashboard.html', current_user=user, membership=membership)
    else:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))



@app.route('/')
def index():
    return "Hello, this is the Joinify API."

@app.route('/create')
def execute_command_form():
    user_id = session.get('user_id')
    
    if user_id is not None:
        user = User.query.get_or_404(user_id)
        membership = user.membership  # Access the membership attribute
        print(membership)
        return render_template('create.html', current_user=user, membership=membership)
    else:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))

@app.route('/execute_command', methods=['POST'])
def execute_command():
    user_id = session.get('user_id')
    user = User.query.get_or_404(user_id)
    data = request.form
    bot_token = data.get('bot_token')
    application_id = data.get('application_id') 
    bot_public_key = data.get('public_key')  
    bot_name = data.get('bot_name')

    # Check if the user has a Free membership and already has a bot
    if user.membership == 'Free' and user.bot_token:
        flash('Free members can only create one bot', 'error')
        return redirect(url_for('execute_command_form'))

    if bot_token not in bot_instances:
        # Check if the bot instance is not already in the local dictionary
        bot_instances[bot_token] = {
            'application_id': application_id,
            'bot_public_key': bot_public_key
        }

        # Save bot instance details to the database
        existing_bot_instance = BotInstance.query.filter_by(bot_token=bot_token).first()
        if existing_bot_instance:
            existing_bot_instance.public_key = bot_public_key
        else:
            new_bot_instance = BotInstance(bot_token=bot_token, public_key=bot_public_key)
            db.session.add(new_bot_instance)

        # Save bot_name to the user associated with the current session
        if user_id:
            user = User.query.get(user_id)
            if user:
                user.bot_name = bot_name
                user.bot_token = bot_token
                user.bot_public_key = bot_public_key
                db.session.commit()
                url = f"https://discord.com/api/v10/applications/{application_id}/commands"
                headers = {
                    "Authorization": f"Bot {bot_token}"
                }

                slash_command2 = {
                    "name": "djoin",
                    "description": "Add the members to the guild using the author's role allowance.",
                    "options": [
                        {
                            "name": "guild_id",
                            "description": "The ID of the guild to add the members to.",
                            "type": 3,
                            "required": True
                        }
                    ]
                }

                slash_command_stock = {
                    "name": "stock",
                    "description": "Check the stock status",
                }

                requests.post(url, headers=headers, json=slash_command_stock)
                response = requests.post(url, headers=headers, json=slash_command2)

                if response.status_code == 201:
                    registration_status = "Bot Created"
                else:
                    registration_status = f"Bot Created"

                # Pass the registration status to the template
                
                return render_template('create.html', current_user=user, registration_status=registration_status)

            return jsonify({'success joinify bot made / love Dylan': True})

def get_guild_from_id(bot_token, guild_id):
    headers = {
        "Authorization": f"Bot {bot_token}"
    }

    url = f"https://discord.com/api/v10/guilds/{guild_id}"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        guild_data = response.json()
        return guild_data
    elif response.status_code == 404:
        return None
    else:
        return None
    
@app.route('/interactions', methods=['POST'])
def interactions():
    try:
        validate_request(request)
    except Unauthorized as e:
        logger.error(f"Unauthorized request: {str(e)}")
        return str(e), 401

    data = request.json

    logger.info(f"Received interaction data: {data}")

    if data['type'] == 1:
        logger.info("Received Ping")
        return jsonify({"type": 1})

    elif data['type'] == 2:
        # Handle Command interaction
        command_name = data['data']['name']

        if command_name == 'stock':
            

                return jsonify(response)
            
        elif command_name == 'djoin':
            logger.info("Received 'djoin' command")

        
            guild_id = data['data']['options'][0]['value']

            bot_token = "MTE5OTkwNzM5Mjc0NjQyMjI4Mg.GEEl4p.QGQF_jUIIqnJEMrWKyIFa36UHWqlC6xYGsiTts"

            guild_data = get_guild_from_id(bot_token, guild_id)

            if guild_data:
                guild_name = guild_data['name']

                logger.info(f"Adding members to guild: '{guild_name}' with ID: {guild_id}")
                response = {
                    "type": 4,
                    "data": {
                        "content": f"Received 'djoin' command for guild '{guild_name}' with ID {guild_id}",
                    }
                }
                return jsonify(response)
            else:
                response = {
                    "type": 4,
                    "data": {
                        "embeds": [
                            {
                                "title": "Something went wrong",
                                "description": f"Please invite the bot to ur discord server\nServer ID: {guild_id}",
                                "color": 15548997,
                                "timestamp": datetime.utcnow().isoformat(),
                            }
                        ]
                    }
                }

                return jsonify(response)

    else:
        logger.warning(f"Unknown interaction type: {data['type']}")
        return jsonify({"type": 1})


if __name__ == '__main__':
    app.run(port=5000)
