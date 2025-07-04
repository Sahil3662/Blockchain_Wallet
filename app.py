from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from web3 import Web3
from cryptography.fernet import Fernet
import requests
import time
import logging
from decimal import Decimal


app = Flask(__name__)
app.secret_key = 'your_strong_secret_key_here' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wallets.db'
app.config['SESSION_COOKIE_SECURE'] = False  
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['WTF_CSRF_SSL_STRICT'] = False 


db = SQLAlchemy(app)
csrf = CSRFProtect(app)
CORS(app, supports_credentials=True)
logging.basicConfig(level=logging.DEBUG)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

key = Fernet.generate_key()
cipher_suite = Fernet(key)


GANACHE_URL = "http://127.0.0.1:7545"
INFURA_URL = "https://mainnet.infura.io/v3/50b982020aa244fdbe97c0f4155ed8cf"
ganache_web3 = Web3(Web3.HTTPProvider(GANACHE_URL))
infura_web3 = Web3(Web3.HTTPProvider(INFURA_URL))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    wallets = db.relationship('Wallet', backref='user', lazy=True)

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(120), nullable=False)
    private_key = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tx_hash = db.Column(db.String(120), nullable=False)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'), nullable=False)


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('login', next=request.endpoint))


eth_to_usd_cache = {'rate': None, 'last_updated': 0}

def get_eth_to_usd():
    try:
        current_time = time.time()
        if eth_to_usd_cache['rate'] and (current_time - eth_to_usd_cache['last_updated']) < 300:
            return eth_to_usd_cache['rate']

        response = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd")
        if response.status_code == 200:
            data = response.json()
            if 'ethereum' in data and 'usd' in data['ethereum']:
                eth_to_usd_cache['rate'] = data['ethereum']['usd']
                eth_to_usd_cache['last_updated'] = current_time
                return eth_to_usd_cache['rate']
        return None
    except Exception as e:
        logging.error(f"ETH to USD error: {e}")
        return None


@app.before_request
def check_csrf():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        csrf.protect()


@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user:
            if user.password == password:
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            flash('Invalid password')
        else:
            flash('Username not found. Please register.')
            return redirect(url_for('register'))
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))
            
        if not User.query.filter_by(username=username).first():
            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        flash('Username already exists')
    return render_template('register.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

@app.route('/create_wallet', methods=['POST'])
@login_required
def create_wallet():
    try:
        if not request.is_json:
            return jsonify({'error': 'Invalid content type'}), 400

        account = ganache_web3.eth.account.create()
        encrypted_private_key = cipher_suite.encrypt(account.key)

        wallet = Wallet(
            address=account.address,
            private_key=encrypted_private_key,
            user_id=current_user.id
        )
        db.session.add(wallet)
        db.session.commit()

        return jsonify({
            'address': account.address,
            'private_key': account.key.hex()
        })
    except Exception as e:
        app.logger.error(f"Error creating wallet: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_balance', methods=['POST'])
@login_required
def get_balance():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        address = data.get('address', '').strip()
        network = data.get('network', 'ganache')
        web3 = ganache_web3 if network == 'ganache' else infura_web3

        if not address:
            return jsonify({'error': 'Address is required'}), 400

        balance = web3.eth.get_balance(address)
        eth_balance = web3.from_wei(balance, 'ether')
        eth_to_usd = get_eth_to_usd()
        
        usd_balance = eth_balance * Decimal(str(eth_to_usd)) if eth_to_usd else "N/A"

        return jsonify({
            'balance': float(eth_balance),
            'usd_balance': float(usd_balance) if isinstance(usd_balance, Decimal) else usd_balance
        })
    except Exception as e:
        logging.error(f"Balance check error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/send_transaction', methods=['POST'])
@login_required
def send_transaction():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        sender_address = data.get('sender_address', '').strip()
        private_key = data.get('private_key', '').strip()
        receiver_address = data.get('receiver_address', '').strip()
        amount = data.get('amount')
        network = data.get('network', 'ganache')
        web3 = ganache_web3 if network == 'ganache' else infura_web3

        if not all([sender_address, private_key, receiver_address, amount]):
            return jsonify({'error': 'All fields are required'}), 400

        try:
            amount = float(amount)
            if amount <= 0:
                return jsonify({'error': 'Amount must be positive'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid amount'}), 400

        value = web3.to_wei(amount, 'ether')
        nonce = web3.eth.get_transaction_count(sender_address)
        gas_price = web3.eth.gas_price

        tx = {
            'nonce': nonce,
            'to': receiver_address,
            'value': value,
            'gas': 2000000,
            'gasPrice': gas_price,
            'chainId': web3.eth.chain_id
        }

        signed_tx = web3.eth.account.sign_transaction(tx, private_key)
        raw_tx = signed_tx.rawTransaction if hasattr(signed_tx, 'rawTransaction') else signed_tx.raw_transaction
        tx_hash = web3.eth.send_raw_transaction(raw_tx)

        wallet = Wallet.query.filter_by(address=sender_address).first()
        if wallet:
            transaction = Transaction(tx_hash=web3.to_hex(tx_hash), wallet_id=wallet.id)
            db.session.add(transaction)
            db.session.commit()

        return jsonify({
            'transaction_hash': web3.to_hex(tx_hash)
        })
    except ValueError as ve:
        logging.error(f"Transaction error: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logging.error(f"Transaction error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_transactions', methods=['POST'])
@login_required
def get_transactions():
    try:
        wallet_id = request.json['wallet_id']
        transactions = Transaction.query.filter_by(wallet_id=wallet_id).all()
        return jsonify([{'tx_hash': tx.tx_hash} for tx in transactions])
    except Exception as e:
        logging.error(f"Transactions error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)