from flask import Flask, request, jsonify, session, render_template, send_from_directory, redirect, url_for
from flask_migrate import Migrate, upgrade, init, migrate
from flask_sqlalchemy import SQLAlchemy
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from datetime import datetime, timedelta
from pytz import timezone
from sqlalchemy import Column, DateTime, text
from flask_mail import Mail
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from extensions import mail
from email_notification import envoyer_notification_recherche, envoyer_email_confirmation, generate_confirmation_token, confirm_token, envoyer_code_recuperation, envoyer_email_paiement
import logging
import traceback
from random import randint
import os
import time
import jwt
import requests
import stripe
from sqlalchemy.exc import IntegrityError
from functools import wraps
from flask import abort
from config import Config
#Sécurisation avec Talisman
from flask_talisman import Talisman
#Limitation des requêtes
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hashlib
import sys
from whitenoise import WhiteNoise




france_tz = timezone("Europe/Paris")

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
# Dictionnaire pour stocker temporairement les codes de récupération
recovery_codes = {}

# Initialisation de l'application Flask
app = Flask(__name__)
#Intégration de whitenoise pour optimiser le chargement des images et autres fichiers statiques
app.wsgi_app = WhiteNoise(app.wsgi_app, root="static/") 
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Utilisez vos configs SMTP
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
#Données obtenues à partir du fichier config.py
stripe.api_key = Config.STRIPE_API_KEY
app.secret_key = Config.APP_SECRET_KEY
SECRET_KEY = Config.SECRET_KEY
WEBHOOK_SECRET = Config.WEBHOOK_SECRET
app.config['MAIL_USERNAME'] = Config.APP_MAIL_USERNAME
app.config['MAIL_PASSWORD'] = Config.APP_MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = Config.APP_MAIL_DEFAULT_SENDER
app.config['SECURITY_PASSWORD_SALT'] = Config.SECURITY_PASSWORD_SALT
app.config['SECRET_KEY'] = Config.FLASK_SECRET_KEY
# Configuration de la base de données et des options SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = Config.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'timeout': 15, 'check_same_thread': False}}


# Configurer Flask-Talisman
#Talisman(app, force_https=False)

#Limitation des requêtes
# Configurer Flask-Limiter avec le nombre de requêtes par minute autorisées
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"]
)


# Initialise l'extension mail
mail.init_app(app)


# Initialisation de SQLAlchemy avec l'application Flask
db = SQLAlchemy(app)

# Configuration du mode journal WAL pour SQLite
with app.app_context():
    with db.engine.connect() as connection:
        connection.execute(text("PRAGMA journal_mode=WAL"))

#db.init_app(app)
#mail = Mail(app)  # Initialisez mail ici
# Initialisation de Flask-Mail
#init_mail(app)


# A Ajouter pour rediriger vers HTTPS en phase de production
##@app.before_request
##def before_request():
##    if not request.is_secure:
##        return redirect(request.url.replace("http://", "https://"), code=301)




##@app.route('/header-content')
##def header_content():
##    user_logged_in = 'user_id' in session
##    user_initial = session.get('user_initial', '')  # Récupère l'initiale de l'utilisateur s'il est connecté
##    return render_template('header.html', user_logged_in=user_logged_in, user_initial=user_initial)


def generate_unique_suffix():
    # Obtenir la date et l'heure actuelles
    now = datetime.now()
    # Convertir la date et l'heure en chaîne (format compact)
    timestamp = now.strftime("%Y%m%d%H%M%S")
    # Générer un hash (SHA256, par exemple) à partir du timestamp
    hash_object = hashlib.sha256(timestamp.encode('utf-8'))
    # Convertir en hexadécimal et prendre les 8 premiers caractères
    unique_suffix = hash_object.hexdigest()[:8]
    return unique_suffix



# Ajouter cette route au début du code de l'application
@app.route('/')
@limiter.limit("100 per minute")
def index():
    app.logger.info("Message affiché dans les logs Flask")
    #return send_from_directory('', 'index.html')  # '' indique le dossier courant
    user_logged_in = session.get('user_logged_in', False) # Vérifie l'état de connexion dans la session
    user_initial = session.get('user_initial', None)  # Récupère l'initiale de l'utilisateur s'il est connecté
    return render_template('index.html', user_logged_in=user_logged_in, user_initial=user_initial) # Affiche la page d'accueil


@app.route('/api/header-buttons', methods=['GET'])
def header_buttons():
    # Vérifie si l'utilisateur est connecté
    if 'user_id' in session:
        user_initial = session.get('user_initial', '')  # L'initiale de l'utilisateur, si définie
        user_logged_in = session.get('user_logged_in', False) #AJOUT A VERIFIER
        return jsonify({
            #'user_logged_in': True, #SUPPRESSION A VERIFIER
            'user_logged_in' : user_logged_in, #AJOUT A VERIFIER
            'user_initial': user_initial  # On envoie l'initiale pour le bouton
        }), 200
    else:
        # Utilisateur non connecté
        return jsonify({
            'user_logged_in': False
        }), 200


@app.route('/search')
@limiter.limit("100 per minute")
def search():
    user_logged_in = session.get('user_logged_in', False) # Vérifie l'état de connexion dans la session
    user_initial = session.get('user_initial', None)  # Récupère l'initiale de l'utilisateur s'il est connecté
    return render_template('search.html', user_logged_in=user_logged_in, user_initial=user_initial) # Affiche la page d'accueil


#Route pour Actualités et Conseils
@app.route('/actu')
@limiter.limit("100 per minute")
def actu():
    return render_template('actu-conseils.html')

@app.route('/article1')
@limiter.limit("100 per minute")
def article1():
    return render_template('article1.html')

@app.route('/article2')
@limiter.limit("100 per minute")
def article2():
    return render_template('article2.html')

@app.route('/article3')
@limiter.limit("100 per minute")
def article3():
    return render_template('article3.html')

@app.route('/simu-mensu-pret')
@limiter.limit("100 per minute")
def simu_mensu_pret():
    return render_template('simu-mensu-pret.html')

# Route pour la page de tableau de bord
@app.route('/dashboard')
@limiter.limit("100 per minute")
def dashboard():

    #return send_from_directory('.', 'dashboard.html')  # Le point (.) représente le dossier courant
     # Vérifie si l'utilisateur est connecté
    if 'user_id' not in session:
        # Redirige vers la page d'accueil s'il n'est pas connecté
        return redirect(url_for('index'))
    
    # L'utilisateur est connecté, récupère ses informations
    user_logged_in = True
    user_initial = session.get('user_initial', None)
    
    return render_template('dashboard.html', user_logged_in=user_logged_in, user_initial=user_initial)

#Route pour les CGU
@app.route('/CGU')
@limiter.limit("100 per minute")
def cgu():
    return render_template('CGU.html')

#Route pour les CGV
@app.route('/CGV')
@limiter.limit("100 per minute")
def cgv():
    return render_template('CGV.html')

#Route pour les Mentions légales
@app.route('/Mentions-légales')
@limiter.limit("100 per minute")
def mentions():
    return render_template('Mentions-légales.html')

#Route pour la Politique de Confidentialité
@app.route('/PDC')
@limiter.limit("100 per minute")
def PDC():
    return render_template('PDC.html')

#Route pour Contact
@app.route('/Contact')
@limiter.limit("100 per minute")
def contact():
    return render_template('Contact.html')

#Route pour FAQ
@app.route('/FAQ')
@limiter.limit("100 per minute")
def FAQ():
    return render_template('FAQ.html')

@app.route('/sitemap.xml')
@limiter.limit("100 per minute")
def sitemap():
    return send_from_directory('static', 'sitemap.xml', mimetype='application/xml')

@app.route('/robots.txt')
def robots():
    return send_from_directory('static', 'robots.txt', mimetype='text/plain')

class Utilisateur(db.Model):
    __tablename__ = 'utilisateur'
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(80), nullable=True)
    nom = db.Column(db.String(80), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    date_creation = db.Column(DateTime, default=lambda: datetime.now(france_tz).astimezone(france_tz))
    is_active = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)  # Ajoute un champ pour le rôle administrateur
    last_login = db.Column(db.DateTime, nullable=True)
    #is_logged_in = db.Column(db.Boolean, default=False, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Recherche(db.Model):
    __tablename__ = 'recherche'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    statut = db.Column(db.String(50), default='en cours')
    date_creation = db.Column(DateTime, default=lambda: datetime.now(france_tz).astimezone(france_tz))
    adresse = db.Column(db.String(255), nullable=True)
    is_paid = db.Column(db.Boolean, default=False)

    utilisateur = db.relationship('Utilisateur', backref=db.backref('recherches', lazy=True))




# Route pour gérer l'inscription
@app.route('/api/register', methods=['POST'])
def register_user():
    try:
        logging.debug("Requête d'inscription reçue.")

        # Récupérer les données envoyées
        data = request.get_json()
        nom =  "default_name"
        email = data.get("email")
        password = data.get("password")
        # Définir is_admin pour une adresse spécifique
        is_admin = True if email == "alexandra.abough@gmail.com" else False
        is_logged_in = True;

        # Vérifie si l'email est déjà dans la base de données
        utilisateur_existant = Utilisateur.query.filter_by(email=email, is_active=True).first()
        if utilisateur_existant:
            return jsonify({"message": "On vous connait déjà.", "existing_user": True}), 409


        # Hash du mot de passe
        hashed_password = generate_password_hash(password)

         
        # Valider que les champs requis sont présents
        if not email or not password:
            logging.error("Email ou mot de passe manquant dans la requête.")
            return 400


        #Ajout du nouvel utilisateur à la base de donnée
        nouvel_utilisateur = Utilisateur(nom=nom, email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(nouvel_utilisateur)
        db.session.commit()
        # Envoyer l'email de confirmation
        #from email_notification import envoyer_email_confirmation
        envoyer_email_confirmation(nouvel_utilisateur)
        logging.debug("Email de confirmation envoyé à : %s", email)
    
        return 201

    except IntegrityError:
        db.session.rollback()
        logging.error("Conflit d'email lors de l'inscription pour l'email : %s", email)
        return jsonify({"message": "Cet email est déjà utilisé."}), 409

    except Exception as e:
            db.session.rollback()
            logging.error("Erreur lors de l'inscription : %s", str(e))
            return jsonify({"message": "Erreur interne. Veuillez réessayer plus tard."}), 500


    
@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_token(token)
    print (f"Email présent dans confirm_email({token}) {email}")
    if not email:
        return jsonify({"message": "Le lien de confirmation est invalide ou a expiré."}), 400

    # Rechercher l'utilisateur et activer le compte
    user = Utilisateur.query.filter_by(email=email).first_or_404()
    if user.is_active:
        return redirect(url_for('index')),200
    else:
        user.is_active = True
        user.last_login = datetime.now(france_tz).astimezone(france_tz)  # Mise à jour de la dernière connexion
        db.session.commit()

        # Création de session pour l'utilisateur
        session['user_id'] = user.id
        session['user_logged_in'] = True
        session['user_initial'] = user.nom[0].upper()  # Initiale de l'utilisateur
        session['is_admin'] = user.is_admin  # Stocker le statut d'administrateur
        
        return render_template('registration_success.html'), 200

@app.route('/api/check-login', methods=['GET'])
def check_login():
    #is_logged_in = 'user_id' in session #SUPPRESSION A VERIFIER
    #is_logged_in = user.is_logged_in #AJOUT A VERIFIER
    is_logged_in = session.get('user_logged_in', False)
    return jsonify({"is_logged_in": is_logged_in})



@app.route('/api/add-user', methods=['POST'])
def add_user():
    data = request.json
    nom = data.get('nom', 'default_name')
    email = data.get('email', 'default_email@example.com')
    password = data.get('password', 'default_password')
    is_admin = data.get('is_admin', False)

    # Crée un nouvel utilisateur
    nouvel_utilisateur = Utilisateur(nom=nom, email=email, password=password, is_admin=is_admin)
    db.session.add(nouvel_utilisateur)
    db.session.commit()
    
    # Stocke l'ID de l'utilisateur dans la session
    session['user_id'] = nouvel_utilisateur.id
    

    return jsonify({"message": "Utilisateur créé avec succès", "success": True}), 201


@app.route('/api/send-url', methods=['POST'])
def send_url():

    user_id = session.get('user_id')  # Récupère l'ID de l'utilisateur depuis la session
    if not user_id:
        return jsonify({'success': False, 'message': 'Aucun user_id'}), 401
    
    utilisateur = Utilisateur.query.get(user_id)
    data = request.get_json()  # Récupère les données envoyées par le client
    url = data.get('url')  # L'URL soumise par l'utilisateur


    if not url:
        return jsonify({'success': False, 'message': 'URL manquante.'}), 400

    
    # Ajouter la nouvelle recherche dans la base de données
    nouvelle_recherche = Recherche(user_id=user_id, url=url, statut="en cours")
    db.session.add(nouvelle_recherche)
    db.session.flush()
    db.session.commit()

    envoyer_notification_recherche(utilisateur, nouvelle_recherche)
    

    # Notifier l'administrateur (logique simplifiée ici)
    print(f"Nouvelle recherche envoyée par l'utilisateur {user_id}: {url}")

    return jsonify({'success': True, 'message': "Recherche envoyée et notification envoyée à l'administrateur !"}), 200



@app.route('/api/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url')
    
    if is_valid_url(url):
        return jsonify({'message': 'URL valide.'}), 200
    else:
        return jsonify({'message': 'URL invalide.'}), 450
    
# Fonction de vérification de la validité de l'URL
def is_valid_url(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        print(f"response = {response.status_code}")
        return response.status_code in [200, 403]
    except requests.RequestException:
        return False

@app.route('/api/get-user-searches', methods=['GET'])
def get_user_searches():
    if 'user_id' not in session:
        return jsonify({'error': 'Utilisateur non connecté'}), 403

    user_id = session['user_id']
    recherches = Recherche.query.filter_by(user_id=user_id).all()
    search_data = [{'id': recherche.id, 'url': recherche.url, 'statut': recherche.statut, 'date_creation': recherche.date_creation.strftime('%Y-%m-%d %H:%M'), 'adresse': recherche.adresse} for recherche in recherches]

    return jsonify(search_data)


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # Rechercher l'utilisateur dans la base de données
    user = Utilisateur.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password, password):
        if not user.is_active:
            return jsonify({"message": "Veuillez confirmer votre inscription par e-mail."}), 403

        # Mise à jour de la date de dernière connexion
        user.last_login = datetime.now(france_tz).astimezone(france_tz)
        #user.is_logged_in = True #AJOUT A VERIFIER
        db.session.commit()
        
        # Création d'une session pour l'utilisateur
        session['user_id'] = user.id
        session['user_logged_in'] = True
        session['user_initial'] = user.nom[0].upper()  # Initiale de l'utilisateur
        session['is_admin'] = user.is_admin  # Stocker le statut d'administrateur
        return jsonify({
            "message": "Connexion réussie.",
            "user_logged_in": session['user_logged_in'],
            "user_initial": session['user_initial'],
            "is_admin": session['is_admin']
        }), 200
    else:
        return jsonify({"message": "E-mail ou mot de passe incorrect."}), 401

@app.route('/logout')
def logout():
    session.clear()
    #user.is_logged_in = False #AJOUT A VERIFIER
    session['user_logged_in'] = False
    return redirect(url_for('index'))  # Redirige vers la page d'accueil

# Dans app.py, pour injecter la variable `user_logged_in` dans tous les templates
@app.context_processor
def inject_user():
    #user_logged_in = 'user_id' in session
    user_logged_in = session.get('user_logged_in', False) # A VERIFIER
    return dict(user_logged_in=user_logged_in)

# Endpoint pour gérer la connexion Google
@app.route('/api/auth/google', methods=['POST'])
def google_login():
    token = request.json.get('id_token')
    try:
        # Vérifier le token Google /!\ A MODIFIER POUR LA VERSION PRODUCTION 434261287317-9djqaj05oio6rldc55sq67b17pjnv4jj.apps.googleusercontent.com
        # Version locale : '434261287317-f5mhnvrf5gp41aevuhcivv9euc671498.apps.googleusercontent.com'
        # Version Heroku : '434261287317-cb4sjdrpveidesagf210jnf7qtt0lbg5.apps.googleusercontent.com'
        # Version GitHub : '434261287317-9djqaj05oio6rldc55sq67b17pjnv4jj.apps.googleusercontent.com'
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), '434261287317-cb4sjdrpveidesagf210jnf7qtt0lbg5.apps.googleusercontent.com')
        
        # Extraire les informations de l'utilisateur
        google_id = idinfo['sub']
        nom = idinfo.get('name', 'Utilisateur')
        email = idinfo.get('email')

        # Vérifier si l'utilisateur existe déjà
        utilisateur = Utilisateur.query.filter_by(google_id=google_id).first()
        
        if not utilisateur:
            # Ajouter un nouvel utilisateur
            utilisateur = Utilisateur(google_id=google_id, nom=nom, email=email)
            db.session.add(utilisateur)
            db.session.flush()
            db.session.commit()
        
        # Enregistrer l'utilisateur dans la session
        session['user_initial'] = utilisateur.nom[0].upper()
        session['user_id'] = utilisateur.id
        return jsonify({'message': 'Connexion réussie', 'user': {'nom': utilisateur.nom, 'email': utilisateur.email}})

    except ValueError:
        # Le token est invalide
        return jsonify({'error': 'Token invalide'}), 401

#------------------Mot de passe oublié ------------------#
@app.route('/api/send-recovery-code', methods=['POST'])
def send_recovery_code():
    data = request.get_json()
    email = data.get('email')

    user = Utilisateur.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Email non trouvé."}), 404

    # Génère un code à 4 chiffres
    code = f"{randint(1000, 9999)}"
    recovery_codes[email] = code

    # Envoie le code par email
    envoyer_code_recuperation(email, code)
    return jsonify({"message": "Code envoyé"}), 200

@app.route('/api/check-code', methods=['POST'])
def check_code():
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    if recovery_codes.get(email) == code:
        return jsonify({"message": "Code correct"}), 200
    else:
        return jsonify({"message": "Code incorrect"}), 400

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('newPassword')

    user = Utilisateur.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Utilisateur non trouvé."}), 404

    # Met à jour le mot de passe
    user.password = generate_password_hash(new_password)
    db.session.commit()

    # Supprime le code de récupération
    del recovery_codes[email]
    return jsonify({"message": "Mot de passe mis à jour avec succès.", "success": True}), 200

#------------------Fin Mot de passe oublié ------------------#

#------------------Modifier son Mot de passe ----------------#
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():


    user_logged_in = 'user_id' in session
    user_initial = session.get('user_initial', None)  # Récupère l'initiale de l'utilisateur s'il est connecté
    
    if request.method == 'GET':
        if 'user_id' in session:
            return render_template('change-password.html', user_logged_in=user_logged_in, user_initial=user_initial)
        else:
            return redirect(url_for('index'))  # Redirige vers l'accueil si l'utilisateur n'est pas connecté
    # Traitement du changement de mot de passe lors de la soumission du formulaire
    elif request.method == 'POST':
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        user_id = session.get('user_id')

        user = Utilisateur.query.get(user_id)

        # Vérifier le mot de passe actuel
        if user and check_password_hash(user.password, current_password):
            user.password = generate_password_hash(new_password)
            db.session.commit()
            return jsonify({"message": "Mot de passe mis à jour avec succès."}), 200
        else:
            return jsonify({"message": "Mot de passe actuel incorrect."}), 401

@app.route('/api/check-password', methods=['POST'])
def check_password():
    data = request.get_json()
    current_password = data.get('current_password')
    
    # Récupère l'utilisateur actuel
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"message": "Utilisateur non connecté"}), 401

    utilisateur = Utilisateur.query.get(user_id)
    if not utilisateur:
        return jsonify({"message": "Utilisateur non trouvé"}), 404

    # Vérifie si le mot de passe est correct
    if check_password_hash(utilisateur.password, current_password):
        return jsonify({"valid": True}), 200
    else:
        return jsonify({"valid": False}), 200
#------------------Fin Modifier son Mot de passe ----------------#

    

#---------------------- Page de Paiement ---------------------#

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:

        # Extraire les données de la requête POST
        data = request.get_json()
        user_id = session.get('user_id')
        is_logged_in = data.get('is_logged_in', False)  # Récupérer l'état de connexion depuis la requête
        url = data.get('url')
        app.logger.info(f"Etat de connexion is_logged_in récupéré : {is_logged_in}")

        if not url:
            return jsonify(error="URL manquante"), 400

        app.logger.info(f"Création de session de paiement. User ID: {user_id}, is_logged_in: {is_logged_in}")

        # Créer une session de paiement Stripe
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            customer_creation='always',  # Crée toujours un client Stripe pour capturer l'email
            line_items=[{
                'price_data': {
                    'currency': 'eur',
                    'product_data': {
                        'name': 'Vous recevrez l\'adresse du bien sous 1 à 72h. Si nous ne trouvons pas, vous serez intégralement remboursé.',
                    },
                    'unit_amount': 990,  # Prix en centimes (ex. 3000 = 30,00 EUR)
                },
                'quantity': 1,
            }],
            mode='payment',
            #success_url=f"http://localhost:8000/payment-success?session_id={{CHECKOUT_SESSION_ID}}",
            #cancel_url="http://localhost:8000/payment-cancel",
            success_url=f"http://www.adressator.com/payment-success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url="http://www.adressator.com/payment-cancel",
            
            metadata={
                'user_id': user_id,  # Ajouter l'ID de l'utilisateur connecté
                'is_logged_in': str(is_logged_in),  # Passer la connexion sous forme de chaîne (True/False)
                'url': url  # Ajout de l'URL comme métadonnée
            }

            #customer_email=request.json.get('email'),  # Capture l'e-mail de l'utilisateur
        )

        # Rediriger vers la page de paiement Stripe
        return jsonify({'url': checkout_session.url})
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/payment-success')
def payment_success():
    
    # Exemple de récupération des informations de session Stripe pour afficher les détails
    session_id = request.args.get('session_id')
    print(f"Session ID reçu : {session_id}")
    if not session_id:
        return redirect(url_for('index'))  # Redirige vers la page d'accueil si aucun session_id n'est trouvé

    try:
        session = stripe.checkout.Session.retrieve(session_id)
        customer_email = session.get('customer_details', {}).get('email')
        url_searched = session.get('metadata', {}).get('url')
        order_date = session.get('created')  # Timestamp Unix
        # Convertir la date Unix en un format lisible
        order_date = datetime.utcfromtimestamp(order_date)
        # Ajouter une heure
        order_date += timedelta(hours=1)
        # Convertir en chaîne lisible
        order_date = order_date.strftime('%Y-%m-%d %H:%M:%S')

        # Identifier l'utilisateur connecté 
        user_id = session.get('metadata', {}).get('user_id')
        is_logged_in = session.get('metadata', {}).get('is_logged_in', 'False').lower() in ['true', '1']
        app.logger.info(f"ID utilisateur : {user_id}, est connecté : {is_logged_in}")


        if user_id and customer_email:
            user = Utilisateur.query.get(user_id)
            if user:
                                
                # Mettre à jour l'email de l'utilisateur s'il n'est pas connecté
                if not is_logged_in:
                    logged_user_email=""
                    #Géner un suffixe unique et mettre à jour l'utilisateur pour intégrer son customer_email
                    unique_suffix = generate_unique_suffix()
                    user.email = f"{customer_email}&{unique_suffix}"
                    try:
                        db.session.commit()
                        app.logger.info(f"Email mis à jour pour l'utilisateur {user_id}.")
                    except Exception:
                        db.session.rollback()
                        app.logger.info(f"Erreur lors de la mise à jour de la base de données : {e}")
                    #Envoyer un mail au customer_email 
                    envoyer_email_paiement(customer_email, url_searched)
                    

                else:
                    app.logger.info(f"L'utilisateur {user_id} est connecté, pas de mise à jour de son email dans la database.")
                    #Si l'email renseigné dans stripe correspond à l'email de l'utilisateur connecté, on envoit 1 seul mail
                    logged_user_email=user.email
                    if logged_user_email==customer_email:
                        envoyer_email_paiement(customer_email, url_searched)
                    #Si l'email renseigné dans stripe est différent de l'email de l'utilisateur connecté, on envoit 1 mail à chaque adresse
                    else:
                        envoyer_email_paiement(logged_user_email, url_searched)
                        envoyer_email_paiement(customer_email, url_searched)
                        
            else:
                app.logger.info(f"Aucun utilisateur trouvé avec l'ID {user_id}.")
        else:
            app.logger.info("Données manquantes : user_id ou email.")

        app.logger.info(f"Conversion finale de is_logged_in : {is_logged_in}")


        # Convertir user_id en entier si existant
        user_id = int(user_id) if user_id else None

        # Vérification des données
        if user_id and url_searched:
            marquer_recherche_payee(user_id, url_searched)


        return render_template('payment-success.html',
                               logged_user_email = logged_user_email,
                               customer_email=customer_email,
                               url_searched=url_searched,
                               order_date=order_date)
    
    except stripe.error.InvalidRequestError as e:
        app.logger.error(f"Erreur Erreur lors du traitement du paiement : {e}")
        return redirect(url_for('index'))

@app.route('/payment-cancel')
def payment_cancel():
    return redirect(url_for('index'))


@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        # Vérifier l'authenticité du webhook
        event = stripe.Webhook.construct_event(
            payload, sig_header, WEBHOOK_SECRET
        )
    except ValueError:
        # Payload invalide
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        # Signature invalide
        return 'Invalid signature', 400

    # Gestion des événements Stripe
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']

        # Log complet de la session pour débogage
        app.logger.info("Contenu de la session Stripe :", session)

        # Extraire l'email de la session
        customer_email = session.get('customer_details', {}).get('email')
        app.logger.info("Email récupéré :", customer_email)

        # Identifier l'utilisateur connecté dans votre application (par ex. via session)
        user_id = session.get('metadata', {}).get('user_id')
        app.logger.info("ID utilisateur :", user_id)

        if user_id and customer_email:
            # Mettre à jour l'utilisateur
            user = Utilisateur.query.get(user_id)
            if user:
                #Géner un suffixe unique
                unique_suffix = generate_unique_suffix()
                #user.email = f"{customer_email}&{unique_suffix}"
                user.email = customer_email
                try:
                    db.session.commit()
                    app.logger.info(f"Email mis à jour pour l'utilisateur {user_id}.")
                except Exception:
                    db.session.rollback()
                    app.logger.info(f"Erreur lors de la mise à jour de la base de données : {e}")
            else:
                app.logger.info(f"Aucun utilisateur trouvé avec l'ID {user_id}.")
        else:
            app.logger.info("Données manquantes : user_id ou email.")

    return '', 200


def marquer_recherche_payee(user_id, url):
    """
    Met à jour l'attribut is_paid à True pour la recherche correspondant à l'utilisateur et l'URL.
    """
    try:
        # Rechercher la dernière recherche correspondant au user_id et à l'url
        recherche = Recherche.query.filter_by(user_id=user_id, url=url, is_paid=False).first()

        if recherche:
            recherche.is_paid = True
            db.session.commit()
            app.logger.info(f"Recherche payée mise à jour pour user_id {user_id} et url {url}.")
        else:
            app.logger.warning(f"Aucune recherche en attente de paiement trouvée pour user_id {user_id} et url {url}.")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de la mise à jour de la recherche payée : {e}")



#-------------------- Fin Page de Paiement ---------------------#


#-------------------- Suppression de compte --------------------#
@app.route('/delete-account')
def delete_account_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirige l'utilisateur vers la page de connexion s'il n'est pas connecté
    return render_template('delete-account.html')



# Route pour supprimer le compte de l'utilisateur connecté
@app.route('/api/delete-account', methods=['POST'])
def delete_account():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"message": "Vous devez être connecté pour supprimer votre compte."}), 401

    user = Utilisateur.query.get(user_id)
    if not user:
        return jsonify({"message": "Utilisateur introuvable."}), 404

    try:
        # Suppression des recherches de l'utilisateur avant de supprimer son compte
        Recherche.query.filter_by(user_id=user_id).delete()
        db.session.commit()  # On valide la suppression des recherches avant de supprimer l'utilisateur

        # Suppression de l'utilisateur
        db.session.delete(user)
        db.session.commit()

        # Déconnexion de l'utilisateur
        session.clear()

        return jsonify({"message": "Votre compte a été supprimé avec succès."}), 200

    except Exception as e:
        db.session.rollback()  # Annule toutes les modifications en cas d'erreur
        print("Erreur lors de la suppression du compte :", str(e))
        traceback.print_exc()  # Afficher l'erreur complète
        return jsonify({"message": "Erreur lors de la suppression du compte."}), 500


    
#------------------- Fin Suppression de compte -----------------#

#------------------- Page admnistrateur -----------------#
    
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return abort(403)  # Erreur "Forbidden" si l'utilisateur n'est pas admin
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@admin_required
def admin_page():
    return render_template('admin.html')

@app.route('/api/admin/data', methods=['GET'])
def get_admin_data():
    if not session.get('is_admin'):
        return jsonify({"message": "Accès non autorisé."}), 403

    # Récupérer les données depuis la base de données
    searches = Recherche.query.all()
    data = [{
        "user_id": search.user_id,
        #"nom": search.utilisateur.nom,
        "email": search.utilisateur.email,
        "search_id": search.id,
        "url": search.url,
        "date_creation": search.date_creation,
        "status": search.statut,
        "is_paid": search.is_paid,
        "adresse": search.adresse
    } for search in searches]

    return jsonify(data)

@app.route('/api/admin/update-status', methods=['POST'])
def update_status():
    if not session.get('is_admin'):
        return jsonify({"message": "Accès non autorisé."}), 403

    data = request.get_json()
    search_id = data.get('search_id')
    status = data.get('status')
    adresse = data.get('adresse')

    search = Recherche.query.get(search_id)
    if search:
        search.statut = status
        search.adresse = adresse
        db.session.commit()
        return jsonify({"message": "Recherche mise à jour avec succès."}), 200
    return jsonify({"message": "Recherche introuvable."}), 404





@app.route('/api/add-user-manually', methods=['POST'])
def add_user_manually():
    data = request.get_json()
    nom = data.get("nom")
    email = data.get("email")
    password = data.get("password")
    is_active = data.get('is_active', False)
    is_admin = data.get("is_admin", False)
    
    if Utilisateur.query.filter_by(email=email).first():
        return jsonify({"message": "L'email existe déjà."}), 409
    
    hashed_password = generate_password_hash(password)
    new_user = Utilisateur(nom=nom, email=email, password=hashed_password, is_active=is_active, is_admin=is_admin)
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "Utilisateur ajouté avec succès."}), 201

@app.route('/api/add-search', methods=['POST'])
def add_search():
    data = request.get_json()
    user_id = data.get("user_id")
    url = data.get("url")
    
    user = Utilisateur.query.get(user_id)
    if not user:
        return jsonify({"message": "Utilisateur non trouvé."}), 404
    
    new_search = Recherche(user_id=user_id, url=url)
    db.session.add(new_search)
    db.session.commit()
    
    return jsonify({"message": "Recherche ajoutée avec succès."}), 201


@app.route('/api/delete-user', methods=['POST'])
def delete_user():
    data = request.get_json()
    user_id = data.get('id')
    email = data.get('email')

    # Rechercher l'utilisateur par ID ou email
    user = None
    if user_id:
        user = Utilisateur.query.get(user_id)
    elif email:
        user = Utilisateur.query.filter_by(email=email).first()

    if not user:
        return jsonify({"success": False, "message": "Utilisateur introuvable."}), 404

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"success": True, "message": "Utilisateur supprimé avec succès."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": "Erreur lors de la suppression de l'utilisateur."}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    users = Utilisateur.query.all()
    user_data = [
        {
            "id": user.id,
            "email": user.email,
            "nom": user.nom,
            "password": user.password,  # hashé
            "is_admin": user.is_admin,
            "is_active": user.is_active,
            "last_login": user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Jamais connecté'
        }
        for user in users
    ]
    return jsonify(user_data), 200

@app.route('/api/delete-search-admin', methods=['POST'])
def delete_search_admin():
    # Récupérer l'ID de la recherche à partir des données de la requête
    data = request.get_json()
    search_id = data.get('search_id')

    if not search_id:
        return jsonify({"message": "ID de recherche requis pour la suppression."}), 400

    # Rechercher la recherche dans la base de données
    search = Recherche.query.get(search_id)
    if not search:
        return jsonify({"message": "Recherche introuvable."}), 404

    try:
        # Supprimer la recherche de la base de données
        db.session.delete(search)
        db.session.commit()

        return jsonify({"message": "Recherche supprimée avec succès."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Erreur lors de la suppression de la recherche."}), 500

@app.route('/api/update-user', methods=['POST'])
def update_user():
    data = request.get_json()
    user_id = data.get('user_id')
    email = data.get('email')
    
    # Vérifier que soit l'ID soit l'email est fourni
    if not user_id and not email:
        return jsonify({"message": "ID ou email requis pour identifier l'utilisateur."}), 400

    # Rechercher l'utilisateur par ID ou email
    user = None
    if user_id:
        user = Utilisateur.query.get(user_id)
    elif email:
        user = Utilisateur.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "Utilisateur introuvable."}), 404

    # Mettre à jour les champs modifiables
    user.nom = data.get('nom', user.nom)
    user.email = data.get('email', user.email)
    user.password = generate_password_hash(data.get('password')) if data.get('password') else user.password
    user.is_active = data.get('is_active', user.is_active)
    user.is_admin = data.get('is_admin', user.is_admin)

    try:
        db.session.commit()
        return jsonify({"message": "Utilisateur mis à jour avec succès."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Erreur lors de la mise à jour de l'utilisateur."}), 500

@app.route('/api/get-user', methods=['POST'])
def get_user():
    data = request.get_json()
    user_id = data.get('user_id')
    email = data.get('email')

    # Vérifier que l'ID ou l'email est fourni
    if not user_id and not email:
        return jsonify({"message": "ID ou email requis pour trouver l'utilisateur."}), 400

    # Rechercher l'utilisateur par ID ou email
    user = None
    if user_id:
        user = Utilisateur.query.get(user_id)
    elif email:
        user = Utilisateur.query.filter_by(email=email).first()

    # Si l'utilisateur n'est pas trouvé
    if not user:
        return jsonify({"message": "Utilisateur introuvable."}), 404

    # Retourner les informations de l'utilisateur
    return jsonify({
        "user": {
            "id": user.id,
            "nom": user.nom,
            "email": user.email,
            "is_active": user.is_active,
            "is_admin": user.is_admin
        }
    }), 200




#------------------- Fin Page admnistrateur -----------------#  

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # S'assure que la BDD existe (sans la recréer à chaque fois)
    
    sys.stdout = sys.stderr  # Redirige stdout vers stderr pour affichage immédiat dans les logs

    #Pour lancer l'app sur le port 8000 en local, décommenter la ligne ci-dessous, et commenter les lignes suivantes
    #app.run(debug=True, port=8000)

    # Récupère le port assigné par Heroku (ou 5000 en local)
    port = int(os.environ.get("PORT", 5000))

    # Lancer l'application sur 0.0.0.0 (nécessaire pour Heroku)
    app.run(debug=False, host="0.0.0.0", port=port)

