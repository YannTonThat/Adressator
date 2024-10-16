from flask import Flask, request, jsonify, session, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
db = SQLAlchemy(app)

# Ajouter cette route au début du code de l'application
@app.route('/')
def home():
    return send_from_directory('', 'index.html')  # '' indique le dossier courant

# Route pour la page de tableau de bord
@app.route('/dashboard.html')
def dashboard():
    return send_from_directory('.', 'dashboard.html')  # Le point (.) représente le dossier courant

# Autres routes de ton application (à compléter)


# Modèle Utilisateur
class Utilisateur(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(255), unique=True, nullable=False)
    nom = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)

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
            db.session.commit()
        
        # Enregistrer l'utilisateur dans la session
        session['user_initial'] = utilisateur.nom[0].upper()
        session['user_id'] = utilisateur.id
        return jsonify({'message': 'Connexion réussie', 'user': {'nom': utilisateur.nom, 'email': utilisateur.email, 'initial': session['user_initial']}})


    except ValueError:
        # Le token est invalide
        return jsonify({'error': 'Token invalide'}), 401

# Création de la base de données avec le contexte d'application
if __name__ == '__main__':
    # Utiliser le contexte d'application pour créer la base de données une fois
    with app.app_context():
        db.create_all()
    
    # Récupérer le port assigné par Heroku
    port = int(os.environ.get("PORT", 5000))
    
    # Lancer l'application en écoutant sur le port dynamique
    app.run(debug=True, host="0.0.0.0", port=port)
