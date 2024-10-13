from flask import Flask, request, jsonify, session, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
db = SQLAlchemy(app)

# Ajouter cette route au début du code de l'application
@app.route('/')
def home():
    return send_from_directory('', 'index.html')  # '' indique le dossier courant

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
        # Version locale : 434261287317-f5mhnvrf5gp41aevuhcivv9euc671498.apps.googleusercontent.com'
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), '434261287317-9djqaj05oio6rldc55sq67b17pjnv4jj.apps.googleusercontent.com')
        
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
        session['user_id'] = utilisateur.id
        return jsonify({'message': 'Connexion réussie', 'user': {'nom': utilisateur.nom, 'email': utilisateur.email}})

    except ValueError:
        # Le token est invalide
        return jsonify({'error': 'Token invalide'}), 401

# Création de la base de données avec le contexte d'application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
