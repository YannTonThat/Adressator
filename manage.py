from flask import Flask, request, jsonify, session, render_template, send_from_directory, redirect, url_for
from flask_migrate import Migrate, upgrade, init, migrate
from flask_sqlalchemy import SQLAlchemy
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from datetime import datetime
from pytz import timezone
from sqlalchemy import Column, DateTime, text
from flask_mail import Mail
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from extensions import mail
from email_notification import envoyer_notification_recherche, envoyer_email_confirmation, generate_confirmation_token, confirm_token, envoyer_code_recuperation 
import logging
from random import randint
import os
import time
import jwt
import requests
import stripe
from sqlalchemy.exc import IntegrityError
from functools import wraps
from flask import abort
from app import app, db  # Importez votre application Flask et l'instance de SQLAlchemy


##app = Flask(__name__)
##app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
##db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialise Migrate

### Définition du modèle Utilisateur
##class Utilisateur(db.Model):
##    __tablename__ = 'utilisateur'
##    id = db.Column(db.Integer, primary_key=True)
##    google_id = db.Column(db.String(80), nullable=True)
##    nom = db.Column(db.String(80), nullable=False)
##    email = db.Column(db.String(120), unique=True, nullable=False)
##    password = db.Column(db.String(128), nullable=False)
##    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
##    is_active = db.Column(db.Boolean, default=False)
##    is_admin = db.Column(db.Boolean, default=False)
##    last_login = db.Column(db.DateTime, nullable=True)  # Nouveau champ
##
##    def set_password(self, password):
##        self.password_hash = generate_password_hash(password)
##
##    def check_password(self, password):
##        return check_password_hash(self.password_hash, password)
##

##class Recherche(db.Model):
##    __tablename__ = 'recherche'
##    id = db.Column(db.Integer, primary_key=True)
##    user_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=False)
##    url = db.Column(db.String(255), nullable=False)
##    statut = db.Column(db.String(50), default='en cours')
##    date_creation = db.Column(DateTime, default=lambda: datetime.now(france_tz).astimezone(france_tz))
##    adresse = db.Column(db.String(255), nullable=True)
##
##    utilisateur = db.relationship('Utilisateur', backref=db.backref('recherches', lazy=True))
##


if __name__ == '__main__':
    #app.run(debug=True, port=8000)
    from flask.cli import FlaskGroup

    cli = FlaskGroup(app)

    cli()
