from flask_mail import Message
from flask import url_for, current_app
from extensions import mail
from itsdangerous import URLSafeTimedSerializer

# Initialise Flask-Mail avec l'application Flask
#mail = Mail()

##def init_mail(app):
##    # Configure Flask-Mail
##    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
##    app.config['MAIL_PORT'] = 587
##    app.config['MAIL_USE_TLS'] = True
##    app.config['MAIL_USERNAME'] = 'alexandra.abough@gmail.com'
##    app.config['MAIL_PASSWORD'] = 'wyca chuq beuc shkg'
##    app.config['MAIL_DEFAULT_SENDER'] = ('Adressator', 'alexandra.abough@gmail.com')
##    mail.init_app(app)


def envoyer_notification_recherche(user, recherche):
    # Envoie un email avec les informations de recherche de l'utilisateur
    with current_app.app_context():
        msg = Message(subject=f"#000{recherche.id} Nouvelle recherche envoyée",
                      recipients=['alexandra.abough@gmail.com','adressator.team@gmail.com','yann.tonthat@gmail.com'])  # Remplacez par l'email de l'administrateur

        # Contenu de l'email
        msg.body = f"""
        Une nouvelle recherche a été envoyée par l'utilisateur {user.nom} ({user.email}).

        Informations de la recherche :
        - ID Utilisateur : {user.id}
        - ID Recherche : {recherche.id}
        - URL : {recherche.url}
        - Statut : {recherche.statut}
        - Date de création : {recherche.date_creation}

        Amuse toi bien, Adressator.
        """
        mail.send(msg)


##def envoyer_email_paiement(customer_email, url):
##    # Envoie un email avec les informations de recherche de l'utilisateur
##    with current_app.app_context():
##        msg = Message(subject=f"Confirmation de votre demande sur Adressator",
##                      recipients=[customer_email],
##                      bcc=[admin_email])
##
##        # Contenu de l'email
##        # Contenu HTML de l'email avec stylisation
##        msg.html = f"""
##        <html>
##        <head>
##            <style>
##                body {{
##                    font-family: Arial, sans-serif;
##                    background-color: #72ab19;
##                    padding: 20px;
##                }}
##                .container {{
##                    max-width: 600px;
##                    background: #ffffff;
##                    padding: 20px;
##                    border-radius: 10px;
##                    box-shadow: 0px 0px 10px #ccc;
##                }}
##                .header {{
##                    background: #0073e6;
##                    color: white;
##                    padding: 10px;
##                    text-align: center;
##                    font-size: 20px;
##                    font-weight: bold;
##                    border-top-left-radius: 10px;
##                    border-top-right-radius: 10px;
##                }}
##                .content {{
##                    padding: 20px;
##                    color: #333;
##                }}
##                .footer {{
##                    text-align: center;
##                    font-size: 14px;
##                    color: #666;
##                    margin-top: 20px;
##                }}
##                .button {{
##                    display: inline-block;
##                    padding: 10px 20px;
##                    background: #0073e6;
##                    color: #ffffff;
##                    text-decoration: none;
##                    border-radius: 20px;
##                    font-weight: bold;
##                }}
##                .centered-container {{
##                    display : flex;
##                    flex-direction : column;
##                    text-align : center;
##                    justify-content : center;
##                }}
##                
##            </style>
##        </head>
##        <body>
##            <div class="container">
##                <div class="header" style="background:#0073e6">Votre demande a bien été reçue !</div>
##                <div class="content">
##                    <p>Bonjour,</p>
##                    <p>Nous avons bien reçu votre demande et la traitons actuellement.</p>
##                    <p><strong>Récapitulatif :</strong></p>
##                    <ul>
##                        <li><strong>Lien soumis :</strong> {url}</li>
##                        <li><strong>Coût du service :</strong> 9,90 € TTC</li>
##                        <li><strong>Statut :</strong> En cours de traitement</li>
##                    </ul>
##                    <p>Notre équipe s’engage à traiter votre demande dans les meilleurs délais.</p>
##                    <p>Vous recevrez généralement l’adresse correspondante <strong>dans la journée</strong>, et au plus tard sous <strong>3 jours ouvrés</strong>.</p>
##                    <p style="justify-content: center">Si vous avez des questions, contactez-nous :</p>
##                    <div class=centered-container style="justify-content: center"><a href="mailto:adressator.team@gmail.com" class="button" style="color:white">Nous contacter</a></div>
##                </div>
##                <div class="footer">
##                    Merci de faire confiance à Adressator !<br>
##                    <a href="https://www.adressator.com">www.adressator.com</a>
##                </div>
##            </div>
##        </body>
##        </html>
##        """
##
##        mail.send(msg)


def envoyer_email_paiement(customer_email, url):
    admin_email = "adressator.team@gmail.com"

    with current_app.app_context():
        msg = Message(
            subject="Confirmation de votre demande sur Adressator",
            recipients=[customer_email],
            bcc=[admin_email]
        )

        msg.html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
            <div style="max-width: 600px; background: #ffffff; padding: 20px; border-radius: 10px; 
                        box-shadow: 0px 0px 10px #ccc; margin: auto;">
                <!-- HEADER -->
                <div style="background: #72ab19; color: white; padding: 10px; text-align: center; 
                            font-size: 20px; font-weight: bold; border-top-left-radius: 10px;
                            border-top-right-radius: 10px;">
                    Votre demande a bien été reçue !
                </div>

                <!-- CONTENU -->
                <div style="padding: 20px; color: #333;">
                    <p>Bonjour,</p>
                    <p>Nous avons bien reçu votre demande et la traitons actuellement.</p>
                    <p><strong>Récapitulatif :</strong></p>
                    <ul>
                        <li><strong>Lien soumis :</strong> {url}</li>
                        <li><strong>Coût du service :</strong> 9,90 € TTC</li>
                        <li><strong>Statut :</strong> En cours de traitement</li>
                    </ul>
                    <p>Notre équipe s’engage à traiter votre demande dans les meilleurs délais.</p>
                    <p>Vous recevrez généralement l’adresse correspondante <strong>dans la journée</strong>, 
                       et au plus tard sous <strong>3 jours ouvrés</strong>.</p>

                    <p style="text-align: center;">Si vous avez des questions, contactez-nous :</p>

                    <!-- BOUTON CENTRÉ -->
                    <table role="presentation" align="center" style="margin: auto;">
                        <tr>
                            <td style="background: #72ab19; padding: 12px 24px; border-radius: 20px; text-align: center;">
                                <a href="mailto:adressator.team@gmail.com" 
                                   style="color: white; text-decoration: none; font-weight: bold;">
                                    Nous contacter
                                </a>
                            </td>
                        </tr>
                    </table>
                </div>

                <!-- FOOTER -->
                <div style="text-align: center; font-size: 14px; color: #666; margin-top: 20px;">
                    Merci de faire confiance à Adressator !<br>
                    <a href="https://www.adressator.com" style="color: #0073e6;">www.adressator.com</a>
                </div>
            </div>
        </body>
        </html>
        """

        mail.send(msg)


def envoyer_email_confirmation(user):
    token = generate_confirmation_token(user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Adressator : Confirmez votre inscription"
    msg = Message(subject=subject, recipients=[user.email])
    msg.body = f'Bonjour !\n\nCliquez sur le lien pour confirmer votre inscription : {confirm_url}\n\nMerci !\n\n Equipe Adressator'
    mail.send(msg)


# Créer une instance de serializer pour générer des tokens
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    token = serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])
    print(f"Token généré pour {email}: {token}")  # Log
    return token


def confirm_token(token, expiration=86400):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=current_app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        print(f"Token confirmé pour {email}")  # Log
    except Exception as e:
        print("Erreur lors de la vérification du token:", str(e))  # Log d'erreur
        return False
    return email


#Code de récupération
def envoyer_code_recuperation(email, code):
    with current_app.app_context():
        subject = "Code de récupération de mot de passe"
        msg = Message(subject=subject, recipients=[email])
        msg.body = f"Votre code de récupération de mot de passe est : {code}"
        mail.send(msg)
