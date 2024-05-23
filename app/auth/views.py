from flask import render_template, redirect, request, flash, url_for
from flask_mail import Message
from . import auth
from .forms import LoginForm, RegistrationForm
from .. import db, mail
from ..models import User, Role
from flask_login import login_user, login_required, logout_user, current_user
from threading import Thread


@auth.before_app_request
def before_request():
    """Perform checks and setup before each request.

    This function pings the current user to update their last_seen time.
    If the user is authenticated but not confirmed, they are redirected to the unconfirmed page.
    """
    if current_user.is_authenticated:
        current_user.ping()
        if (
                not current_user.confirmed
                and request.blueprint != 'auth'
                and request.endpoint != 'static'
                and request.endpoint != 'auth.confirm'
        ):
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/login', methods=['GET', 'POST'])
def login():
    """Log the user into the system.

    Displays the login form and handles user authentication. If the user provides valid credentials,
    they are logged in and redirected to the next page or the default page.
    """
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.password_verify(form.password.data):
            login_user(user)
            next_page = request.args.get("next")
            if next_page is None or not next_page.startswith('/'):
                next_page = url_for('main.set_cookie')
            return redirect(next_page)
        flash('Invalid email or password')
    return render_template("auth/login.html", form=form)


@auth.route("/register", methods=["GET", "POST"])
def register():
    """Process user registration.

    Displays the registration form and handles user account creation.
    Sends a confirmation email after successful registration.
    """
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            email=form.email.data,
            username=form.username.data,
            name=form.name.data,
            about_me=form.about_me.data,
            role=Role.query.get(form.role.data)
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_confirm(user, token)
        flash('Вам отправлено письмо для подтверждения аккаунта.')
        return redirect(url_for('auth.login'))
    return render_template("auth/registration.html", form=form)


@auth.route("/logout")
@login_required
def logout():
    """Log out the current user.

    Logs out the user and redirects them to the main page.
    """
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('main.set_cookie'))


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    """Confirm a user's account.

    Confirms the user's account using a token. If the token is valid, the user's account is confirmed.
    Otherwise, an error message is displayed.
    """
    if current_user.confirmed:
        flash("Ваш аккаунт уже подтвержден.")
        return redirect(url_for('main.set_cookie'))
    if current_user.confirm(token):
        db.session.commit()
        flash("Ваш аккаунт был подтвержден.")
        return redirect(url_for('auth.login'))
    else:
        flash("Ссылка для подтверждения недействительна или истекла.")
    return redirect(url_for('auth.login'))


@auth.route('/unconfirmed')
def unconfirmed():
    """Display the unconfirmed account page.

    If the user is not confirmed, they are redirected to this page.
    """
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.set_cookie'))
    return render_template('auth/unconfirmed.html')


def send_confirm(user, token):
    """Send account confirmation email.

    Sends a confirmation email to the user with a link to confirm their account.
    """
    confirm_url = url_for('auth.confirm', token=token, _external=True)
    send_mail(user.email, 'Подтвердите свою учетную запись', 'auth/confirm', user=user, confirm_url=confirm_url)


def send_mail(to, subject, template, **kwargs):
    """Send an email.

    Sends an email asynchronously using a separate thread.
    """
    msg = Message(subject, sender="poltest1708@gmail.com", recipients=[to])
    try:
        msg.html = render_template(template + ".html", **kwargs)
    except:
        msg.body = render_template(template + ".txt", **kwargs)
    from app_file import flask_app
    thread = Thread(target=send_async_email, args=[flask_app, msg])
    thread.start()
    return thread


def send_async_email(app, msg):
    """Send email asynchronously.

    Sends an email within the Flask app context to ensure the email is sent correctly.
    """
    with app.app_context():
        mail.send(msg)
