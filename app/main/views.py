from flask import render_template, session, flash, redirect, url_for, request
from flask_login import login_required, current_user
from app.models import User, Permission, Workout, Recommendation
from .. import db
from ..decorators import admin_required, permission_required
from . import main


@main.route('/')
@main.route('/home')
def set_cookie():
    """Render the home page and set a session cookie if not already set."""
    session_text = session.get('text')
    if session_text is not None or session_text != "":
        return render_template("home.html")
    else:
        return render_template("home.html")


@main.route('/user/<name>')
def hello_user(name):
    """Greet the user by name and display their profile page."""
    return render_template('user.html', name=name, current_user=current_user)


@main.route('/admin')
@login_required
@admin_required
def for_admin():
    """Display a message indicating this page is for admins only."""
    return "For admin"


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE)
def for_moderator():
    """Display a message indicating this page is for moderators only."""
    return "For moderator"


@main.route('/secret')
@login_required
def secret():
    """Display a message indicating this page is for authenticated users only."""
    return "Only for auth"


@main.route("/testConfirm")
def testConfirm():
    """Generate and confirm a test token for the first user in the database."""
    user = User.query.filter_by().first()
    tmp = user.generate_confirmation_token()
    user.confirm(tmp)


@main.route('/user/<username>')
def user(username):
    """Display the user's profile page based on their username."""
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=user)


@main.route('/profile')
def profile():
    """Render the profile page."""
    return render_template('profile.html')


@main.route('/add_workout', methods=['POST'])
@login_required
def add_workout():
    """Add a new workout for the current user."""
    workout_name = request.form.get('workout_name')
    workout_date = request.form.get('workout_date')

    if workout_name and workout_date:
        new_workout = Workout(
            name=workout_name, date=workout_date, user_id=current_user.id
        )
        db.session.add(new_workout)
        db.session.commit()
        flash('Тренировка успешно добавлена!', 'success')
    else:
        flash('Заполните все поля формы!', 'danger')

    return redirect(url_for('main.workouts'))


@main.route('/workouts')
def workouts():
    """Display the workouts page with the current user's workouts if authenticated."""
    if current_user.is_authenticated:
        user_workouts = Workout.query.filter_by(user_id=current_user.id).all()
        return render_template('workouts.html', workouts=user_workouts)
    else:
        return render_template('workouts.html')


@main.route('/progress')
@login_required
def progress():
    """Display the progress page with the current user's workouts."""
    workouts = Workout.query.filter_by(user_id=current_user.id).all()
    return render_template('progress.html', workouts=workouts)


@main.route('/history')
@login_required
def history():
    """Display the workout history page with the current user's workouts."""
    workouts = Workout.query.filter_by(user_id=current_user.id).all()
    return render_template('history.html', workouts=workouts)


@main.route('/recommendations')
def recommendations():
    """Display the recommendations page with all recommendations and admin options if applicable."""
    recommendations = Recommendation.query.all()
    is_admin = current_user.is_authenticated and current_user.is_admin()
    return render_template('recommendations.html', recommendations=recommendations, is_admin=is_admin)


@main.route('/add_recommendation', methods=['GET', 'POST'])
@login_required
@admin_required
def add_recommendation():
    """Add a new recommendation if the user is an admin."""
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        date = request.form.get('date')

        if title and description and date:
            new_recommendation = Recommendation(
                title=title,
                description=description,
                date=date,
                user_id=current_user.id
            )
            db.session.add(new_recommendation)
            db.session.commit()
            flash('Рекомендация успешно добавлена!')
            return redirect(url_for('main.recommendations'))
        else:
            flash('Заполните все поля формы!')

    return render_template('add_recommendation.html')


@main.app_errorhandler(401)
def unauthorized(error):
    """Handle 401 Unauthorized errors by rendering an unauthorized page."""
    return render_template('unauthorized.html'), 401
