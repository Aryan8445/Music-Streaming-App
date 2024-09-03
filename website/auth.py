from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import *
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, logout_user, current_user, login_required
auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if not user.is_blacklisted:
                if check_password_hash(user.password, password):
                    flash('Logged in successfully', category='success')
                    login_user(user, remember=True)
                    return redirect(url_for('controllers.home'))
                else:
                    flash('Incorect password, try again.', category='error')
            else:
                flash('You have been placed on the blacklist, and as a result, logging in is not permitted.', category='error')
        else:
            flash('User does not exixt', category='error')
    return render_template('login.html', user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('controllers.index'))


@auth.route('/sign_up', methods=['GET', 'POST'])
def sign_up():

    if request.method == 'POST':

        email = request.form.get('email')
        firstname = request.form.get('firstName')
        lastname = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user_type = 'user'

        user = User.query.filter_by(
            email=email, firstname=firstname, lastname=lastname).first()
        if user:
            flash('Email already exist! Please login.', category='error')
        elif len(email) < 4:
            flash('Email must contain at least 4 characters. ', category='error')
        elif len(firstname) < 2:
            flash('First name must contain at least 2 characters. ', category='error')
        elif password1 != password2:
            flash('Both passwords don\'t match. ', category='error')
        elif len(password1) < 7:
            flash('Password must contain at least 7 characters. ', category='error')
        else:
            new_user = User(email=email, user_type=user_type, firstname=firstname,
                            lastname=lastname, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! ', category='success')
            login_user(new_user, remember=True)
            return redirect(url_for('controllers.home'))
    return render_template('sign_up.html', user=current_user)


@auth.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        admin = User.query.filter_by(email=email, user_type='admin').first()
        if admin:
            if check_password_hash(admin.password, password):
                flash('Logged in successfully', category='success')
                login_user(admin, remember=True)
                return redirect(url_for('controllers.admin_dashboard'))
            else:
                flash('Incorect password, try again.', category='error')
        else:
            flash('Admin does not exist', category='error')
    return render_template('admin_login.html', admin=current_user)


@auth.route('/admin_sign_up', methods=['GET', 'POST'])
def admin_sign_up():

    if request.method == 'POST':

        email = request.form.get('email')
        firstname = request.form.get('firstName')
        lastname = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user_type = 'admin'

        admin = User.query.filter_by(
            firstname=firstname, lastname=lastname, email=email).first()
        if admin:
            flash('Email already exist! Please login.', category='error')
        elif len(email) < 4:
            flash('Email must contain at least 4 characters. ', category='error')
        elif len(firstname) < 2:
            flash('First name must contain at least 2 characters. ', category='error')
        elif password1 != password2:
            flash('The entered passwords do not match. ', category='error')
        elif len(password1) < 7:
            flash('Your password needs to consist of a minimum of 7 characters.', category='error')
        else:
            new_admin = User(email=email, firstname=firstname,
                             lastname=lastname, user_type=user_type, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_admin)
            db.session.commit()
            flash('Account created succesfully! ', category='success')
            login_user(new_admin, remember=True)
            return redirect(url_for('controllers.admin_dashboard'))
    return render_template('admin_sign_up.html', admin=current_user)
