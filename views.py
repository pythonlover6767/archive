from flask import Blueprint, render_template, redirect, url_for, session, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from db import db_connection

views = Blueprint("views", __name__)

@views.route("/")
def index():
    return render_template("index.html")

@views.route("/profile")
def profile():
    if "username" in session:
        return render_template("profile.html", name=session["username"])
    else:
        return redirect(url_for("views.login"))

@views.route("/account", methods=["POST", "GET"])
def account():
    if "username" not in session:
        return redirect(url_for("views.login"))

    current_username = session["username"]

    if request.method == "POST":
        new_username = request.form["username"]
        new_email = request.form["email"]
        new_password = request.form["password"]

        connection = db_connection()

        if new_password:
            password_hash = generate_password_hash(new_password)
            connection.execute(
                "UPDATE users SET username = ?, email = ?, password_hash = ? WHERE username = ?",
                (new_username, new_email, password_hash, current_username)
            )
        else:
            connection.execute(
                "UPDATE users SET username = ?, email = ? WHERE username = ?",
                (new_username, new_email, current_username)
            )

        connection.commit()
        connection.close()

        session["username"] = new_username

        return redirect(url_for("views.profile"))

    else:
        connection = db_connection()
        user = connection.execute(
            "SELECT * FROM users WHERE username = ?", (current_username,)
        ).fetchone()
        connection.close()

        return render_template("account.html", user=user)

@views.route("/registration", methods=["POST", "GET"])
def registration():
    if "username" in session:
        return redirect(url_for("views.profile"))
    elif request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        password_hash = generate_password_hash(password)

        connection = db_connection()
        existing = connection.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            connection.close()
            flash("Account already exists.", "error")
            return redirect(url_for("views.login"))
        else:
            connection.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )

        connection.commit()
        connection.close()

        session.permanent = True
        session["username"] = username

        flash("Account created for " + username, "success")

        return redirect(url_for("views.profile"))
    else:
        return render_template("registration.html")

@views.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username_input = request.form["username"]
        password_input = request.form["password"]

        connection = db_connection()
        user = connection.execute(
            "SELECT * FROM users WHERE username = ?", (username_input,)
        ).fetchone()
        connection.close()

        if user and check_password_hash(user["password_hash"], password_input):
            session["username"] = user["username"]
            return redirect(url_for("views.profile"))
        else:
            return redirect(url_for("views.login"))
    else:
        if "username" in session:
            return redirect(url_for("views.profile"))
        else:
            return render_template("login.html")

@views.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("views.login"))

@views.route("/go-to-home")
def go_to_home():
    return redirect(url_for("views.index"))