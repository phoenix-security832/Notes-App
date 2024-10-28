from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import secrets

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///notes.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    notes = db.relationship("Note", backref="author", lazy=True)


class Note(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


# Routes for authentication
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('notes'))
    return render_template('home.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        username = data.get("username")
        password = data.get("password")

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.form
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for("notes"))
        flash('Invalid credentials', 'error')
        return redirect(url_for('login'))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for("home"))


# Routes for notes
@app.route("/notes", methods=["GET"])
def notes():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user_notes = Note.query.filter_by(user_id=session["user_id"]).all()
    return render_template("notes.html", notes=user_notes)


@app.route("/notes/add", methods=["GET", "POST"])
def add_note():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        data = request.form
        new_note = Note(
            title=data.get("title"),
            content=data.get("content"),
            user_id=session["user_id"],
        )
        db.session.add(new_note)
        db.session.commit()
        return redirect(url_for("note_operations", note_id=new_note.id))
    return render_template("add_note.html")


@app.route("/notes/<string:note_id>", methods=["GET", "PUT", "DELETE"])
def note_operations(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    note = Note.query.get_or_404(note_id)

    if request.method == "GET":
        return render_template("edit_note.html", note=note)
    
    if note.user_id != session["user_id"]:
        return jsonify({"error": "Unauthorized"}), 403

    if request.method == "PUT":
        data = request.get_json()
        note.title = data.get("title", note.title)
        note.content = data.get("content", note.content)
        db.session.commit()
        return jsonify({"message": "Note updated successfully"})

    elif request.method == "DELETE":
        db.session.delete(note)
        db.session.commit()
        return jsonify({"message": "Note deleted successfully"})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
