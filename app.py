# received bootstrap code from ChatGPT
# for flask SQLAlchemy "Flask SQLAlchemy Tutorial for Database - GeeksforGeeks"
# app route layout from ChatGPT

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
    UserMixin,
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func  #use SQL functions inside object relational mapping queries so you don't use SQL anymore; you interact directly with an object in the same language you're using.
import os
from dotenv import load_dotenv

# Load environment variables from a local .env file if present DATABASE_URL FLASK_SECRET
load_dotenv()

# Create a Flask application instance
app = Flask(__name__)

# Configure a secret key for sign session cookies and protection
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", "dev")

# Configure SQLAlchemy database URI
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///app.db")


# Disable the SQLAlchemy event system that tracks modifications in memory
# This reduces memory overhead when not needed
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database and login manager extensions
# These must be created after app configuration
db = SQLAlchemy(app)
login_manager = LoginManager(app)

# Configure the login view endpoint name used by @login_required
login_manager.login_view = "login"


# Database Models


class User(UserMixin, db.Model):
    # Table that stores both student and company accounts
    __tablename__ = "users"

    # Primary key identifier
    id = db.Column(db.Integer, primary_key=True)

    # Role of the user: "student" or "company"
    role = db.Column(db.String(20), nullable=False, default="student")

    # Display name for the account
    name = db.Column(db.String(120), nullable=False)

    # Email address for login; indexed and unique for fast lookup and uniqueness
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)

    # Hashed password using Werkzeug helpers
    password_hash = db.Column(db.String(255), nullable=False)

    # Optional student profile fields
    skills = db.Column(db.Text)
    grades = db.Column(db.String(120))
    projects = db.Column(db.Text)
    references = db.Column(db.Text)

    # Whether the account has been verified based on email rules or manual review
    verified = db.Column(db.Boolean, default=False)

    # Password helper to set a hashed password
    def set_password(self, pw: str) -> None:
        self.password_hash = generate_password_hash(pw)

    # Password helper to verify a plaintext password against the stored hash
    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Task(db.Model):
    # Tasks posted by company users for students to apply to
    __tablename__ = "tasks"

    # Primary key identifier
    id = db.Column(db.Integer, primary_key=True)

    # Short title or summary of the task
    title = db.Column(db.String(200), nullable=False)

    # Detailed requirements or description of the task
    requirements = db.Column(db.Text)

    # Estimated effort for the task in hours
    estimated_hours = db.Column(db.Integer)

    # Foreign key linking the task to the company user that created it
    company_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Backref relationship configured below on Application; optional helper list of applications
    applications = db.relationship(
        "Application", backref="task", cascade="all, delete-orphan"
    )


class Application(db.Model):
    # Applications submitted by student users for a specific task
    __tablename__ = "applications"

    # Primary key identifier
    id = db.Column(db.Integer, primary_key=True)

    # Foreign key to the related task
    task_id = db.Column(db.Integer, db.ForeignKey("tasks.id"), nullable=False)

    # Foreign key to the applying student (stored in users table)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Application workflow status; default is pending
    status = db.Column(db.String(20), default="pending")

    # Server-side timestamp for when the application was created
    created_at = db.Column(db.DateTime, server_default=func.now())



# Login manager user loader

@login_manager.user_loader
def load_user(user_id: str):
    # Flask-Login callback to load a user object by its id
    # Must return None if user is not found
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


# Helper functions


def is_student_email(email: str) -> bool:
    # Basic line to mark student accounts as verified based on the email domain
    email_lower = (email or "").lower()
    return email_lower.endswith(".ie") or email_lower.endswith("\.ie") or "student" in email_lower


# used ChatGPT for a framework of routes but added info inside to customize website
# Routes
@app.route("/")
def index():
    # Always send users to the real login route
    # Prevents POSTs from hitting '/' which only allows GET
    return redirect(url_for("login"))

@app.after_request
def no_store(response):
    # Prevent caching of authenticated pages and forms
    response.headers["Cache-Control"] = "no-store"
    return response


# register a user account [company/student]
@app.route("/register", methods=["GET", "POST"])
def register():
    # Handle account creation for both students and companies
    if request.method == "POST":
        role = request.form.get("role", "student").strip()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").lower().strip()
        password = request.form.get("password", "")

        # Gather role-specific inputs
        if role == "company":
            skills_needed = request.form.get("company_skills_needed", "").strip()
            comp_task_title = request.form.get("company_task_title", "").strip()
            comp_task_requirements = request.form.get("company_task_requirements", "").strip()
            comp_task_estimate = request.form.get("company_task_estimate", "").strip()
            skills = skills_needed
            grades = None
            projects = None
            references = None


        # Prevent duplicate registrations by email
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        # Create a user record and set an initial verification flag
        user = User(
            role=role,
            name=name,
            email=email,
            skills=skills,
            grades=grades,
            projects=projects,
            references=references,
        )
        user.set_password(password)
        user.verified = is_student_email(email) if role == "student" else False

        # Persist user to get an id for potential task creation
        db.session.add(user)
        db.session.flush()

        # If a company included a first task in the registration form, create it
        if role == "company" and comp_task_title:
            try:
                est_hours = int(comp_task_estimate) if comp_task_estimate else None
            except ValueError:
                est_hours = None
            task = Task(
                title=comp_task_title,
                requirements=comp_task_requirements,
                estimated_hours=est_hours,
                company_id=user.id,
            )
            db.session.add(task)

        # Commit all changes atomically
        db.session.commit()
        flash("Account created. You can now log in.", "success")
        return redirect(url_for("login"))

    # Render registration page on GET
    return render_template("register.html")






# login to an existing account
@app.route("/login", methods=["GET", "POST"])
def login():
    # Authenticate a user by verifying email and password
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")





# logout of the current user
@app.route("/logout")
@login_required
def logout():
    # Log out the current user and return to the login page
    logout_user()
    return redirect(url_for("login"))





# company dashboard to see tasks uploaded
@app.route("/dashboard")
@login_required
def dashboard():
    # Provide dashboard data customized to the current user's role
    tasks = []
    counts = {}

    # Company users see their posted tasks and application counts
    if current_user.role == "company":
        tasks = Task.query.filter_by(company_id=current_user.id).all()
        rows = (
            db.session.query(Application.task_id, func.count(Application.id))
            .join(Task, Task.id == Application.task_id)
            .filter(Task.company_id == current_user.id)
            .group_by(Application.task_id)
            .all()
        )
        counts = {task_id: c for task_id, c in rows}

    # Students can be extended to see recommended tasks in the future
    return render_template("dashboard.html", user=current_user, tasks=tasks, counts=counts)



# Allows students to apply to tasks
@app.route("/tasks/<int:task_id>/apply", methods=["POST"])
@login_required
def apply(task_id: int):
    # Allow only student users to apply to tasks
    if current_user.role != "student":
        flash("Only students can apply.", "danger")
        return redirect(url_for("dashboard"))

    # Prevent duplicate applications by the same student to the same task
    exists = Application.query.filter_by(task_id=task_id, student_id=current_user.id).first()
    if exists:
        flash("You already applied.", "info")
        return redirect(request.referrer or url_for("dashboard"))

    # Create an application and persist to a database
    appn = Application(task_id=task_id, student_id=current_user.id)
    db.session.add(appn)
    db.session.commit()
    flash("Applied!", "success")
    return redirect(request.referrer or url_for("dashboard"))



# Allows students to update their profile
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    # Allow a user to update their profile and change the password
    if request.method == "POST":
        current_user.name = request.form.get("name", current_user.name).strip()

        # Handle optional password change if a non-empty value was submitted
        new_pw = request.form.get("password", "").strip()
        if new_pw:
            current_user.set_password(new_pw)

        # Allow only students to modify student-specific fields
        if current_user.role == "student":
            current_user.skills = request.form.get("skills", current_user.skills)
            current_user.grades = request.form.get("grades", current_user.grades)
            current_user.projects = request.form.get("projects", current_user.projects)
            current_user.references = request.form.get("references", current_user.references)

        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("profile"))

    # Render profile page for GET requests
    return render_template("profile.html", user=current_user)






# Task creation route for company user
@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id: int):
    # Only company users can delete tasks
    if current_user.role != "company":
        flash("Only company users can delete tasks.", "danger")
        return redirect(url_for("dashboard"))

    task = Task.query.get_or_404(task_id)

    # Prevent deleting tasks that are not owned by this company
    if task.company_id != current_user.id:
        flash("You are not allowed to delete this task.", "danger")
        return redirect(url_for("dashboard"))

    db.session.delete(task)
    db.session.commit()
    flash("Task deleted.", "success")
    return redirect(url_for("dashboard"))





# Companys option to edit tasks
@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@login_required
def edit_task(task_id: int):
    # Only company users can edit
    if current_user.role != "company":
        flash("Only company users can edit tasks.", "danger")
        return redirect(url_for("dashboard"))
    # Fetch the task or 404 if missing
    task = Task.query.get_or_404(task_id)
    # Ensure the current company owns the task
    if task.company_id != current_user.id:
        flash("You are not allowed to edit this task.", "danger")
        return redirect(url_for("dashboard"))
    # Handle form submit
    if request.method == "POST":
        # Update fields from form inputs
        title = (request.form.get("title") or "").strip()
        requirements = (request.form.get("requirements") or "").strip()
        est_raw = (request.form.get("estimated_hours") or "").strip()
        if not title:
            flash("Title is required.", "danger")
            return render_template("edit_task.html", task=task)
        try:
            estimated_hours = int(est_raw) if est_raw else None
        except ValueError:
            estimated_hours = None
        task.title = title
        task.requirements = requirements
        task.estimated_hours = estimated_hours
        db.session.commit()
        flash("Task updated.", "success")
        return redirect(url_for("dashboard"))
    # Render form with current values for GET
    return render_template("edit_task.html", task=task)





# Company user can add a new task
@app.route("/tasks/new", methods=["GET", "POST"])
@login_required
def add_task():
    # Only company users can add tasks
    if current_user.role != "company":
        flash("Only company users can add tasks.", "danger")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        # Extract and sanitize inputs
        title = (request.form.get("title") or "").strip()
        requirements = (request.form.get("requirements") or "").strip()
        est_raw = (request.form.get("estimated_hours") or "").strip()
        # Basic validation for title
        if not title:
            flash("Title is required.", "danger")
            return render_template("add_task.html")
        # Parse estimated hours as integer if provided
        try:
            estimated_hours = int(est_raw) if est_raw else None
        except ValueError:
            estimated_hours = None
        # Create and persist the task row
        task = Task(
            title=title,
            requirements=requirements,
            estimated_hours=estimated_hours,
            company_id=current_user.id,
        )
        db.session.add(task)
        db.session.commit()
        flash("Task created.", "success")
        return redirect(url_for("dashboard"))
    # Render the blank task form on GET
    return render_template("add_task.html")





# Application Entry Point

if __name__ == "__main__":
    # Ensure database tables exist before starting the development server
    with app.app_context():
        db.create_all()
    # Start Flask development server with debug mode enabled
    app.run(debug=True)
