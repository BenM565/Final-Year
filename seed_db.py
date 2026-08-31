"""
Reset the STEP database and fill it with sample data.

Usage:
    python seed_db.py

WARNING: this DELETES ALL existing data first.

Which database it targets follows the same rule as the app:
- DATABASE_URL set        -> that database (e.g. Render Postgres)
- DATABASE_URL not set    -> local SQLite file at instance/step.db

Sample accounts it creates (password for all: password123):
    admin@stepplatform.com    - admin
    hr@acmeltd.com            - company
    ben.murphy.step@gmail.com - student (verified)
    aoife.walsh.step@gmail.com- student (verified)
    liam.byrne.step@gmail.com - student (unverified)
"""

from app import app, db, User, Task, Application

PASSWORD = "password123"


def seed():
    with app.app_context():
        print(f"Database: {db.engine.url.render_as_string(hide_password=True)}")

        print("Dropping all tables...")
        db.drop_all()
        print("Creating fresh schema...")
        db.create_all()

        # ---- Accounts ----
        admin = User(name="Admin", email="admin@stepplatform.com", role="admin", verified=True)
        admin.set_password(PASSWORD)

        company = User(name="Acme Ltd", email="hr@acmeltd.com", role="company", verified=True)
        company.set_password(PASSWORD)

        ben = User(
            name="Ben Murphy", email="ben.murphy.step@gmail.com", role="student",
            verified=True, headline="Final-year Computer Science student",
            skills="Python, SQL, Flask, Excel", grades="1:1",
            bio="Final-year CS student at UCC interested in full-stack development.",
        )
        ben.set_password(PASSWORD)

        aoife = User(
            name="Aoife Walsh", email="aoife.walsh.step@gmail.com", role="student",
            verified=True, headline="Data analytics student",
            skills="Python, Pandas, Tableau", grades="2:1",
        )
        aoife.set_password(PASSWORD)

        liam = User(
            name="Liam Byrne", email="liam.byrne.step@gmail.com", role="student",
            verified=False, skills="JavaScript, HTML, CSS",
        )
        liam.set_password(PASSWORD)

        db.session.add_all([admin, company, ben, aoife, liam])
        db.session.flush()

        # ---- Tasks ----
        tasks = [
            Task(
                title="Build a landing page",
                description="Design and build a responsive one-page site for our product launch.",
                requirements="HTML, CSS, Bootstrap. Deliver source files and a live preview.",
                estimated_hours=10, tags="web, html, css",
                payment_type="fixed", fixed_price=150.0, status="open",
                company_id=company.id,
            ),
            Task(
                title="Customer data cleanup",
                description="Clean and de-duplicate roughly 2,000 rows of customer records.",
                requirements="Excel or Python. Attention to detail matters more than speed.",
                estimated_hours=5, tags="data, excel",
                payment_type="fixed", fixed_price=60.0, status="open",
                company_id=company.id,
            ),
            Task(
                title="Sales trends analysis",
                description="Analyse a year of sales CSV data and produce charts of the key trends.",
                requirements="Python, Pandas, matplotlib. Deliver a short report with figures.",
                estimated_hours=15, tags="python, data analysis",
                payment_type="hourly", hourly_rate=15.0, status="open",
                company_id=company.id,
            ),
        ]
        db.session.add_all(tasks)
        db.session.flush()

        # ---- One sample application ----
        db.session.add(
            Application(task_id=tasks[0].id, student_id=ben.id, status="pending")
        )

        db.session.commit()

        print()
        print("Done. Sample accounts (password for all: password123):")
        for u in [admin, company, ben, aoife, liam]:
            print(f"  {u.email:28s} {u.role:8s} {'verified' if u.verified else 'unverified'}")
        print(f"\n{len(tasks)} tasks posted by Acme Ltd; Ben has applied to '{tasks[0].title}'.")


if __name__ == "__main__":
    seed()
