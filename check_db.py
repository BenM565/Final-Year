"""
Show which database this project is currently talking to, and what is in it.

Usage:
    python check_db.py

Reads the same configuration the app does, so it is the quickest way to confirm
whether you are pointed at the local SQLite file or the live Render Postgres.
"""

from app import app, db, User, Task


def main():
    with app.app_context():
        url = db.engine.url
        print("Connected to:", url.render_as_string(hide_password=True))

        if url.drivername.startswith("sqlite"):
            print("Type:        LOCAL SQLite file (this machine only)")
        else:
            print(f"Type:        REMOTE {url.drivername} on {url.host}")
            print("             *** This is shared/live data — edits affect the real site ***")
        print()

        try:
            users = User.query.order_by(User.id).all()
        except Exception as exc:
            print("Could not read the users table:")
            print(" ", str(exc).splitlines()[0])
            print()
            print("If this is a connection error, check that the DATABASE_URL in .env")
            print("is Render's EXTERNAL database URL and that the database is running.")
            return

        print(f"{len(users)} account(s):")
        for u in users:
            flag = "verified" if u.verified else "unverified"
            print(f"  id={u.id:<3} {u.email:<34} {u.role:<9} {flag}")

        print()
        print(f"{Task.query.count()} task(s) posted.")


if __name__ == "__main__":
    main()
