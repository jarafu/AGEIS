from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    manager = User.query.filter_by(username="socmanager").first()
    if manager:
        manager.password_hash = generate_password_hash("Manager123!")
        db.session.commit()
        print("SOC Manager password has been reset.")
    else:
        manager = User(
            username="socmanager",
            email="socmanager@example.com",
            password_hash=generate_password_hash("Manager123!"),
            role="manager",
            approved=True
        )
        db.session.add(manager)
        db.session.commit()
        print("SOC Manager created.")
