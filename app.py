import os
import re
from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# --- Custom Imports ---
from utils.ai_engine import generate_refined_report

# --- Setup ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecret")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///threat_reports.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# --- User Model ---
class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="Tier-1")  # Tier-1, Tier-2, Tier-3, Manager
    approved = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# --- ThreatReport Model ---
class ThreatReport(db.Model):
    __tablename__ = "threat_report"
    __table_args__ = {"extend_existing": True}

    id = db.Column(db.Integer, primary_key=True)
    prompt = db.Column(db.Text, nullable=False)
    report = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(50))
    source = db.Column(db.String(50), default="Manual Input")
    status = db.Column(db.String(50), default="Pending")

    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))  # 👈 references User table
    escalated_to = db.Column(db.String(20), default=None)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Utility ---
def clean_report_text(text):
    text = re.sub(r"[*_|#`>-]+", "", text)
    text = re.sub(r"\n{2,}", "\n\n", text)
    return text.strip()

# --- Routes ---
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        if User.query.filter_by(email=email).first():
            return "Email already registered."
        if User.query.filter_by(username=username).first():
            return "Username already taken."
        user = User(username=username, email=email, approved=False)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return "Registration successful. Await manager approval."
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            if not user.approved:
                return "Access pending SOC manager approval."
            login_user(user)
            flash("Your account has been approved by the SOC Manager ✅", "success")
            return redirect(url_for("dashboard"))
        return "Invalid credentials."
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    reports = []
    message = ""

    if request.method == "POST":
        prompt = request.form.get("prompt")
        if not prompt:
            message = "Please enter an incident description."
        else:
            try:
                report, severity, metadata = generate_refined_report(prompt, current_user.role)
                new_report = ThreatReport(
                    prompt=prompt,
                    report=report,
                    severity=severity,
                    source=current_user.role,
                    author_id=current_user.id
                )
                db.session.add(new_report)
                db.session.commit()
                message = "Incident report successfully generated ✅"
            except Exception as e:
                message = f"Error generating report: {e}"

    # Different views based on role
    if current_user.role == "Manager":
        severity = request.args.get('severity')
        status = request.args.get('status')
        search = request.args.get('search', '')

        query = ThreatReport.query
        if severity:
            query = query.filter_by(severity=severity)
        if status:
            query = query.filter_by(status=status)
        if search:
            query = query.filter(
                (ThreatReport.report.ilike(f"%{search}%")) |
                (ThreatReport.source.ilike(f"%{search}%"))
            )

        reports = query.all()
        pending_users = User.query.filter_by(approved=False).all()

        # Severity chart counts
        critical_count = ThreatReport.query.filter_by(severity='Critical').count()
        high_count = ThreatReport.query.filter_by(severity='High').count()
        medium_count = ThreatReport.query.filter_by(severity='Medium').count()
        low_count = ThreatReport.query.filter_by(severity='Low').count()

        return render_template(
            'manager_dashboard.html',
            reports=reports,
            pending_users=pending_users,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            message=message
        )

    reports = ThreatReport.query.filter_by(source=current_user.role).all()
    return render_template("analyst_dashboard.html", reports=reports, role=current_user.role, message=message)

# --- ESCALATION LOGIC ---
@app.route("/escalate/<int:report_id>", methods=["POST"])
@login_required
def escalate(report_id):
    """Allows analysts to escalate incidents to the next tier."""
    report = ThreatReport.query.get_or_404(report_id)

    escalation_flow = {
        "Tier-1": "Tier-2",
        "Tier-2": "Tier-3",
        "Tier-3": "Manager"
    }

    next_level = escalation_flow.get(current_user.role)
    if not next_level:
        flash("You are not authorized to escalate further.", "warning")
        return redirect(url_for("dashboard"))

    report.escalated_to = next_level
    db.session.commit()
    flash(f"Incident successfully escalated to {next_level}.", "success")
    return redirect(url_for("dashboard"))

# --- MANAGER APPROVAL LOGIC ---
@app.route("/approve_user/<int:user_id>", methods=["POST"])
@login_required
def approve_user(user_id):
    """SOC Manager approves user access."""
    if current_user.role != "Manager":
        flash("Access denied. Only SOC Managers can approve users.", "danger")
        return redirect(url_for("dashboard"))

    user = User.query.get_or_404(user_id)
    user.approved = True
    db.session.commit()
    flash(f"User {user.username} approved successfully ✅", "success")
    return redirect(url_for("dashboard"))

# --- REPORT GENERATION ---
@app.route("/generate", methods=["POST"])
@login_required
def generate():
    prompt = request.form["prompt"]
    report, severity, metadata = generate_refined_report(prompt, current_user.role)
    report = clean_report_text(report)

    new_report = ThreatReport(
        prompt=prompt,
        report=report,
        severity=severity,
        author_id=current_user.id,
        source=current_user.role
    )
    db.session.add(new_report)
    db.session.commit()
    return render_template("index.html", report=report, prompt=prompt, metadata=metadata)

# --- REPORT DOWNLOAD ---
@app.route('/download/<int:report_id>')
@login_required
def download_report(report_id):
    report = ThreatReport.query.get_or_404(report_id)
    buffer = BytesIO()
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter

    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, 750, f"AGEIS Incident Report #{report.id}")
    p.setFont("Helvetica", 11)
    text_object = p.beginText(50, 720)
    for line in report.report.splitlines():
        text_object.textLine(line)
    p.drawText(text_object)
    p.setFont("Helvetica-Oblique", 10)
    p.drawString(50, 60, f"Generated by: {report.source}")
    p.drawString(400, 60, f"Severity: {report.severity}")
    p.save()

    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"AGEIS_Report_{report.id}.pdf",
        mimetype="application/pdf"
    )



@app.route('/approve/<int:report_id>', methods=['POST'])
@login_required
def approve_report(report_id):
    report = ThreatReport.query.get_or_404(report_id)
    report.status = 'Approved'
    db.session.commit()
    flash('Report approved successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/reject/<int:report_id>', methods=['POST'])
@login_required
def reject_report(report_id):
    report = ThreatReport.query.get_or_404(report_id)
    report.status = 'Rejected'
    db.session.commit()
    flash('Report rejected successfully.', 'danger')
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(debug=True, port=5001)

