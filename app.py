from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
import uuid

app = Flask(__name__)
app.secret_key = "supersecretkey"   # change for production
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# MongoDB connection (adjust URI if needed)
client = MongoClient("mongodb://localhost:27017/")
db = client["file_sharing"]
users_col = db["users"]
files_col = db["files"]

# ---------------- Helpers ----------------
def logged_in():
    return "username" in session

def current_user():
    return session.get("username")

def doc_with_str_id(doc):
    """Return a shallow copy with _id converted to string for templates."""
    if not doc:
        return doc
    doc2 = dict(doc)
    doc2["_id"] = str(doc2["_id"])
    return doc2

# ---------------- Routes ----------------
@app.route("/")
def index():
    if logged_in():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# ----- Auth -----
@app.route("/register", methods=["GET", "POST"])
def register():
    if logged_in():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Provide username and password.", "warning")
            return redirect(url_for("register"))
        if users_col.find_one({"username": username}):
            flash("Username already exists!", "danger")
            return redirect(url_for("register"))
        users_col.insert_one({"username": username, "password": generate_password_hash(password)})
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = users_col.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials!", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# ----- Dashboard / Upload -----
@app.route("/dashboard")
def dashboard():
    if not logged_in():
        return redirect(url_for("login"))
    user = current_user()

    # My uploaded files
    my_files = [doc_with_str_id(f) for f in files_col.find({"owner": user}).sort("uploaded_at", -1)]

    # Files where current user is in shared_with
    shared_files = [doc_with_str_id(f) for f in files_col.find({"shared_with": user}).sort("uploaded_at", -1)]

    # Members list (exclude current user)
    members_cursor = users_col.find({"username": {"$ne": user}}, {"username": 1, "_id": 0}).sort("username", 1)
    members = [m["username"] for m in members_cursor]

    return render_template("dashboard.html", username=user, my_files=my_files, shared_files=shared_files, members=members)

@app.route("/upload", methods=["POST"])
def upload():
    if not logged_in():
        return redirect(url_for("login"))
    if "file" not in request.files:
        flash("No file selected!", "danger")
        return redirect(url_for("dashboard"))
    file = request.files["file"]
    if file.filename == "":
        flash("No file selected!", "danger")
        return redirect(url_for("dashboard"))

    filename = secure_filename(file.filename)
    unique_id = str(uuid.uuid4())
    stored_name = unique_id + "_" + filename
    file_path = os.path.join(UPLOAD_FOLDER, stored_name)

    try:
        file.save(file_path)
    except Exception as e:
        flash("Failed to save file: " + str(e), "danger")
        return redirect(url_for("dashboard"))

    # Insert file doc
    files_col.insert_one({
        "owner": current_user(),
        "filename": filename,
        "stored_name": stored_name,
        "filepath": file_path,
        "shared_with": [],
        "uploaded_at":  __import__("datetime").datetime.utcnow()
    })

    flash("File uploaded successfully!", "success")
    return redirect(url_for("dashboard"))

# ----- Share -----
@app.route("/share/<file_id>", methods=["POST"])
def share_file(file_id):
    if not logged_in():
        return redirect(url_for("login"))

    target_user = request.form.get("username", "").strip()
    if not target_user:
        flash("Select a user to share with.", "warning")
        return redirect(url_for("dashboard"))

    # verify target_user exists
    if not users_col.find_one({"username": target_user}):
        flash("Target user does not exist.", "danger")
        return redirect(url_for("dashboard"))

    # load file by ObjectId
    try:
        oid = ObjectId(file_id)
    except Exception:
        flash("Invalid file id.", "danger")
        return redirect(url_for("dashboard"))

    file_doc = files_col.find_one({"_id": oid})
    if not file_doc:
        flash("File not found.", "danger")
        return redirect(url_for("dashboard"))

    # ensure only owner can share
    if file_doc.get("owner") != current_user():
        flash("Unauthorized to share this file.", "danger")
        return redirect(url_for("dashboard"))

    # add to shared_with (no duplicates)
    files_col.update_one({"_id": oid}, {"$addToSet": {"shared_with": target_user}})
    flash(f"File shared with {target_user}!", "success")
    return redirect(url_for("dashboard"))

@app.route("/download/<file_id>")
def download_file(file_id):
    if not logged_in():
        return redirect(url_for("login"))

    # validate id
    try:
        oid = ObjectId(file_id)
    except Exception:
        flash("Invalid file id.", "danger")
        return redirect(url_for("dashboard"))

    file = files_col.find_one({"_id": oid})
    if not file:
        flash("File not found!", "danger")
        return redirect(url_for("dashboard"))

    user = current_user()
    if file.get("owner") != user and user not in file.get("shared_with", []):
        flash("Unauthorized to download!", "danger")
        return redirect(url_for("dashboard"))

    # send file from uploads folder
    directory = os.path.abspath(UPLOAD_FOLDER)
    stored_name = file.get("stored_name")
    if not stored_name or not os.path.exists(os.path.join(directory, stored_name)):
        flash("File missing on server.", "danger")
        return redirect(url_for("dashboard"))

    return send_from_directory(directory, stored_name, as_attachment=True, download_name=file.get("filename"))

if __name__ == "__main__":
    app.run(debug=True)
