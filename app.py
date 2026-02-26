import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker
from transformers import pipeline
import PyPDF2
import hashlib
import os

# -----------------------------
# CONFIG
# -----------------------------
st.set_page_config(page_title="HealthMate AI", layout="wide")

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    st.error("❌ DATABASE_URL not set in Streamlit Secrets.")
    st.stop()

try:
    engine = create_engine(DATABASE_URL)
    connection = engine.connect()
    connection.close()
except Exception as e:
    st.error(f"Database connection failed: {e}")
    st.stop()

Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

# -----------------------------
# TABLES
# -----------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    role = Column(String)

class Patient(Base):
    __tablename__ = "patients"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    full_name = Column(String)
    age = Column(Integer)
    gender = Column(String)
    blood_group = Column(String)
    contact = Column(String)

class EHR(Base):
    __tablename__ = "ehr"
    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    report_name = Column(String)
    extracted_text = Column(Text)

Base.metadata.create_all(engine)

# -----------------------------
# AI MODEL
# -----------------------------
@st.cache_resource
def load_model():
    return pipeline("ner", model="d4data/biomedical-ner-all")

ner_model = load_model()

# -----------------------------
# PASSWORD HASHING (SHA256)
# -----------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# -----------------------------
# HELPER FUNCTIONS
# -----------------------------
def register_user(username, password, role):
    if not username or not password:
        return "Username and password required"

    existing = session.query(User).filter_by(username=username).first()
    if existing:
        return "Username already exists"

    hashed_pw = hash_password(password)
    new_user = User(username=username, password=hashed_pw, role=role)
    session.add(new_user)
    session.commit()
    return "success"

def login_user(username, password):
    user = session.query(User).filter_by(username=username).first()
    if user and user.password == hash_password(password):
        return user
    return None

def extract_text_from_pdf(file):
    reader = PyPDF2.PdfReader(file)
    text = ""
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            text += page_text
    return text

# -----------------------------
# SESSION STATE
# -----------------------------
if "username" not in st.session_state:
    st.session_state.username = None
if "role" not in st.session_state:
    st.session_state.role = None

# -----------------------------
# UI
# -----------------------------
st.title("🏥 HealthMate AI Healthcare System")

menu = st.selectbox("Select Option", ["Login", "Register"])
username = st.text_input("Username")
password = st.text_input("Password", type="password")

# -----------------------------
# REGISTER
# -----------------------------
if menu == "Register":
    role = st.selectbox("Role", ["patient", "doctor"])
    if st.button("Register"):
        result = register_user(username, password, role)
        if result == "success":
            st.success("Registered Successfully")
        else:
            st.error(result)

# -----------------------------
# LOGIN
# -----------------------------
if menu == "Login":
    if st.button("Login"):
        user = login_user(username, password)
        if user:
            st.session_state.username = user.username
            st.session_state.role = user.role
            st.success("Login Successful")
            st.rerun()
        else:
            st.error("Invalid Credentials")

# -----------------------------
# SIDEBAR
# -----------------------------
if st.session_state.username:
    st.sidebar.success(f"Logged in as {st.session_state.username}")
    st.sidebar.info(f"Role: {st.session_state.role}")
    if st.sidebar.button("Logout"):
        st.session_state.username = None
        st.session_state.role = None
        st.rerun()

# -----------------------------
# PATIENT DASHBOARD
# -----------------------------
if st.session_state.role == "patient":

    st.header("👤 Patient Dashboard")
    st.warning("⚠️ Not a substitute for professional medical advice")

    user = session.query(User).filter_by(username=st.session_state.username).first()
    patient = session.query(Patient).filter_by(user_id=user.id).first()

    if not patient:
        patient = Patient(user_id=user.id)
        session.add(patient)
        session.commit()

    st.subheader("Profile")

    patient.full_name = st.text_input("Full Name", patient.full_name or "")
    patient.age = st.number_input("Age", 0, 120, patient.age or 0)

    gender_options = ["Male", "Female", "Other"]
    current_gender = patient.gender if patient.gender in gender_options else "Male"
    patient.gender = st.selectbox(
        "Gender",
        gender_options,
        index=gender_options.index(current_gender)
    )

    patient.blood_group = st.text_input("Blood Group", patient.blood_group or "")
    patient.contact = st.text_input("Contact", patient.contact or "")

    if st.button("Save Profile"):
        session.commit()
        st.success("Profile Updated")

    st.subheader("Upload Medical Report (PDF)")
    uploaded_file = st.file_uploader("Upload PDF", type=["pdf"])

    if uploaded_file:
        text = extract_text_from_pdf(uploaded_file)
        new_report = EHR(
            patient_id=patient.id,
            report_name=uploaded_file.name,
            extracted_text=text
        )
        session.add(new_report)
        session.commit()
        st.success("Report Uploaded & Stored")

    st.subheader("🤖 AI Medical Assistant")
    user_query = st.text_input("Ask Health Question")

    if user_query:
        results = ner_model(user_query)
        st.write("### Extracted Medical Entities:")
        st.write(results)

# -----------------------------
# DOCTOR DASHBOARD
# -----------------------------
if st.session_state.role == "doctor":

    st.header("🩺 Doctor Dashboard")

    patients = session.query(Patient).all()

    for p in patients:
        st.write("---")
        st.write(f"Name: {p.full_name}")
        st.write(f"Age: {p.age}")
        st.write(f"Blood Group: {p.blood_group}")

        reports = session.query(EHR).filter_by(patient_id=p.id).all()
        for r in reports:
            st.write(f"Report: {r.report_name}")
