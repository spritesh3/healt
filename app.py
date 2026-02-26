import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from passlib.context import CryptContext
from transformers import pipeline
import PyPDF2
import os

# -----------------------------
# CONFIG
# -----------------------------
st.set_page_config(page_title="HealthMate AI", layout="wide")

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
# AI MODEL (BioBERT-like NER)
# -----------------------------
@st.cache_resource
def load_model():
    return pipeline("ner", model="d4data/biomedical-ner-all")

ner_model = load_model()

# -----------------------------
# HELPER FUNCTIONS
# -----------------------------
def register_user(username, password, role):
    hashed_pw = pwd_context.hash(password)
    new_user = User(username=username, password=hashed_pw, role=role)
    session.add(new_user)
    session.commit()

def login_user(username, password):
    user = session.query(User).filter_by(username=username).first()
    if user and pwd_context.verify(password, user.password):
        return user
    return None

def extract_text_from_pdf(file):
    reader = PyPDF2.PdfReader(file)
    text = ""
    for page in reader.pages:
        text += page.extract_text()
    return text

# -----------------------------
# LOGIN SYSTEM
# -----------------------------
if "username" not in st.session_state:
    st.session_state.username = None
if "role" not in st.session_state:
    st.session_state.role = None

st.title("🏥 HealthMate AI Healthcare System")

menu = st.selectbox("Select Option", ["Login", "Register"])
username = st.text_input("Username")
password = st.text_input("Password", type="password")

if menu == "Register":
    role = st.selectbox("Role", ["patient", "doctor"])
    if st.button("Register"):
        register_user(username, password, role)
        st.success("Registered Successfully")

if menu == "Login":
    if st.button("Login"):
        user = login_user(username, password)
        if user:
            st.session_state.username = user.username
            st.session_state.role = user.role
            st.success("Login Successful")
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
        st.experimental_rerun()

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

    # Profile Section
    st.subheader("Profile")
    patient.full_name = st.text_input("Full Name", patient.full_name or "")
    patient.age = st.number_input("Age", 0, 120, patient.age or 0)
    patient.gender = st.selectbox("Gender", ["Male", "Female", "Other"])
    patient.blood_group = st.text_input("Blood Group", patient.blood_group or "")
    patient.contact = st.text_input("Contact", patient.contact or "")

    if st.button("Save Profile"):
        session.commit()
        st.success("Profile Updated")

    # Upload Reports
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

    # AI Chatbot
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
