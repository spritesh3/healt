import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import hashlib
import json
import pandas as pd

# =============================
# CONFIG
# =============================

DATABASE_URL = st.secrets["DATABASE_URL"]

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# =============================
# DATABASE MODELS
# =============================

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    role = Column(String)

class QueryHistory(Base):
    __tablename__ = "query_history"
    id = Column(Integer, primary_key=True)
    username = Column(String)
    question = Column(Text)
    result = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# =============================
# SIMPLE PASSWORD HASHING
# =============================

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# =============================
# SIMPLE MEDICAL ENTITY DETECTOR
# =============================

MEDICAL_TERMS = [
    "fever", "cough", "diabetes", "cancer", "pain",
    "infection", "headache", "asthma", "hypertension",
    "heart", "stroke", "flu", "covid"
]

def detect_medical_terms(text):
    found = []
    text_lower = text.lower()

    for term in MEDICAL_TERMS:
        if term in text_lower:
            found.append({
                "term": term,
                "category": "Medical Condition",
                "confidence": "Keyword Match"
            })

    return found

# =============================
# AUTH FUNCTIONS
# =============================

def register_user(username, password, role):
    db = SessionLocal()
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        db.close()
        return False
    user = User(
        username=username,
        password=hash_password(password),
        role=role
    )
    db.add(user)
    db.commit()
    db.close()
    return True

def login_user(username, password):
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    if user and user.password == hash_password(password):
        return user
    return None

# =============================
# UI
# =============================

st.title("🧠 AI Medical Assistant")

st.warning("""
⚠️ Medical Disclaimer:
This tool is for informational purposes only.
It does NOT provide medical diagnosis.
Consult a licensed healthcare professional.
""")

menu = st.sidebar.selectbox("Menu", ["Login", "Register"])

# =============================
# REGISTER
# =============================

if menu == "Register":
    st.subheader("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["patient", "doctor"])

    if st.button("Register"):
        if register_user(username, password, role):
            st.success("Registered successfully!")
        else:
            st.error("Username already exists")

# =============================
# LOGIN
# =============================

elif menu == "Login":
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = login_user(username, password)
        if user:
            st.session_state["username"] = user.username
            st.session_state["role"] = user.role
            st.success("Login successful")
        else:
            st.error("Invalid credentials")

# =============================
# AFTER LOGIN
# =============================

if "username" in st.session_state:

    st.sidebar.write(f"User: {st.session_state['username']}")
    st.sidebar.write(f"Role: {st.session_state['role']}")

    st.subheader("Ask Health Question")
    user_input = st.text_area("Enter medical question")

    if st.button("Analyze") and user_input.strip():
        results = detect_medical_terms(user_input)

        if not results:
            st.warning("No medical keywords detected.")
        else:
            st.subheader("Detected Medical Terms")
            st.json(results)

            db = SessionLocal()
            entry = QueryHistory(
                username=st.session_state["username"],
                question=user_input,
                result=json.dumps(results)
            )
            db.add(entry)
            db.commit()
            db.close()

    # =============================
    # DOCTOR DASHBOARD
    # =============================

    if st.session_state["role"] == "doctor":

        st.subheader("📊 Doctor Analytics Dashboard")

        db = SessionLocal()
        all_history = db.query(QueryHistory).all()
        db.close()

        if all_history:
            data = []
            query_data = []

            for item in all_history:
                query_data.append({
                    "username": item.username,
                    "date": item.created_at
                })

                try:
                    results = json.loads(item.result)
                    for r in results:
                        data.append({
                            "username": item.username,
                            "term": r.get("term"),
                            "category": r.get("category"),
                            "date": item.created_at
                        })
                except:
                    pass

            df = pd.DataFrame(data)
            query_df = pd.DataFrame(query_data)

            col1, col2, col3 = st.columns(3)
            col1.metric("Total Queries", len(query_df))
            col2.metric("Total Terms Detected", len(df))
            col3.metric("Active Users", query_df["username"].nunique())

            if not df.empty:
                st.subheader("Most Common Terms")
                st.bar_chart(df["term"].value_counts())

            if not query_df.empty:
                st.subheader("Queries Per User")
                st.bar_chart(query_df["username"].value_counts())

                st.subheader("Queries Over Time")
                query_df["date"] = pd.to_datetime(query_df["date"])
                time_series = query_df.groupby(query_df["date"].dt.date).size()
                st.line_chart(time_series)

        else:
            st.info("No data available.")

    # =============================
    # PATIENT DASHBOARD
    # =============================

    else:
        st.subheader("📜 Your History")

        db = SessionLocal()
        history = db.query(QueryHistory).filter(
            QueryHistory.username == st.session_state["username"]
        ).order_by(QueryHistory.created_at.desc()).all()
        db.close()

        for item in history:
            st.markdown(f"**Question:** {item.question}")
            st.json(item.result)

        # CSV Download
        if history:
            csv_data = pd.DataFrame([
                {
                    "question": item.question,
                    "result": item.result,
                    "date": item.created_at
                }
                for item in history
            ])

            st.download_button(
                label="Download History as CSV",
                data=csv_data.to_csv(index=False),
                file_name="medical_history.csv",
                mime="text/csv"
            )
