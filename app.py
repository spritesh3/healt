import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from passlib.context import CryptContext
from transformers import pipeline
import json
import pandas as pd
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

# =============================
# CONFIG
# =============================

DATABASE_URL = st.secrets["DATABASE_URL"]

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ner_pipeline = pipeline("ner", model="d4data/biomedical-ner-all")

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
# AUTH FUNCTIONS
# =============================

def register_user(username, password, role):
    db = SessionLocal()
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        db.close()
        return False
    hashed_pw = pwd_context.hash(password)
    user = User(username=username, password=hashed_pw, role=role)
    db.add(user)
    db.commit()
    db.close()
    return True

def login_user(username, password):
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    if user and pwd_context.verify(password, user.password):
        return user
    return None

# =============================
# PDF GENERATION
# =============================

def generate_pdf(username):
    db = SessionLocal()
    history = db.query(QueryHistory).filter(
        QueryHistory.username == username
    ).order_by(QueryHistory.created_at.desc()).all()
    db.close()

    file_path = f"{username}_history.pdf"
    doc = SimpleDocTemplate(file_path)
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("AI Medical Assistant - Query History", styles["Heading1"]))
    elements.append(Spacer(1, 0.3 * inch))

    for item in history:
        elements.append(Paragraph(f"<b>Question:</b> {item.question}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Date:</b> {item.created_at}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Result:</b> {item.result}", styles["Normal"]))
        elements.append(Spacer(1, 0.3 * inch))

    doc.build(elements)
    return file_path

# =============================
# UI
# =============================

st.title("🧠 AI Medical Assistant")

st.warning("""
⚠️ Medical Disclaimer:
This AI tool is for informational purposes only.
It does NOT provide medical diagnosis or treatment.
Always consult a healthcare professional.
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

    st.sidebar.write(f"Logged in as: {st.session_state['username']}")
    st.sidebar.write(f"Role: {st.session_state['role']}")

    st.subheader("Ask Health Question")
    user_input = st.text_area("Enter medical question")

    if st.button("Analyze") and user_input.strip() != "":
        with st.spinner("Analyzing..."):
            results = ner_pipeline(user_input)

        filtered = [
            r for r in results
            if r["score"] > 0.60 and not r["entity"].lower().startswith("b-coreference")
        ]

        if not filtered:
            st.warning("No significant entities detected.")
        else:
            display_results = []
            st.subheader("🩺 Extracted Medical Entities")

            for r in filtered:
                clean_entity = r["entity"].replace("B-", "").replace("I-", "")
                confidence = round(r["score"] * 100, 2)

                display_results.append({
                    "term": r["word"],
                    "category": clean_entity,
                    "confidence": confidence
                })

                st.markdown(f"""
                **Term:** {r['word']}  
                **Category:** {clean_entity}  
                Confidence: {confidence}%
                """)

            db = SessionLocal()
            history_entry = QueryHistory(
                username=st.session_state["username"],
                question=user_input,
                result=json.dumps(display_results)
            )
            db.add(history_entry)
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
                    "question": item.question,
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
            col2.metric("Total Medical Entities", len(df))
            col3.metric("Active Users", query_df["username"].nunique())

            st.divider()

            if not df.empty:
                st.subheader("🧬 Most Common Categories")
                st.bar_chart(df["category"].value_counts())

                st.subheader("💊 Top 10 Medical Terms")
                st.bar_chart(df["term"].value_counts().head(10))

            if not query_df.empty:
                st.subheader("👥 Queries Per User")
                st.bar_chart(query_df["username"].value_counts())

                st.subheader("📅 Queries Over Time")
                query_df["date"] = pd.to_datetime(query_df["date"])
                time_series = query_df.groupby(query_df["date"].dt.date).size()
                st.line_chart(time_series)

        else:
            st.info("No analytics data available.")

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
            st.markdown(f"""
            **Question:** {item.question}  
            **Date:** {item.created_at}
            """)
            st.json(item.result)

    # =============================
    # DOWNLOAD PDF
    # =============================

    if st.button("Download My History as PDF"):
        pdf_path = generate_pdf(st.session_state["username"])
        with open(pdf_path, "rb") as f:
            st.download_button(
                label="Download PDF",
                data=f,
                file_name=pdf_path,
                mime="application/pdf"
            )
