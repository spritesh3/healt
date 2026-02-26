import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
from passlib.hash import bcrypt

# ------------------------
# Database Setup
# ------------------------
engine = create_engine("sqlite:///healthmate.db")
Session = sessionmaker(bind=engine)
session = Session()
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    role = Column(String)

Base.metadata.create_all(engine)

# ------------------------
# Session State
# ------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.username = None

def register_user(username, password, role):
    hashed_pw = bcrypt.hash(password)
    new_user = User(username=username, password=hashed_pw, role=role)
    session.add(new_user)
    session.commit()


def login_user(username, password):
    user = session.query(User).filter_by(username=username).first()
    if user and bcrypt.verify(password, user.password):
        st.session_state.logged_in = True
        st.session_state.role = user.role
        st.session_state.username = username
        return True
    return False



st.title("HealthMate Role-Based Login 🏥")

if not st.session_state.logged_in:

    menu = st.selectbox("Select Option", ["Login", "Register"])

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if menu == "Register":
        role = st.selectbox("Select Role", ["doctor", "patient"])
        if st.button("Register"):
            register_user(username, password, role)
            st.success("Registered Successfully!")

    if menu == "Login":
        if st.button("Login"):
            if login_user(username, password):
                st.success("Login Successful!")
            else:
                st.error("Invalid Credentials")





if st.session_state.logged_in:

    st.sidebar.write(f"Logged in as: {st.session_state.username}")
    st.sidebar.write(f"Role: {st.session_state.role}")

    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.experimental_rerun()

    # ------------------------
    # Patient Dashboard
    # ------------------------
    if st.session_state.role == "patient":
        st.header("Patient Dashboard")
        st.write("You can upload reports and view your health data here.")

    # ------------------------
    # Doctor Dashboard
    # ------------------------
    if st.session_state.role == "doctor":
        st.header("Doctor Dashboard")
        st.write("You can view patient records and add notes here.")





