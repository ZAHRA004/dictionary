# 🧠 Personal Dictionary Web App (Inspired by Anki)

This is a **web-based personal dictionary** built with **Django**, inspired by the Anki flashcard system. The app allows users to create, manage, and review their own vocabulary words in an efficient and personalized way.

---

## 🚀 Features

- ✅ User registration and login
- 🔐 Captcha verification during signup for enhanced security
- 🔄 Password reset via email
- 📘 Add, update, and review personal vocabulary
- 🧠 Smart review system for repeated practice
- 👨‍💼 Admin panel to manage users and their word collections

---

## 👤 User Flow

1. **Register** with captcha validation.
2. **Log in** securely.
3. **Add words** with definitions, usage, or tags.
4. **Review** your saved words as needed.
5. **Reset password** via email if forgotten.

---

## 🛠️ Tech Stack

- **Backend**: Django (Python)
- **Frontend**: Django Templates + Bootstrap
- **Database**: SQLite
- **Email**: Django Email Backend (for password reset)
- **Security**: Captcha with `django-simple-captcha`

---

## 🔧 Admin Panel

Accessible at `/admin/`, where the administrator can:

- View all registered users
- Manage their word entries
- Control app-wide data

---

## 📦 Installation (For Developers)

```bash
git clone https://github.com/yourusername/dictionary-app.git
cd dictionary-app
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
