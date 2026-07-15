#. Menjalankan Satpam App (Aplikasi Web Flask)
1. Masuk ke direktori satpam_app
2. Aktifkan virtual environment (.venv)
.venv\Scripts\activate
Generate RSA Keys (hanya perlu dijalankan sekali jika kunci belum ada)
python backend/generate_keys.py
 4. Jalankan server Flask
python backend/app.py


#. Menjalankan Guard App (FastAPI Backend)**
1. Masuk ke direktori guard_app
2. 2. Aktifkan virtual environment (.venv)
.venv\Scripts\activate
3. Jalankan server FastAPI menggunakan uvicorn
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
