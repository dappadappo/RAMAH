import calendar
from datetime import date

from werkzeug.utils import secure_filename
from uuid import uuid4
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from pathlib import Path
from datetime import date
import sqlite3
import os
import re

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database" / "ramah.db"

# Untuk pengembangan lokal.
# Ganti dengan secret key acak dari environment
# sebelum aplikasi dipublikasikan.
app.config["SECRET_KEY"] = os.environ.get(
    "RAMAH_SECRET_KEY",
    "ramah-local-development-key-change-before-deployment"
)

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
PROFILE_FOLDER = BASE_DIR / "static" / "images" / "profile"

PROFILE_FOLDER.mkdir(parents=True, exist_ok=True)

# ==========================================
# DATABASE
# ==========================================

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as db:
        db.execute("PRAGMA foreign_keys = ON")

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Migrasi: pertahankan tabel lama agar
        # catatan uji coba tidak hilang.
        table = db.execute("""
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name = 'ttd_logs'
        """).fetchone()

        if table:
            columns = {
                row[1] for row in
                db.execute("PRAGMA table_info(ttd_logs)").fetchall()
            }

            if "user_id" not in columns:
                legacy = db.execute("""
                    SELECT name FROM sqlite_master
                    WHERE type = 'table'
                    AND name = 'ttd_logs_legacy'
                """).fetchone()

                if not legacy:
                    db.execute(
                        "ALTER TABLE ttd_logs RENAME TO ttd_logs_legacy"
                    )

        # ==========================================
        # TABEL TRACKING TTD
        # ==========================================

        db.execute("""
            CREATE TABLE IF NOT EXISTS ttd_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                log_date TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK(status IN ('taken', 'missed')),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
                    ON DELETE CASCADE,
                UNIQUE(user_id, log_date)
            )
        """)

        # ==========================================
        # MENAMBAHKAN KOLOM PROFIL
        # ==========================================

        columns = {
            row[1] for row in
            db.execute("PRAGMA table_info(users)").fetchall()
        }

        profile_columns = {
            "display_name": "TEXT",
            "school_level": "TEXT",
            "school_class": "TEXT",
            "age": "INTEGER",
            "profile_photo": "TEXT"
        }

        for column, data_type in profile_columns.items():
            if column not in columns:
                db.execute(
                    f"ALTER TABLE users ADD COLUMN {column} {data_type}"
                )

        # ==========================================
        # TABEL MONITORING Hb
        # ==========================================

        db.execute("""
            CREATE TABLE IF NOT EXISTS hb_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                exam_date TEXT NOT NULL,
                hb_value REAL NOT NULL,
                examination_place TEXT,
                notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        # Index untuk mempercepat pencarian riwayat Hb
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_hb_user_date
            ON hb_records(user_id, exam_date)
        """)

        # ==========================================
        # SIMPAN PERUBAHAN DATABASE
        # ==========================================
        # ==========================================
        # TABEL HASIL KUIS RAMAH
        # ==========================================

        db.execute("""
            CREATE TABLE IF NOT EXISTS quiz_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                score INTEGER NOT NULL,
                total_questions INTEGER NOT NULL,
                correct_answers INTEGER NOT NULL,
                completed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)
        db.commit()



# ==========================================
# LOGIN PROTECTION
# ==========================================

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Silakan login terlebih dahulu.", "error")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )
# ==========================================
# REGISTER
# ==========================================


@app.route("/register", methods=["GET", "POST"])
def register():

    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        acknowledgement = request.form.get("acknowledgement")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
            flash(
                "Username harus 3-20 karakter, hanya huruf, angka, dan underscore.",
                "error"
            )
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password minimal 8 karakter.", "error")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Konfirmasi password tidak sama.", "error")
            return redirect(url_for("register"))

        if not acknowledgement:
            flash("Silakan baca dan setujui informasi penggunaan.", "error")
            return redirect(url_for("register"))

        db = get_db()

        existing = db.execute("""
            SELECT id FROM users WHERE username = ?
        """, (username,)).fetchone()

        if existing:
            flash("Username sudah digunakan.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        try:
            cursor = db.execute("""
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
            """, (username, password_hash))

            db.commit()

            session.clear()
            session["user_id"] = cursor.lastrowid
            session["username"] = username

            flash("Akun RAMAH berhasil dibuat! 💗", "success")
            return redirect(url_for("home"))

        except sqlite3.IntegrityError:
            db.rollback()
            flash("Username tidak tersedia.", "error")
            return redirect(url_for("register"))

    return render_template("register.html")


# ==========================================
# LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute("""
            SELECT * FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        if user is None or not check_password_hash(
            user["password_hash"], password
        ):
            flash("Username atau password salah.", "error")
            return redirect(url_for("login"))

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        flash("Selamat datang kembali! 💗", "success")
        return redirect(url_for("home"))

    return render_template("login.html")


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout", methods=["POST"])
@login_required
def logout():

    session.clear()
    flash("Kamu berhasil keluar dari akun.", "success")

    return redirect(url_for("login"))


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/")
@login_required
def home():

    db = get_db()
    user_id = session["user_id"]

    total_taken = db.execute("""
        SELECT COUNT(*) FROM ttd_logs
        WHERE user_id = ? AND status = 'taken'
    """, (user_id,)).fetchone()[0]

    return render_template(
        "dashboard.html",
        total_taken=total_taken,
        username=session["username"]
    )



# ==========================================
# TRACKING TTD
# ==========================================

@app.route("/ttd")
@login_required
def tracking():

    db = get_db()
    user_id = session["user_id"]
    today = date.today().isoformat()

    logs = db.execute("""
        SELECT * FROM ttd_logs
        WHERE user_id = ?
        ORDER BY log_date DESC
        LIMIT 30
    """, (user_id,)).fetchall()

    today_log = db.execute("""
        SELECT * FROM ttd_logs
        WHERE user_id = ? AND log_date = ?
    """, (user_id, today)).fetchone()

    return render_template(
        "tracking.html",
        logs=logs,
        today=today,
        today_log=today_log,
        session_username=session["username"]
    )


# ==========================================
# SIMPAN CATATAN TTD
# ==========================================

@app.route("/ttd/catat", methods=["POST"])
@login_required
def record_ttd():

    status = request.form.get("status")

    if status not in ["taken", "missed"]:
        return "Status tidak valid", 400

    db = get_db()

    db.execute("""
        INSERT INTO ttd_logs (user_id, log_date, status)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, log_date)
        DO UPDATE SET
            status = excluded.status,
            created_at = CURRENT_TIMESTAMP
    """, (
        session["user_id"],
        date.today().isoformat(),
        status
    ))

    db.commit()

    flash("Catatan TTD berhasil disimpan! 💗", "success")

    return redirect(url_for("tracking"))


# ==========================================
# PROFIL PENGGUNA
# ==========================================

@app.route("/profil", methods=["GET", "POST"])
@login_required
def profil():

    db = get_db()
    user_id = session["user_id"]

    user = db.execute("""
        SELECT * FROM users WHERE id = ?
    """, (user_id,)).fetchone()

    if request.method == "POST":

        display_name = request.form.get(
            "display_name", ""
        ).strip()

        school_level = request.form.get("school_level", "")
        school_class = request.form.get("school_class", "")

        age_text = request.form.get("age", "").strip()

        if not display_name or len(display_name) > 50:
            flash("Nama panggilan wajib diisi (maksimal 50 karakter).", "error")
            return redirect(url_for("profil"))

        if school_level not in ["SMP", "SMA"]:
            flash("Pilih jenjang sekolah yang benar.", "error")
            return redirect(url_for("profil"))

        valid_classes = {
            "SMP": ["VII", "VIII", "IX"],
            "SMA": ["X", "XI", "XII"]
        }

        if school_class not in valid_classes[school_level]:
            flash("Kelas tidak sesuai dengan jenjang sekolah.", "error")
            return redirect(url_for("profil"))

        try:
            age = int(age_text)
            if age < 10 or age > 19:
                raise ValueError
        except ValueError:
            flash("Usia harus antara 10 sampai 19 tahun.", "error")
            return redirect(url_for("profil"))

        # Foto lama dipertahankan jika tidak upload foto baru
        photo_path = user["profile_photo"]

        photo = request.files.get("profile_photo")

        if photo and photo.filename:

            if not allowed_file(photo.filename):
                flash("Gunakan foto JPG, JPEG, PNG, atau WEBP.", "error")
                return redirect(url_for("profil"))

            extension = photo.filename.rsplit(".", 1)[1].lower()

            # Nama file acak agar tidak bertabrakan
            filename = f"{uuid4().hex}.{extension}"

            old_photo = photo_path

            photo.save(PROFILE_FOLDER / filename)

            photo_path = f"images/profile/{filename}"

            # Hapus foto lama hanya jika berada di folder profil
            if old_photo and old_photo.startswith("images/profile/"):
                old_filename = old_photo.split("/")[-1]
                old_file = PROFILE_FOLDER / secure_filename(old_filename)

                if old_file.is_file():
                    old_file.unlink()

        db.execute("""
            UPDATE users
            SET display_name = ?,
                school_level = ?,
                school_class = ?,
                age = ?,
                profile_photo = ?
            WHERE id = ?
        """, (
            display_name,
            school_level,
            school_class,
            age,
            photo_path,
            user_id
        ))

        db.commit()

        flash("Profil berhasil diperbarui! 💗", "success")
        return redirect(url_for("profil"))

    return render_template(
        "profil.html",
        user=user
    )

# ==========================================
# KALENDER TTD
# ==========================================

@app.route("/kalender")
@login_required
def kalender_ttd():

    db = get_db()
    user_id = session["user_id"]

    today = date.today()

    # Mengambil bulan dan tahun dari URL
    try:
        month = int(request.args.get("month", today.month))
        year = int(request.args.get("year", today.year))

        if month < 1 or month > 12:
            raise ValueError

        if year < 2020 or year > 2100:
            raise ValueError

    except (ValueError, TypeError):
        month = today.month
        year = today.year

    # Menentukan tanggal awal dan akhir bulan
    first_day = date(year, month, 1)
    last_day_number = calendar.monthrange(year, month)[1]
    last_day = date(year, month, last_day_number)

    # Mengambil catatan pengguna pada bulan tersebut
    logs = db.execute("""
        SELECT log_date, status
        FROM ttd_logs
        WHERE user_id = ?
        AND log_date BETWEEN ? AND ?
    """, (
        user_id,
        first_day.isoformat(),
        last_day.isoformat()
    )).fetchall()

    # Mengubah catatan menjadi dictionary
    log_data = {
        int(log["log_date"][-2:]): log["status"]
        for log in logs
    }

    # Membuat susunan minggu kalender
    calendar_data = calendar.Calendar(
        firstweekday=6
    ).monthdayscalendar(year, month)

    # Ringkasan bulanan
    total_taken = sum(
        1 for log in logs
        if log["status"] == "taken"
    )

    total_missed = sum(
        1 for log in logs
        if log["status"] == "missed"
    )

    total_recorded = len(logs)

    # Navigasi bulan sebelumnya dan berikutnya
    previous_month = month - 1
    previous_year = year

    if previous_month == 0:
        previous_month = 12
        previous_year -= 1

    next_month = month + 1
    next_year = year

    if next_month == 13:
        next_month = 1
        next_year += 1

    month_names = [
        "Januari", "Februari", "Maret",
        "April", "Mei", "Juni",
        "Juli", "Agustus", "September",
        "Oktober", "November", "Desember"
    ]

    return render_template(
        "kalender.html",
        calendar_data=calendar_data,
        log_data=log_data,
        month=month,
        year=year,
        month_name=month_names[month - 1],
        today=today,
        total_taken=total_taken,
        total_missed=total_missed,
        total_recorded=total_recorded,
        previous_month=previous_month,
        previous_year=previous_year,
        next_month=next_month,
        next_year=next_year
    )


# ==========================================
# MONITORING HEMOGLOBIN (Hb)
# ==========================================

@app.route("/monitoring-hb", methods=["GET", "POST"])
@login_required
def monitoring_hb():

    db = get_db()
    user_id = session["user_id"]

    if request.method == "POST":

        exam_date = request.form.get("exam_date", "").strip()
        hb_text = request.form.get("hb_value", "").strip()
        place = request.form.get("examination_place", "").strip()
        notes = request.form.get("notes", "").strip()

        # Validasi tanggal
        try:
            parsed_date = date.fromisoformat(exam_date)

            if parsed_date > date.today():
                raise ValueError

        except (ValueError, TypeError):
            flash("Tanggal pemeriksaan tidak valid.", "error")
            return redirect(url_for("monitoring_hb"))

        # Validasi nilai Hb
        try:
            hb_value = float(hb_text)

            if not 3 <= hb_value <= 25:
                raise ValueError

        except (ValueError, TypeError):
            flash("Masukkan nilai Hb yang valid.", "error")
            return redirect(url_for("monitoring_hb"))

        if len(place) > 100 or len(notes) > 500:
            flash("Tempat atau catatan terlalu panjang.", "error")
            return redirect(url_for("monitoring_hb"))

        db.execute("""
            INSERT INTO hb_records (
                user_id,
                exam_date,
                hb_value,
                examination_place,
                notes
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_id,
            exam_date,
            hb_value,
            place,
            notes
        ))

        db.commit()

        flash("Hasil pemeriksaan Hb berhasil disimpan! 💗", "success")

        return redirect(url_for("monitoring_hb"))

    # Mengambil seluruh riwayat Hb milik pengguna
    records = db.execute("""
        SELECT *
        FROM hb_records
        WHERE user_id = ?
        ORDER BY exam_date DESC, id DESC
    """, (user_id,)).fetchall()

    latest = records[0] if records else None

    # Data grafik: urutkan dari pemeriksaan lama ke terbaru
    chart_records = sorted(
        records,
        key=lambda item: (item["exam_date"], item["id"])
    )

    return render_template(
        "monitoring_hb.html",
        records=records,
        latest=latest,
        chart_records=chart_records,
        today=date.today().isoformat()
    )


# Menghapus catatan Hb
@app.route("/monitoring-hb/hapus/<int:record_id>", methods=["POST"])
@login_required
def delete_hb(record_id):

    db = get_db()

    db.execute("""
        DELETE FROM hb_records
        WHERE id = ? AND user_id = ?
    """, (record_id, session["user_id"]))

    db.commit()

    flash("Catatan pemeriksaan berhasil dihapus.", "success")

    return redirect(url_for("monitoring_hb"))

# ==========================================
# EDUKASI ANEMIA RAMAH
# ==========================================

materi_edukasi = [
    # Seluruh daftar materi yang kamu kirim
]


@app.route("/edukasi")
@login_required
def edukasi():
    return render_template(
        "edukasi.html",
        materi=materi_edukasi
    )


@app.route("/edukasi/<slug>")
@login_required
def detail_edukasi(slug):
    materi = next(
        (
            item for item in materi_edukasi
            if item["slug"] == slug
        ),
        None
    )

    if materi is None:
        return "Materi tidak ditemukan", 404

    return render_template(
        "edukasi_detail.html",
        materi=materi
    )
# ==========================================
# KUIS RAMAH
# ==========================================


@app.route("/kuis", methods=["GET", "POST"])
@login_required
def kuis():

    if request.method == "POST":
        print("=== DEBUG KUIS RAMAH ===")
        print("Data jawaban:", request.form.to_dict())
        print("Jumlah soal:", len(soal_kuis))

        jawaban_benar = 0
        hasil_jawaban = []

        for item in soal_kuis:
            nomor = item["id"]
            jawaban_user = request.form.get(f"jawaban_{nomor}")

            benar = jawaban_user == item["jawaban"]

            if benar:
                jawaban_benar += 1

            hasil_jawaban.append({
                "nomor": nomor,
                "pertanyaan": item["pertanyaan"],
                "jawaban_user": jawaban_user,
                "jawaban_benar": item["jawaban"],
                "benar": benar,
                "pembahasan": item["pembahasan"],
                "pilihan": item["pilihan"]
            })

        total_soal = len(soal_kuis)
        skor = round((jawaban_benar / total_soal) * 100)

        print("Jawaban benar:", jawaban_benar)
        print("Total soal:", total_soal)
        print("Skor:", skor)

        db = get_db()
        db.execute("""
            INSERT INTO quiz_results (
                user_id,
                score,
                total_questions,
                correct_answers
            )
            VALUES (?, ?, ?, ?)
        """, (
            session["user_id"],
            skor,
            total_soal,
            jawaban_benar
        ))

        db.commit()

        return render_template(
            "kuis_hasil.html",
            hasil=hasil_jawaban,
            skor=skor,
            benar=jawaban_benar,
            total=total_soal
        )

    return render_template(
        "kuis.html",
        soal=soal_kuis
    )

# ==========================================
# BANK SOAL KUIS RAMAH
# ==========================================

soal_kuis = [
    {
        "id": 1,
        "pertanyaan": "Apa yang dimaksud dengan anemia?",
        "pilihan": {
            "A": "Kadar hemoglobin lebih rendah dari batas normal",
            "B": "Kadar gula darah lebih tinggi dari normal",
            "C": "Tekanan darah selalu rendah",
            "D": "Kondisi tubuh kekurangan cairan"
        },
        "jawaban": "A",
        "pembahasan": "Anemia merupakan kondisi ketika kadar hemoglobin dalam darah lebih rendah dari batas normal."
    },
    {
        "id": 2,
        "pertanyaan": "Mengapa remaja putri berisiko mengalami kekurangan zat besi?",
        "pilihan": {
            "A": "Karena tidak membutuhkan zat besi",
            "B": "Karena kehilangan darah saat menstruasi",
            "C": "Karena terlalu banyak tidur",
            "D": "Karena selalu mengalami dehidrasi"
        },
        "jawaban": "B",
        "pembahasan": "Menstruasi menyebabkan kehilangan darah sehingga kebutuhan zat besi perlu diperhatikan."
    },
    {
        "id": 3,
        "pertanyaan": "Apa fungsi utama hemoglobin?",
        "pilihan": {
            "A": "Mengatur suhu tubuh",
            "B": "Mencerna makanan",
            "C": "Membawa oksigen ke seluruh tubuh",
            "D": "Menghasilkan hormon"
        },
        "jawaban": "C",
        "pembahasan": "Hemoglobin dalam sel darah merah berfungsi membawa oksigen ke seluruh tubuh."
    },
    {
        "id": 4,
        "pertanyaan": "Apa kandungan utama TTD dalam program pemerintah?",
        "pilihan": {
            "A": "Kalsium dan vitamin D",
            "B": "Zat besi dan asam folat",
            "C": "Vitamin A dan vitamin E",
            "D": "Protein dan karbohidrat"
        },
        "jawaban": "B",
        "pembahasan": "TTD untuk program pencegahan anemia mengandung zat besi dan asam folat."
    },
    {
        "id": 5,
        "pertanyaan": "Berapa anjuran konsumsi TTD bagi remaja putri dalam program pencegahan?",
        "pilihan": {
            "A": "Satu tablet setiap hari",
            "B": "Satu tablet setiap bulan",
            "C": "Satu tablet setiap minggu",
            "D": "Satu tablet setiap enam bulan"
        },
        "jawaban": "C",
        "pembahasan": "Program pencegahan anemia bagi remaja putri menganjurkan satu tablet setiap minggu sepanjang tahun, sesuai program dan arahan tenaga kesehatan."
    },
    {
        "id": 6,
        "pertanyaan": "Manakah makanan yang dapat menjadi sumber zat besi?",
        "pilihan": {
            "A": "Daging dan kacang-kacangan",
            "B": "Permen dan minuman bersoda",
            "C": "Kerupuk dan es batu",
            "D": "Sirup dan agar-agar"
        },
        "jawaban": "A",
        "pembahasan": "Daging dan kacang-kacangan merupakan contoh sumber zat besi."
    },
    {
        "id": 7,
        "pertanyaan": "Vitamin apa yang membantu penyerapan zat besi dari makanan nabati?",
        "pilihan": {
            "A": "Vitamin D",
            "B": "Vitamin C",
            "C": "Vitamin K",
            "D": "Vitamin A"
        },
        "jawaban": "B",
        "pembahasan": "Vitamin C membantu penyerapan zat besi dari sumber makanan nabati."
    },
    {
        "id": 8,
        "pertanyaan": "Manakah yang termasuk keluhan 5L pada anemia?",
        "pilihan": {
            "A": "Lapar, lincah, lega, luas, dan lucu",
            "B": "Lemas, lapar, lambat, licin, dan lengket",
            "C": "Lemah, letih, lesu, lelah, dan lalai",
            "D": "Lama, lurus, lembut, luwes, dan lentur"
        },
        "jawaban": "C",
        "pembahasan": "Keluhan 5L yang sering dikenalkan dalam edukasi anemia adalah lemah, letih, lesu, lelah, dan lalai."
    },
    {
        "id": 9,
        "pertanyaan": "Apa yang sebaiknya dilakukan jika mengalami keluhan yang diduga berkaitan dengan anemia?",
        "pilihan": {
            "A": "Langsung mendiagnosis diri sendiri",
            "B": "Mengonsumsi tablet sebanyak-banyaknya",
            "C": "Mengabaikan semua keluhan",
            "D": "Berkonsultasi dengan tenaga kesehatan"
        },
        "jawaban": "D",
        "pembahasan": "Gejala saja tidak cukup untuk memastikan anemia. Konsultasikan keluhan kepada tenaga kesehatan."
    },
    {
        "id": 10,
        "pertanyaan": "Apakah seseorang yang tidak merasakan gejala pasti bebas anemia?",
        "pilihan": {
            "A": "Ya, karena anemia selalu menimbulkan pusing",
            "B": "Tidak, anemia dapat terjadi tanpa gejala yang jelas",
            "C": "Ya, selama masih bisa beraktivitas",
            "D": "Tidak, karena semua orang pasti anemia"
        },
        "jawaban": "B",
        "pembahasan": "Sebagian orang dengan anemia tidak merasakan gejala yang jelas. Pemeriksaan Hb membantu mengetahui kadar hemoglobin."
    }
]
# ==========================================
# START APPLICATION
# ==========================================
init_db()

if __name__ == "__main__":
    app.run(debug=True)