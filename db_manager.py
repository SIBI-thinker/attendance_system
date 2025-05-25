# database/db_manager.py
import sqlite3
import hashlib
import datetime
import shutil # For backup

DB_NAME = 'attendance.db'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class DatabaseManager:
    def __init__(self, db_name=DB_NAME):
        self.db_name = db_name
        self.conn = None
        self.cursor = None
        self.connect()
        self.create_tables()

    def connect(self):
        self.conn = sqlite3.connect(self.db_name)
        self.conn.row_factory = sqlite3.Row # Access columns by name
        self.cursor = self.conn.cursor()

    def close(self):
        if self.conn:
            self.conn.close()

    def create_tables(self):
        # Faculty Table (includes admin role)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS faculty (
                faculty_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                is_admin INTEGER DEFAULT 0 -- 0 for faculty, 1 for admin
            )
        ''')

        # Students Table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                student_id INTEGER PRIMARY KEY AUTOINCREMENT,
                roll_number TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                class_section TEXT,
                email TEXT,
                phone TEXT
            )
        ''')

        # Attendance Table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS attendance (
                attendance_id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                date TEXT NOT NULL, -- YYYY-MM-DD
                status TEXT NOT NULL, -- 'Present', 'Absent'
                marked_by_faculty_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES students(student_id),
                FOREIGN KEY (marked_by_faculty_id) REFERENCES faculty(faculty_id)
            )
        ''')
        self.conn.commit()
        self._ensure_admin_exists() # Ensure at least one admin

    def _ensure_admin_exists(self):
        self.cursor.execute("SELECT * FROM faculty WHERE username = 'admin'")
        if not self.cursor.fetchone():
            self.add_faculty('admin', 'admin123', 'Default Admin', is_admin=1)
            print("Default admin user 'admin' with password 'admin123' created.")

    # --- Faculty Methods ---
    def add_faculty(self, username, password, full_name, is_admin=0):
        try:
            hashed_pw = hash_password(password)
            self.cursor.execute('''
                INSERT INTO faculty (username, password_hash, full_name, is_admin)
                VALUES (?, ?, ?, ?)
            ''', (username, hashed_pw, full_name, is_admin))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError: # Username already exists
            return False

    def verify_faculty(self, username, password):
        self.cursor.execute("SELECT * FROM faculty WHERE username = ?", (username,))
        user = self.cursor.fetchone()
        if user and user['password_hash'] == hash_password(password):
            return {'faculty_id': user['faculty_id'], 'username': user['username'], 'is_admin': user['is_admin']}
        return None

    def get_all_faculty(self):
        self.cursor.execute("SELECT faculty_id, username, full_name, is_admin FROM faculty")
        return self.cursor.fetchall()

    def update_faculty_role(self, faculty_id, is_admin):
        try:
            self.cursor.execute("UPDATE faculty SET is_admin = ? WHERE faculty_id = ?", (is_admin, faculty_id))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error updating faculty role: {e}")
            return False

    # --- Student Methods ---
    def add_student(self, roll_number, name, class_section, email, phone):
        try:
            self.cursor.execute('''
                INSERT INTO students (roll_number, name, class_section, email, phone)
                VALUES (?, ?, ?, ?, ?)
            ''', (roll_number, name, class_section, email, phone))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError: # Roll number already exists
            return False

    def get_student_by_roll(self, roll_number):
        self.cursor.execute("SELECT * FROM students WHERE roll_number = ?", (roll_number,))
        return self.cursor.fetchone()

    def get_students_by_class(self, class_section):
        self.cursor.execute("SELECT student_id, roll_number, name FROM students WHERE class_section = ? ORDER BY name", (class_section,))
        return self.cursor.fetchall()
    
    def get_all_students(self):
        self.cursor.execute("SELECT student_id, roll_number, name, class_section FROM students ORDER BY name")
        return self.cursor.fetchall()

    def get_distinct_classes(self):
        self.cursor.execute("SELECT DISTINCT class_section FROM students ORDER BY class_section")
        return [row['class_section'] for row in self.cursor.fetchall() if row['class_section']]


    # --- Attendance Methods ---
    def mark_attendance(self, student_id, date_str, status, faculty_id):
        # Ensure date_str is YYYY-MM-DD
        try:
            datetime.datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            print("Invalid date format for attendance. Use YYYY-MM-DD.")
            return False
        
        # Check if attendance for this student on this date already exists
        self.cursor.execute('''
            SELECT attendance_id FROM attendance 
            WHERE student_id = ? AND date = ?
        ''', (student_id, date_str))
        existing_attendance = self.cursor.fetchone()

        if existing_attendance:
            # Update existing record
            self.cursor.execute('''
                UPDATE attendance 
                SET status = ?, marked_by_faculty_id = ?, timestamp = CURRENT_TIMESTAMP
                WHERE attendance_id = ?
            ''', (status, faculty_id, existing_attendance['attendance_id']))
        else:
            # Insert new record
            self.cursor.execute('''
                INSERT INTO attendance (student_id, date, status, marked_by_faculty_id)
                VALUES (?, ?, ?, ?)
            ''', (student_id, date_str, status, faculty_id))
        self.conn.commit()
        return True

    def get_attendance_report_student(self, student_id, start_date=None, end_date=None):
        query = """
            SELECT a.date, a.status, s.name, s.roll_number, f.username as marked_by
            FROM attendance a
            JOIN students s ON a.student_id = s.student_id
            LEFT JOIN faculty f ON a.marked_by_faculty_id = f.faculty_id
            WHERE a.student_id = ?
        """
        params = [student_id]
        if start_date and end_date:
            query += " AND a.date BETWEEN ? AND ?"
            params.extend([start_date, end_date])
        query += " ORDER BY a.date DESC"
        self.cursor.execute(query, params)
        return self.cursor.fetchall()

    def get_attendance_report_class(self, class_section, date_str):
        query = """
            SELECT s.roll_number, s.name, a.status, f.username as marked_by
            FROM students s
            LEFT JOIN attendance a ON s.student_id = a.student_id AND a.date = ?
            LEFT JOIN faculty f ON a.marked_by_faculty_id = f.faculty_id
            WHERE s.class_section = ?
            ORDER BY s.roll_number
        """
        self.cursor.execute(query, (date_str, class_section))
        return self.cursor.fetchall()

    # --- Admin Methods ---
    def backup_database(self, backup_path):
        self.close() # Close connection before copying
        try:
            shutil.copyfile(self.db_name, backup_path)
            self.connect() # Reopen connection
            return True
        except Exception as e:
            print(f"Backup failed: {e}")
            self.connect() # Reopen connection
            return False

    def __del__(self): # Destructor to ensure connection is closed
        self.close()

# Initialize DB Manager (creates DB and tables if they don't exist)
db_manager = DatabaseManager()