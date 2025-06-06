# main_app.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkcalendar import DateEntry # pip install tkcalendar
import datetime

# Assuming db_manager.py is in the same directory or accessible via PYTHONPATH
from db_manager import DatabaseManager, db_manager # Use the global instance

class AttendanceApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Student Attendance System")
        self.root.geometry("800x600")

        self.db = db_manager # Use the shared instance
        self.current_user = None # To store logged-in faculty info {'faculty_id': ..., 'username': ..., 'is_admin': ..., 'full_name': ...}


        # Main frame that will hold different views
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.show_login_view()

    def clear_main_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def show_login_view(self):
        self.clear_main_frame()
        self.current_user = None # Logout
        self.root.title("Student Attendance System - Login")
        LoginView(self.main_frame, self)

    def show_main_menu_view(self):
        self.clear_main_frame()
        if self.current_user and self.current_user.get('full_name'):
             self.root.title(f"Student Attendance System - Welcome {self.current_user['full_name']}")
        elif self.current_user and self.current_user.get('username'):
             self.root.title(f"Student Attendance System - Welcome {self.current_user['username']}")
        else:
            self.root.title("Student Attendance System - Main Menu")
        MainMenu(self.main_frame, self)

    def show_student_registration_view(self):
        StudentRegistrationView(tk.Toplevel(self.root), self)

    def show_attendance_marking_view(self):
        AttendanceMarkingView(tk.Toplevel(self.root), self)

    def show_attendance_report_view(self):
        AttendanceReportView(tk.Toplevel(self.root), self)

    def show_admin_panel_view(self):
        if self.current_user and self.current_user['is_admin']:
            AdminPanelView(tk.Toplevel(self.root), self)
        else:
            messagebox.showerror("Access Denied", "You must be an admin to access this panel.")


class LoginView(ttk.Frame):
    def __init__(self, parent, app_controller):
        super().__init__(parent, padding="20")
        self.pack(fill=tk.BOTH, expand=True)
        self.app_controller = app_controller

        ttk.Label(self, text="Faculty Login", font=("Arial", 16)).pack(pady=10)

        ttk.Label(self, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self, width=30)
        self.username_entry.pack()
        self.username_entry.focus()

        ttk.Label(self, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self, width=30, show="*")
        self.password_entry.pack()

        ttk.Button(self, text="Login", command=self.login).pack(pady=20)
        
        self.username_entry.bind("<Return>", lambda event: self.password_entry.focus())
        self.password_entry.bind("<Return>", lambda event: self.login())


    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and Password cannot be empty.")
            return

        user = self.app_controller.db.verify_faculty(username, password)
        if user:
            self.app_controller.current_user = user
            print(f"[LOGIN_SUCCESS] User: {self.app_controller.current_user}") # DEBUG
            messagebox.showinfo("Success", f"Welcome {user.get('full_name', username)}!")
            self.app_controller.show_main_menu_view()
        else:
            print(f"[LOGIN_FAILED] For username: {username}") # DEBUG
            messagebox.showerror("Login Failed", "Invalid username or password.")


class MainMenu(ttk.Frame):
    def __init__(self, parent, app_controller):
        super().__init__(parent, padding="20")
        self.pack(fill=tk.BOTH, expand=True)
        self.app_controller = app_controller

        ttk.Label(self, text="Main Menu", font=("Arial", 16)).pack(pady=20)

        ttk.Button(self, text="Student Registration", command=self.app_controller.show_student_registration_view).pack(fill=tk.X, pady=5)
        ttk.Button(self, text="Mark Attendance", command=self.app_controller.show_attendance_marking_view).pack(fill=tk.X, pady=5)
        ttk.Button(self, text="Attendance Reports", command=self.app_controller.show_attendance_report_view).pack(fill=tk.X, pady=5)

        if self.app_controller.current_user and self.app_controller.current_user['is_admin']:
            ttk.Button(self, text="Admin Control Panel", command=self.app_controller.show_admin_panel_view).pack(fill=tk.X, pady=5)

        ttk.Button(self, text="Logout", command=self.app_controller.show_login_view).pack(fill=tk.X, pady=20)


class StudentRegistrationView(tk.Toplevel):
    def __init__(self, parent, app_controller):
        super().__init__(parent)
        self.title("Student Registration")
        self.geometry("400x400")
        self.app_controller = app_controller
        self.transient(parent) 
        self.grab_set() 

        frame = ttk.Frame(self, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Roll Number:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.roll_entry = ttk.Entry(frame, width=30)
        self.roll_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Name:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.name_entry = ttk.Entry(frame, width=30)
        self.name_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Class/Section:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.class_entry = ttk.Entry(frame, width=30)
        self.class_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Email:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.email_entry = ttk.Entry(frame, width=30)
        self.email_entry.grid(row=3, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Phone:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.phone_entry = ttk.Entry(frame, width=30)
        self.phone_entry.grid(row=4, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Register Student", command=self.register_student).grid(row=5, column=0, columnspan=2, pady=10)

    def register_student(self):
        roll = self.roll_entry.get().strip() # Strip roll number
        name = self.name_entry.get().strip()
        class_sec = self.class_entry.get().strip()
        email = self.email_entry.get().strip()
        phone = self.phone_entry.get().strip()

        if not all([roll, name, class_sec]):
            messagebox.showerror("Error", "Roll Number, Name, and Class/Section are required.", parent=self)
            return

        if self.app_controller.db.add_student(roll, name, class_sec, email, phone):
            messagebox.showinfo("Success", "Student registered successfully.", parent=self)
            self.destroy()
        else:
            messagebox.showerror("Error", "Roll Number already exists or database error.", parent=self)


class AttendanceMarkingView(tk.Toplevel):
    def __init__(self, parent, app_controller):
        super().__init__(parent)
        self.title("Mark Attendance")
        self.geometry("600x500")
        self.app_controller = app_controller
        self.transient(parent)
        self.grab_set()

        self.selected_class = tk.StringVar()
        self.attendance_date = tk.StringVar(value=datetime.date.today().strftime('%Y-%m-%d'))
        self.student_vars = {} 

        frame = ttk.Frame(self, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        controls_frame = ttk.Frame(frame)
        controls_frame.pack(pady=10, fill=tk.X)

        ttk.Label(controls_frame, text="Select Class:").pack(side=tk.LEFT, padx=5)
        self.class_options = self.app_controller.db.get_distinct_classes()
        if not self.class_options: self.class_options = ["No classes found"]
        self.class_combo = ttk.Combobox(controls_frame, textvariable=self.selected_class, values=self.class_options, state="readonly")
        self.class_combo.pack(side=tk.LEFT, padx=5)
        self.class_combo.bind("<<ComboboxSelected>>", self.load_students)
        if self.class_options and self.class_options[0] != "No classes found":
            self.class_combo.set(self.class_options[0])


        ttk.Label(controls_frame, text="Date:").pack(side=tk.LEFT, padx=5)
        self.date_entry = DateEntry(controls_frame, textvariable=self.attendance_date, date_pattern='yyyy-mm-dd', width=12)
        self.date_entry.pack(side=tk.LEFT, padx=5)
        self.date_entry.bind("<<DateEntrySelected>>", self.load_students) 

        list_frame_container = ttk.LabelFrame(frame, text="Students")
        list_frame_container.pack(fill=tk.BOTH, expand=True, pady=10)

        canvas = tk.Canvas(list_frame_container)
        scrollbar = ttk.Scrollbar(list_frame_container, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        ttk.Button(frame, text="Mark All Present", command=lambda: self.mark_all("Present")).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(frame, text="Mark All Absent", command=lambda: self.mark_all("Absent")).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(frame, text="Submit Attendance", command=self.submit_attendance).pack(side=tk.RIGHT, padx=5, pady=5)

        if self.class_options and self.class_options[0] != "No classes found":
            self.load_students() 

    def load_students(self, event=None):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.student_vars.clear()

        class_sec = self.selected_class.get()
        att_date = self.attendance_date.get() 
        print(f"[LOAD_STUDENTS] Class: {class_sec}, Date: {att_date}") 

        if not class_sec or class_sec == "No classes found":
            ttk.Label(self.scrollable_frame, text="Please select a class.").pack()
            return

        students = self.app_controller.db.get_students_by_class(class_sec)
        
        existing_attendance_raw = self.app_controller.db.get_attendance_report_class(class_sec, att_date)
        existing_attendance_map = {row['roll_number']: row['status'] for row in existing_attendance_raw if row['status']}
        print(f"[LOAD_STUDENTS] Existing attendance map for {class_sec} on {att_date}: {existing_attendance_map}") 


        if not students:
            ttk.Label(self.scrollable_frame, text="No students found for this class.").pack()
            return

        ttk.Label(self.scrollable_frame, text="Roll No.", font=('Arial', 10, 'bold')).grid(row=0, column=0, padx=5, pady=2, sticky='w')
        ttk.Label(self.scrollable_frame, text="Name", font=('Arial', 10, 'bold')).grid(row=0, column=1, padx=5, pady=2, sticky='w')
        ttk.Label(self.scrollable_frame, text="Status", font=('Arial', 10, 'bold')).grid(row=0, column=2, padx=5, pady=2, sticky='w')


        for i, student in enumerate(students):
            student_id = student['student_id']
            roll_no = student['roll_number']
            name = student['name']
            
            status_var = tk.StringVar(value=existing_attendance_map.get(roll_no, "Present")) 

            self.student_vars[student_id] = (name, roll_no, status_var)

            ttk.Label(self.scrollable_frame, text=roll_no).grid(row=i+1, column=0, padx=5, pady=2, sticky='w')
            ttk.Label(self.scrollable_frame, text=name).grid(row=i+1, column=1, padx=5, pady=2, sticky='w')
            
            status_frame = ttk.Frame(self.scrollable_frame)
            status_frame.grid(row=i+1, column=2, padx=5, pady=2, sticky='w')
            ttk.Radiobutton(status_frame, text="P", variable=status_var, value="Present").pack(side=tk.LEFT)
            ttk.Radiobutton(status_frame, text="A", variable=status_var, value="Absent").pack(side=tk.LEFT)

    def mark_all(self, status):
        for _name, _roll, status_var in self.student_vars.values():
            status_var.set(status)

    def submit_attendance(self):
        att_date = self.attendance_date.get() 
        if not self.app_controller.current_user or 'faculty_id' not in self.app_controller.current_user:
            messagebox.showerror("Error", "Faculty user not properly logged in. Cannot mark attendance.", parent=self)
            print("[SUBMIT_ATTENDANCE_ERROR] current_user or faculty_id missing") 
            return
        faculty_id = self.app_controller.current_user['faculty_id']
        
        print(f"[SUBMIT_ATTENDANCE] Date: {att_date}, Faculty ID: {faculty_id}") 
        if not self.student_vars:
            messagebox.showwarning("No Students", "No students loaded to mark attendance.", parent=self)
            return

        marked_count = 0
        success_count = 0
        try:
            for student_id, (name, roll, status_var) in self.student_vars.items():
                status = status_var.get()
                print(f"[SUBMIT_ATTENDANCE] Marking: Student ID={student_id} ({name}), Status='{status}'") 
                if self.app_controller.db.mark_attendance(student_id, att_date, status, faculty_id):
                    success_count += 1
                marked_count +=1
            
            if success_count == marked_count and marked_count > 0:
                messagebox.showinfo("Success", f"Attendance submitted for {success_count} students.", parent=self)
                self.destroy()
            elif marked_count > 0 : 
                 messagebox.showwarning("Partial Success", f"Attendance submitted for {success_count} out of {marked_count} students. Check console for errors.", parent=self)
                 # self.destroy() 
            else: 
                messagebox.showerror("Error", "Failed to submit attendance for any student. Check console.", parent=self)

        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}", parent=self)
            print(f"[SUBMIT_ATTENDANCE_EXCEPTION] {e}") 


class AttendanceReportView(tk.Toplevel):
    def __init__(self, parent, app_controller):
        super().__init__(parent)
        self.title("Attendance Reports")
        self.geometry("800x600")
        self.app_controller = app_controller
        self.transient(parent)
        self.grab_set()

        frame = ttk.Frame(self, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        # --- Controls ---
        self.top_controls_container = ttk.Frame(frame)
        self.top_controls_container.pack(fill=tk.X, pady=5)

        self.report_type = tk.StringVar(value="student") 

        radio_button_frame = ttk.Frame(self.top_controls_container)
        radio_button_frame.pack(side=tk.LEFT, padx=5)

        ttk.Radiobutton(radio_button_frame, text="Student Report", variable=self.report_type, value="student", command=self.toggle_report_type).pack(anchor=tk.W)
        ttk.Radiobutton(radio_button_frame, text="Class Report", variable=self.report_type, value="class", command=self.toggle_report_type).pack(anchor=tk.W)

        self.specific_controls_container = ttk.Frame(self.top_controls_container)
        self.specific_controls_container.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        self.student_controls_frame = ttk.Frame(self.specific_controls_container)
        ttk.Label(self.student_controls_frame, text="Roll No:").pack(side=tk.LEFT)
        self.roll_entry = ttk.Entry(self.student_controls_frame, width=15)
        self.roll_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.student_controls_frame, text="Start Date:").pack(side=tk.LEFT)
        self.start_date_entry = DateEntry(self.student_controls_frame, date_pattern='yyyy-mm-dd', width=12)
        self.start_date_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.student_controls_frame, text="End Date:").pack(side=tk.LEFT)
        self.end_date_entry = DateEntry(self.student_controls_frame, date_pattern='yyyy-mm-dd', width=12)
        self.end_date_entry.pack(side=tk.LEFT, padx=5)

        self.class_controls_frame = ttk.Frame(self.specific_controls_container)
        ttk.Label(self.class_controls_frame, text="Select Class:").pack(side=tk.LEFT)
        self.class_options = self.app_controller.db.get_distinct_classes()
        if not self.class_options: self.class_options = ["No classes"]
        self.class_combo = ttk.Combobox(self.class_controls_frame, values=self.class_options, state="readonly", width=15)
        if self.class_options and self.class_options[0] != "No classes": # check if class_options is not empty
            self.class_combo.set(self.class_options[0])
        self.class_combo.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.class_controls_frame, text="Date:").pack(side=tk.LEFT)
        self.class_date_entry = DateEntry(self.class_controls_frame, date_pattern='yyyy-mm-dd', width=12)
        self.class_date_entry.pack(side=tk.LEFT, padx=5)

        ttk.Button(self.top_controls_container, text="Generate Report", command=self.generate_report).pack(side=tk.LEFT, padx=10, pady=(0,3)) 

        report_display_frame = ttk.Frame(frame)
        report_display_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.tree = ttk.Treeview(report_display_frame, show='headings')
        self.tree_scroll_y = ttk.Scrollbar(report_display_frame, orient="vertical", command=self.tree.yview)
        self.tree_scroll_x = ttk.Scrollbar(report_display_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=self.tree_scroll_y.set, xscrollcommand=self.tree_scroll_x.set)

        self.tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        self.toggle_report_type() 

    def toggle_report_type(self):
        self.student_controls_frame.pack_forget()
        self.class_controls_frame.pack_forget()

        if self.report_type.get() == "student":
            self.student_controls_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        else: 
            self.class_controls_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

    def generate_report(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.tree["columns"] = []

        report_type = self.report_type.get()
        print(f"[GENERATE_REPORT] Type: {report_type}")

        if report_type == "student":
            roll_no_raw = self.roll_entry.get()
            roll_no = roll_no_raw.strip() 

            print(f"[GENERATE_REPORT_STUDENT] Raw Roll No from entry: '{roll_no_raw}'") 
            print(f"[GENERATE_REPORT_STUDENT] Stripped Roll No: '{roll_no}'") 

            if not roll_no: 
                messagebox.showerror("Error", "Roll Number is required for student report. Please enter a valid roll number.", parent=self)
                print("[GENERATE_REPORT_STUDENT_ERROR] Roll number is empty after stripping.") 
                return

            start_date_obj = self.start_date_entry.get_date()
            end_date_obj = self.end_date_entry.get_date()

            start_date = start_date_obj.strftime('%Y-%m-%d') if start_date_obj else None
            end_date = end_date_obj.strftime('%Y-%m-%d') if end_date_obj else None

            print(f"[GENERATE_REPORT_STUDENT] Final Params - Roll: '{roll_no}', Start: {start_date}, End: {end_date}") 

            student = self.app_controller.db.get_student_by_roll(roll_no)
            if not student:
                messagebox.showerror("Error", f"Student with Roll Number '{roll_no}' not found.", parent=self)
                print(f"[GENERATE_REPORT_STUDENT_ERROR] Student not found for roll: '{roll_no}'") 
                return

            print(f"[GENERATE_REPORT_STUDENT] Found student: {dict(student)}")
            report_data = self.app_controller.db.get_attendance_report_student(student['student_id'], start_date, end_date)
            print(f"[GENERATE_REPORT_STUDENT] Data from DB: {len(report_data)} records")

            self.tree["columns"] = ("date", "status", "marked_by")
            self.tree.heading("date", text="Date")
            self.tree.heading("status", text="Status")
            self.tree.heading("marked_by", text="Marked By")
            self.tree.column("date", width=100, anchor=tk.CENTER)
            self.tree.column("status", width=100, anchor=tk.CENTER)
            self.tree.column("marked_by", width=150, anchor=tk.W)

            if report_data:
                for row_idx, row in enumerate(report_data):
                    # print(f"[GENERATE_REPORT_STUDENT_ROW_{row_idx}] Date: {row['date']}, Status: {row['status']}, Marked By: {row['marked_by']}")
                    self.tree.insert("", tk.END, values=(row['date'], row['status'], row['marked_by'] or 'N/A'))
            else:
                messagebox.showinfo("No Data", f"No attendance records found for student '{roll_no}' in the selected range.", parent=self)
                print(f"[GENERATE_REPORT_STUDENT_INFO] No data for roll: '{roll_no}'") 


        elif report_type == "class":
            class_sec = self.class_combo.get()
            report_date_obj = self.class_date_entry.get_date()
            report_date = report_date_obj.strftime('%Y-%m-%d') if report_date_obj else None
            print(f"[GENERATE_REPORT_CLASS] Class: {class_sec}, Date: {report_date}")

            if not class_sec or class_sec == "No classes":
                messagebox.showerror("Error", "Class selection is required for class report.", parent=self)
                return

            report_data = self.app_controller.db.get_attendance_report_class(class_sec, report_date)
            print(f"[GENERATE_REPORT_CLASS] Data from DB: {len(report_data)} records")

            self.tree["columns"] = ("roll_number", "name", "status", "marked_by")
            self.tree.heading("roll_number", text="Roll No.")
            self.tree.heading("name", text="Name")
            self.tree.heading("status", text="Status")
            self.tree.heading("marked_by", text="Marked By")
            self.tree.column("roll_number", width=100, anchor=tk.W)
            self.tree.column("name", width=200, anchor=tk.W)
            self.tree.column("status", width=80, anchor=tk.CENTER)
            self.tree.column("marked_by", width=150, anchor=tk.W)

            if report_data:
                for row_idx, row in enumerate(report_data):
                    # print(f"[GENERATE_REPORT_CLASS_ROW_{row_idx}] Roll: {row['roll_number']}, Name: {row['name']}, Status: {row['status']}, Marked By: {row['marked_by']}")
                    self.tree.insert("", tk.END, values=(row['roll_number'], row['name'], row['status'] or 'N/M', row['marked_by'] or 'N/A'))
            else:
                messagebox.showinfo("No Data", "No students or attendance records found for this class on this date.", parent=self)


class AdminPanelView(tk.Toplevel):
    def __init__(self, parent, app_controller):
        super().__init__(parent)
        self.title("Admin Control Panel")
        self.geometry("700x500")
        self.app_controller = app_controller
        self.transient(parent)
        self.grab_set()

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        user_mgmt_tab = ttk.Frame(notebook)
        notebook.add(user_mgmt_tab, text="User Management")
        self.setup_user_management_tab(user_mgmt_tab)

        backup_tab = ttk.Frame(notebook)
        notebook.add(backup_tab, text="Data Backup")
        self.setup_backup_tab(backup_tab)

        config_tab = ttk.Frame(notebook)
        notebook.add(config_tab, text="System Config")
        ttk.Label(config_tab, text="System configuration options (e.g., theme, default settings) - Placeholder").pack(padx=20, pady=20)

    def setup_user_management_tab(self, tab):
        add_faculty_frame = ttk.LabelFrame(tab, text="Add New Faculty/Admin")
        add_faculty_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(add_faculty_frame, text="Username:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.new_faculty_username = ttk.Entry(add_faculty_frame, width=20)
        self.new_faculty_username.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(add_faculty_frame, text="Password:").grid(row=0, column=2, padx=5, pady=2, sticky="w")
        self.new_faculty_password = ttk.Entry(add_faculty_frame, width=20, show="*")
        self.new_faculty_password.grid(row=0, column=3, padx=5, pady=2)
        
        ttk.Label(add_faculty_frame, text="Full Name:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.new_faculty_fullname = ttk.Entry(add_faculty_frame, width=20)
        self.new_faculty_fullname.grid(row=1, column=1, padx=5, pady=2)

        self.new_faculty_is_admin = tk.IntVar()
        ttk.Checkbutton(add_faculty_frame, text="Is Admin?", variable=self.new_faculty_is_admin).grid(row=1, column=2, padx=5, pady=2)
        ttk.Button(add_faculty_frame, text="Add User", command=self.add_new_faculty_user).grid(row=1, column=3, padx=5, pady=5)

        list_faculty_frame = ttk.LabelFrame(tab, text="Manage Existing Users")
        list_faculty_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.faculty_tree = ttk.Treeview(list_faculty_frame, columns=("id", "username", "fullname", "is_admin"), show="headings")
        self.faculty_tree.heading("id", text="ID")
        self.faculty_tree.heading("username", text="Username")
        self.faculty_tree.heading("fullname", text="Full Name")
        self.faculty_tree.heading("is_admin", text="Admin?")
        self.faculty_tree.column("id", width=50, anchor=tk.CENTER)
        self.faculty_tree.column("username", width=150)
        self.faculty_tree.column("fullname", width=200)
        self.faculty_tree.column("is_admin", width=80, anchor=tk.CENTER)
        self.faculty_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        faculty_scroll = ttk.Scrollbar(list_faculty_frame, orient="vertical", command=self.faculty_tree.yview)
        self.faculty_tree.configure(yscrollcommand=faculty_scroll.set)
        faculty_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.faculty_tree.bind("<<TreeviewSelect>>", self.on_faculty_select)

        role_change_frame = ttk.Frame(list_faculty_frame) 
        self.selected_faculty_label = ttk.Label(role_change_frame, text="Selected: None")
        self.selected_faculty_label.pack(pady=2)
        self.role_var = tk.IntVar()
        self.admin_check = ttk.Checkbutton(role_change_frame, text="Set as Admin", variable=self.role_var, command=self.update_selected_faculty_role)
        self.admin_check.pack(pady=2)
        self.admin_check.configure(state=tk.DISABLED) 

        role_change_frame.pack(pady=5, after=self.faculty_tree) 

        self.load_faculty_users()

    def load_faculty_users(self):
        for i in self.faculty_tree.get_children():
            self.faculty_tree.delete(i)
        users = self.app_controller.db.get_all_faculty()
        for user in users:
            self.faculty_tree.insert("", tk.END, values=(user['faculty_id'], user['username'], user['full_name'], "Yes" if user['is_admin'] else "No"))
        self.admin_check.configure(state=tk.DISABLED)
        self.selected_faculty_label.config(text="Selected: None")


    def add_new_faculty_user(self):
        username = self.new_faculty_username.get()
        password = self.new_faculty_password.get()
        fullname = self.new_faculty_fullname.get()
        is_admin = self.new_faculty_is_admin.get()

        if not all([username, password, fullname]):
            messagebox.showerror("Error", "Username, Password, and Full Name are required.", parent=self)
            return

        if self.app_controller.db.add_faculty(username, password, fullname, is_admin):
            messagebox.showinfo("Success", "User added successfully.", parent=self)
            self.new_faculty_username.delete(0, tk.END)
            self.new_faculty_password.delete(0, tk.END)
            self.new_faculty_fullname.delete(0, tk.END)
            self.new_faculty_is_admin.set(0)
            self.load_faculty_users()
        else:
            messagebox.showerror("Error", "Username already exists or database error.", parent=self)

    def on_faculty_select(self, event):
        selected_item = self.faculty_tree.focus() 
        if not selected_item:
            self.admin_check.configure(state=tk.DISABLED)
            self.selected_faculty_label.config(text="Selected: None")
            return

        item_values = self.faculty_tree.item(selected_item)['values']
        faculty_id = item_values[0]
        username = item_values[1]
        is_admin_text = item_values[3]

        self.selected_faculty_label.config(text=f"Selected: {username} (ID: {faculty_id})")
        self.role_var.set(1 if is_admin_text == "Yes" else 0)
        
        if self.app_controller.current_user and username == self.app_controller.current_user['username']: # Check current_user exists
            admins = [u for u in self.app_controller.db.get_all_faculty() if u['is_admin']]
            if len(admins) == 1 and admins[0]['username'] == username:
                self.admin_check.configure(state=tk.DISABLED)
                messagebox.showinfo("Info", "Cannot remove admin rights from the only admin account.", parent=self)
                return

        self.admin_check.configure(state=tk.NORMAL)


    def update_selected_faculty_role(self):
        selected_item = self.faculty_tree.focus()
        if not selected_item:
            messagebox.showerror("Error", "No user selected.", parent=self)
            return

        item_values = self.faculty_tree.item(selected_item)['values']
        faculty_id = item_values[0]
        new_is_admin_val = self.role_var.get()

        if self.app_controller.db.update_faculty_role(faculty_id, new_is_admin_val):
            messagebox.showinfo("Success", "User role updated.", parent=self)
            self.load_faculty_users() 
        else:
            messagebox.showerror("Error", "Failed to update user role.", parent=self)


    def setup_backup_tab(self, tab):
        ttk.Label(tab, text="Database Backup", font=("Arial", 14)).pack(pady=10)
        ttk.Button(tab, text="Backup Database", command=self.backup_db).pack(pady=10)
        ttk.Label(tab, text="Note: This creates a copy of the current database file.").pack(pady=5)

    def backup_db(self):
        backup_file_path = filedialog.asksaveasfilename(
            defaultextension=".db",
            filetypes=[("SQLite Database", "*.db"), ("All Files", "*.*")],
            title="Save Database Backup As",
            initialfile=f"attendance_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        )
        if backup_file_path:
            if self.app_controller.db.backup_database(backup_file_path):
                messagebox.showinfo("Backup Successful", f"Database backed up to:\n{backup_file_path}", parent=self)
            else:
                messagebox.showerror("Backup Failed", "Could not complete database backup.", parent=self)


if __name__ == "__main__":
    root = tk.Tk()
    app = AttendanceApp(root)
    root.mainloop()