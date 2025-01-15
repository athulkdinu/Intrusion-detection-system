import customtkinter as ctk
from tkinter import messagebox
import queue
from PIL import Image
import sqlite3

from .monitoring.packet_sniffer import PacketSniffer
from .monitoring.resource_monitor import ResourceMonitor
from .utils.config_loader import ConfigLoader
from .utils.alert_handler import AlertHandler

class IntrusionDetectionApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Initialize components
        self.config = ConfigLoader()
        self.alert_handler = AlertHandler(self)
        self.resource_monitor = ResourceMonitor(self)
        
        # Load configurations
        self.resource_limits = self.config.load_resource_limits()
        self.process_whitelist = self.config.load_process_whitelist()

        # Initialize packet monitoring
        self.packet_queue = queue.Queue()
        self.packet_sniffer = PacketSniffer(self.packet_queue)

        # Setup GUI
        self.setup_gui()
        
    def setup_gui(self):
        # Window properties
        self.title("Intrusion Detection System")
        self.geometry("1024x720")

        # CustomTkinter settings
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        # User credentials (for demo)
        self.VALID_CREDENTIALS = {
            "admin": "admin123",
            "user1": "user123",
            "": ""
        }

        # Database setup
        self.setup_database()

        # Initialize GUI state
        self.current_frame = None
        self.RESPONSIVE_THRESHOLD = 1200
        self.is_hamburger_visible = False
        self.page_history = []
        self.current_page = None

        # Show login page
        self.show_login_page()

    def setup_database(self):
        self.conn = sqlite3.connect('user_data.db')
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                password TEXT
            )
        ''')
        self.conn.commit()

    def show_login_page(self):
        # Clear existing content
        for widget in self.winfo_children():
            widget.destroy()

        # Create login frame
        frame = ctk.CTkFrame(self, width=400, height=400)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        # Add login components
        ctk.CTkLabel(frame, text="Login", font=("Helvetica", 24, "bold")).pack(pady=20)
        
        # Username
        ctk.CTkLabel(frame, text="Username:").pack(pady=5)
        username_entry = ctk.CTkEntry(frame, width=200)
        username_entry.pack(pady=5)
        
        # Password
        ctk.CTkLabel(frame, text="Password:").pack(pady=5)
        password_entry = ctk.CTkEntry(frame, show="*", width=200)
        password_entry.pack(pady=5)
        
        # Login button
        def handle_login():
            username = username_entry.get()
            password = password_entry.get()
            if username in self.VALID_CREDENTIALS and self.VALID_CREDENTIALS[username] == password:
                self.show_main_page()
            else:
                messagebox.showerror("Error", "Invalid credentials!")

        ctk.CTkButton(frame, text="Login", command=handle_login).pack(pady=20)

    def show_main_page(self):
        # Implement your main page UI here
        pass

    # Add other necessary methods here