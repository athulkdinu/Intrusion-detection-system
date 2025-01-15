from tkinter import messagebox
import customtkinter as ctk
import sqlite3
import psutil
import GPUtil
from datetime import datetime
from PIL import Image
import json
from scapy.all import sniff, IP, TCP, UDP
import threading


class IntrusionDetectionApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Move resource limits and monitoring setup to the beginning
        # Define resource limits (in percentage)
        self.resource_limits = {
            'cpu': 50,  # CPU usage threshold
            'memory': 70,  # Memory usage threshold
            'disk': 90,  # Disk usage threshold
        }

        # Initialize empty process whitelist
        self.process_whitelist = []
        
        # Load process whitelist
        self.process_whitelist = self.load_process_whitelist()
        
        # Load resource limits
        self.resource_limits = self.load_resource_limits()

        # Initialize empty lists for alerts and logs
        self.alerts = []
        self.logs = []

        # Load alerts and logs from a file
        self.load_alerts_and_logs()

        # Create a log file if it doesn't exist
        self.log_file = 'system_logs.txt'
        with open(self.log_file, 'a') as f:
            if f.tell() == 0:  # Only write header if file is empty
                f.write("Timestamp,Resource,Event,Severity,Status,Action,User\n")

        # Initialize monitoring flag and monitoring task ID
        self.monitoring_active = False
        self.monitoring_task = None

        # Initialize packet monitoring flag
        self.packet_monitoring_active = False
        self.packet_monitoring_thread = None

        # CustomTkinter global appearance settings
        ctk.set_appearance_mode("Dark")  # Options: "Dark", "Light", "System"
        ctk.set_default_color_theme("dark-blue")  # Options: "blue", "green", "dark-blue"

        # Hardcoded user credentials
        self.VALID_CREDENTIALS = {
            "admin": "admin123",  # username: password
            "user1": "user123",
            "" : ""    # you can add more users if needed
        }

        # Database setup
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

        # Window properties
        self.title("Intrusion Detection System")
        self.geometry("1024x720")

        # Dictionary to track displayed frames
        self.current_frame = None

        # Add window resize binding
        self.bind("<Configure>", self.on_window_resize)
        
        # Set threshold width for responsive design
        self.RESPONSIVE_THRESHOLD = 1200  # Adjust this value as needed
        self.is_hamburger_visible = False

        # Add navigation history
        self.page_history = []
        self.current_page = None

        # Initialize the login page
        self.show_login_page()

    def load_alerts_and_logs(self):
        """Load alerts and logs from a file."""
        try:
            with open('alerts_logs.json', 'r') as f:
                data = json.load(f)
                self.alerts = data.get('alerts', [])
                self.logs = data.get('logs', [])
        except FileNotFoundError:
            # If the file doesn't exist, start with empty lists
            self.alerts = []
            self.logs = []

    def clear_window(self):
        """Clear all widgets from the window."""
        for widget in self.winfo_children():
            widget.destroy()

    def clear_main_frame(self):
        """Clear the current frame from the main frame."""
        try:
            # Stop any running updates first
            if hasattr(self, 'after_id'):
                self.after_cancel(self.after_id)
                delattr(self, 'after_id')

            # Destroy all widgets in main_frame
            if hasattr(self, 'main_frame'):
                for widget in self.main_frame.winfo_children():
                    widget.destroy()
            
            # Reset current_frame reference
            self.current_frame = None

        except Exception as e:
            print(f"Error in clear_main_frame: {e}")

    def show_login_page(self):
        """Display the login page."""
        self.stop_monitoring()
        self.stop_packet_monitoring()  # Stop packet monitoring
        self.clear_window()

        # Create a centered frame for the login form
        frame = ctk.CTkFrame(self, width=400, height=400, corner_radius=15)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        # Title
        ctk.CTkLabel(frame, text="Login", font=("Helvetica", 24, "bold")).pack(pady=20)

        # Username input
        ctk.CTkLabel(frame, text="Username:", font=("Helvetica", 14)).pack(pady=5)
        self.login_username = ctk.CTkEntry(frame, font=("Helvetica", 14), width=300)
        self.login_username.pack(pady=5)
        
        # Bind Enter key to move to password field
        self.login_username.bind('<Return>', lambda e: self.focus_next_field(e, self.login_password))

        # Password input
        ctk.CTkLabel(frame, text="Password:", font=("Helvetica", 14)).pack(pady=5)
        self.login_password = ctk.CTkEntry(frame, show="*", font=("Helvetica", 14), width=300)
        self.login_password.pack(pady=5)
        
        # Bind Enter key to trigger login
        self.login_password.bind('<Return>', lambda e: self.handle_login())

        # Login button
        login_button = ctk.CTkButton(
            frame, 
            text="Login", 
            font=("Helvetica", 14), 
            command=self.handle_login
        )
        login_button.pack(pady=20)

        # Set initial focus to username field
        self.login_username.focus()

    def focus_next_field(self, event, next_field):
        """Move focus to the next input field."""
        next_field.focus()
        return "break"

    def handle_login(self):
        """Handle user login with hardcoded credentials."""
        username = self.login_username.get()
        password = self.login_password.get()

        if username in self.VALID_CREDENTIALS and self.VALID_CREDENTIALS[username] == password:
            # Start monitoring before showing the main page
            self.start_monitoring()
            self.start_packet_monitoring()  # Start packet monitoring
            self.show_intrusion_detection_page()
        else:
            messagebox.showerror("Error", "Invalid username or password!")

    def navigate_to(self, page_func):
        """Navigate to a new page and store history."""
        if self.current_page:
            self.page_history.append(self.current_page)
        self.current_page = page_func
        page_func()

    def go_back(self):
        """Navigate to previous page."""
        if self.page_history:
            previous_page = self.page_history.pop()
            self.current_page = previous_page
            previous_page()

    def show_intrusion_detection_page(self):
        """Display the intrusion detection main page."""
        self.clear_window()

        # Create main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True)

        # Create top bar
        top_bar = ctk.CTkFrame(main_container, height=50)
        top_bar.pack(fill="x", side="top")
        top_bar.pack_propagate(False)

        # Create hamburger menu button (initially hidden)
        self.hamburger_button = ctk.CTkButton(
            top_bar,
            text="☰",
            width=50,
            command=self.toggle_menu,
            font=("Helvetica", 20),
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        bck = Image.open("back.1.png")  # Replace with your image path
        backimg = ctk.CTkImage(bck, size=(20, 20))  # Adjust size as needed
        # Create back button
        back_button = ctk.CTkButton(
            top_bar,
            text="Back",
            width=80,
            image=backimg,
            command=self.go_back,
            font=("Helvetica", 14),
            fg_color="transparent",
            hover_color=("gray70", "gray30"),
            anchor="center"
        )
        back_button.pack(side="right", padx=(10, 5), pady=5)
# Load and resize the image
        logout_image = Image.open("log1.png")  # Replace with your image path
        logout_ctk_image = ctk.CTkImage(logout_image, size=(20, 20))  # Adjust size as needed

# Modify the button to include the image
        logout_button = ctk.CTkButton(
            top_bar,
            text="logout",  # Remove text
            image=logout_ctk_image,  # Add image
            width=100,
            command=self.show_login_page,
            fg_color="transparent",
            hover_color=("gray70", "gray30"),
            anchor="center"  # Center the image
            )
        logout_button.pack(side="right", padx=5, pady=5)


        # Create content container
        content_container = ctk.CTkFrame(main_container)
        content_container.pack(fill="both", expand=True)

        # Create sidebar
        self.sidebar = ctk.CTkFrame(content_container, width=250)
        self.sidebar.pack_propagate(False)

        # Create main frame
        self.main_frame = ctk.CTkFrame(content_container)
        self.main_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        # Create sidebar content
        ctk.CTkLabel(
            self.sidebar, 
            text="IDS Platform",
            font=("Helvetica", 18, "bold")
        ).pack(pady=20)

        # Create sidebar buttons (updated list with new buttons)
        buttons = [
            ("🏠 Home", self.show_home),
            ("🔍 Anomaly Detection", self.show_anomaly_detection),
            ("🖥 System", self.show_system_resources),
            ("👥 Admin", self.show_admin_panel),
            ("📊 Logs", self.show_logs),
            ("🚨 Alerts", self.show_alerts)
        ]

        for text, command in buttons:
            button = ctk.CTkButton(
                self.sidebar,
                text=text,
                font=("Helvetica", 14),
                command=command,
                width=200,
                corner_radius=8,
                fg_color="transparent",
                hover_color=("gray70", "gray30"),
                anchor="w"
            )
            button.pack(pady=5, padx=20, fill="x")

        # Check initial window size to determine menu style
        if self.winfo_width() < self.RESPONSIVE_THRESHOLD:
            self.switch_to_hamburger_menu()
        else:
            self.switch_to_normal_menu()

        # Show home page by default
        self.show_home()

    def toggle_menu(self):
        """Toggle the sidebar menu."""
        if self.menu_visible:
            self.sidebar.pack_forget()
            self.menu_visible = False
        else:
            self.sidebar.pack(side="left", fill="y", before=self.main_frame)
            self.menu_visible = True

    def show_home(self):
        """Display the home/dashboard page."""
        self.navigate_to(lambda: self._show_home())

    def _show_home(self):
        """Internal method to show home page."""
        self.clear_main_frame()
        
        # Create main container with scrollable frame
        container = ctk.CTkScrollableFrame(self.main_frame)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        self.current_frame = container

        # Set minimum window size
        self.minsize(800, 600)

        # Configure grid weights for responsive layout
        container.grid_columnconfigure(0, weight=1)
        
        # Welcome message
        ctk.CTkLabel(
            container, 
            text="Welcome back, Admin",
            font=("Helvetica", 24, "bold")
        ).pack(anchor="w", pady=(0, 30))

        # System Resource Monitoring Section
        resource_frame = ctk.CTkFrame(container)
        resource_frame.pack(fill="x", pady=(0, 20))

        # Make resource frame responsive
        resource_frame.grid_columnconfigure(0, weight=1)

        # Title with view details button
        header_frame = ctk.CTkFrame(resource_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=15, pady=(15, 5))
        
        ctk.CTkLabel(
            header_frame,
            text="System Resource Monitoring",
            font=("Helvetica", 16, "bold")
        ).pack(side="left")
        
        view_details_btn = ctk.CTkButton(
            header_frame,
            text="View details",
            command=self.show_system_resources,
            font=("Helvetica", 12),
            height=32
        )
        view_details_btn.pack(side="right")

        # CPU Usage
        cpu_frame = ctk.CTkFrame(resource_frame, fg_color="transparent")
        cpu_frame.pack(fill="x", padx=15, pady=5)
        
        cpu_label_frame = ctk.CTkFrame(cpu_frame, fg_color="transparent")
        cpu_label_frame.pack(fill="x")
        ctk.CTkLabel(
            cpu_label_frame,
            text="CPU usage",
            font=("Helvetica", 12)
        ).pack(side="left")
        self.cpu_percent_label = ctk.CTkLabel(
            cpu_label_frame,
            text="0%",
            font=("Helvetica", 12)
        )
        self.cpu_percent_label.pack(side="right")
        
        self.cpu_progress = ctk.CTkProgressBar(cpu_frame, height=6)
        self.cpu_progress.pack(fill="x", pady=(5, 2))
        self.cpu_progress.set(0)
        
        self.cpu_freq_label = ctk.CTkLabel(
            cpu_frame,
            text="Calculating...",
            font=("Helvetica", 10),
            text_color="gray"
        )
        self.cpu_freq_label.pack(anchor="w")

        # Memory Usage
        memory_frame = ctk.CTkFrame(resource_frame, fg_color="transparent")
        memory_frame.pack(fill="x", padx=15, pady=5)
        
        memory_label_frame = ctk.CTkFrame(memory_frame, fg_color="transparent")
        memory_label_frame.pack(fill="x")
        ctk.CTkLabel(
            memory_label_frame,
            text="Memory usage",
            font=("Helvetica", 12)
        ).pack(side="left")
        self.memory_percent_label = ctk.CTkLabel(
            memory_label_frame,
            text="0%",
            font=("Helvetica", 12)
        )
        self.memory_percent_label.pack(side="right")
        
        self.memory_progress = ctk.CTkProgressBar(memory_frame, height=6)
        self.memory_progress.pack(fill="x", pady=(5, 2))
        self.memory_progress.set(0)
        
        self.memory_label = ctk.CTkLabel(
            memory_frame,
            text="Calculating...",
            font=("Helvetica", 10),
            text_color="gray"
        )
        self.memory_label.pack(anchor="w")

        # Alerts Section
        alerts_frame = ctk.CTkFrame(container)
        alerts_frame.pack(fill="x", pady=(0, 20))

        # Title with view details button
        header_frame = ctk.CTkFrame(alerts_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=15, pady=(15, 5))
        
        ctk.CTkLabel(
            header_frame,
            text="Alerts",
            font=("Helvetica", 16, "bold")
        ).pack(side="left")
        
        view_alerts_btn = ctk.CTkButton(
            header_frame,
            text="View details",
            command=self.show_alerts,
            font=("Helvetica", 12),
            height=32
        )
        view_alerts_btn.pack(side="right")

        # Display recent alerts
        if not self.alerts:
            ctk.CTkLabel(
                alerts_frame,
                text="No alerts found.",
                font=("Helvetica", 12),
                text_color="gray"
            ).pack(anchor="w", padx=15, pady=5)
        else:
            for alert in self.alerts[:3]:  # Show only the 3 most recent alerts
                alert_item = ctk.CTkFrame(alerts_frame, fg_color="transparent")
                alert_item.pack(fill="x", padx=15, pady=5)
                
                icon = "🔴" if alert["priority"] == "High" else "🟡"
                ctk.CTkLabel(
                    alert_item,
                    text=f"{icon} {alert['priority']} priority alert",
                    font=("Helvetica", 12, "bold")
                ).pack(anchor="w")
                
                ctk.CTkLabel(
                    alert_item,
                    text=alert["message"],
                    font=("Helvetica", 10),
                    text_color="gray"
                ).pack(anchor="w")
                
                ctk.CTkLabel(
                    alert_item,
                    text=alert["time"],
                    font=("Helvetica", 10),
                    text_color="gray"
                ).pack(anchor="e")

        # Logs Section
        logs_frame = ctk.CTkFrame(container)
        logs_frame.pack(fill="x", pady=(0, 20))

        # Title with view details button
        header_frame = ctk.CTkFrame(logs_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=15, pady=(15, 5))
        
        ctk.CTkLabel(
            header_frame,
            text="Recent Logs",
            font=("Helvetica", 16, "bold")
        ).pack(side="left")
        
        view_logs_btn = ctk.CTkButton(
            header_frame,
            text="View details",
            command=self.show_logs,
            font=("Helvetica", 12),
            height=32
        )
        view_logs_btn.pack(side="right")

        # Display recent logs in a table format
        if not self.logs:
            ctk.CTkLabel(
                logs_frame,
                text="No logs found.",
                font=("Helvetica", 12),
                text_color="gray"
            ).pack(anchor="w", padx=15, pady=5)
        else:
            # Create table headers
            headers = ["Timestamp", "Event", "Severity"]
            header_row = ctk.CTkFrame(logs_frame, fg_color="gray25")
            header_row.pack(fill="x", padx=15, pady=(5, 2))
            for header in headers:
                ctk.CTkLabel(
                    header_row,
                    text=header,
                    font=("Helvetica", 12, "bold"),
                    text_color="white"
                ).pack(side="left", padx=5, pady=5, expand=True)

            # Display log entries
            for i, log in enumerate(self.logs[:3]):  # Show only the 3 most recent logs
                row_color = "gray17" if i % 2 == 0 else "gray20"
                log_row = ctk.CTkFrame(logs_frame, fg_color=row_color)
                log_row.pack(fill="x", padx=15, pady=2)
                
                ctk.CTkLabel(
                    log_row,
                    text=log['timestamp'],
                    font=("Helvetica", 10),
                    text_color="white"
                ).pack(side="left", padx=5, pady=5, expand=True)
                
                ctk.CTkLabel(
                    log_row,
                    text=log['event'],
                    font=("Helvetica", 10),
                    text_color="white"
                ).pack(side="left", padx=5, pady=5, expand=True)
                
                severity_color = "red" if log['severity'] == "High" else "orange"
                ctk.CTkLabel(
                    log_row,
                    text=log['severity'],
                    font=("Helvetica", 10),
                    text_color=severity_color
                ).pack(side="left", padx=5, pady=5, expand=True)

        # Start resource updates
        self.update_home_resources()

    def update_home_resources(self):
        """Update resource information on home page."""
        try:
            # Check if the frame exists and we're still on the home page
            if not hasattr(self, 'current_frame') or not self.current_frame.winfo_exists():
                return False

            # Update CPU usage if labels exist
            if hasattr(self, 'cpu_percent_label') and self.cpu_percent_label.winfo_exists():
                cpu_percent = psutil.cpu_percent(interval=0.1)
                self.cpu_percent_label.configure(text=f"{cpu_percent}%")
                if hasattr(self, 'cpu_progress') and self.cpu_progress.winfo_exists():
                    self.cpu_progress.set(cpu_percent / 100)
            
            # Update CPU frequency if label exists
            if hasattr(self, 'cpu_freq_label') and self.cpu_freq_label.winfo_exists():
                try:
                    cpu_freq = psutil.cpu_freq()
                    if cpu_freq:
                        current_freq = cpu_freq.current / 1000.0
                        self.cpu_freq_label.configure(text=f"{current_freq:.2f} GHz")
                except Exception:
                    self.cpu_freq_label.configure(text="CPU frequency unavailable")

            # Update Memory usage if labels exist
            if hasattr(self, 'memory_percent_label') and self.memory_percent_label.winfo_exists():
                memory = psutil.virtual_memory()
                self.memory_percent_label.configure(text=f"{memory.percent}%")
                
                if hasattr(self, 'memory_progress') and self.memory_progress.winfo_exists():
                    self.memory_progress.set(memory.percent / 100)
                
                if hasattr(self, 'memory_label') and self.memory_label.winfo_exists():
                    total_gb = memory.total / (1024**3)
                    used_gb = (memory.used) / (1024**3)  # Corrected to show used memory
                    self.memory_label.configure(text=f"{used_gb:.1f} GB of {total_gb:.1f} GB")

            # Update Disk usage
            if hasattr(self, 'disk_frames'):
                for partition in psutil.disk_partitions():
                    if partition.fstype and partition.device in self.disk_frames:
                        try:
                            usage = psutil.disk_usage(partition.mountpoint)
                            label, progress = self.disk_frames[partition.device]
                            if label.winfo_exists() and progress.winfo_exists():
                                total_gb = usage.total / (1024**3)
                                used_gb = usage.used / (1024**3)
                                label.configure(text=f"{used_gb:.1f}/{total_gb:.1f}GB ({usage.percent}%)")
                                progress.set(usage.percent / 100)
                        except Exception:
                            continue

            # Update Network usage
            if hasattr(self, 'network_frames') and hasattr(self, 'prev_net_io'):
                current_net_io = psutil.net_io_counters(pernic=True)
                for interface, stats in current_net_io.items():
                    if interface in self.network_frames and interface in self.prev_net_io:
                        if self.network_frames[interface].winfo_exists():
                            bytes_sent = stats.bytes_sent - self.prev_net_io[interface].bytes_sent
                            bytes_recv = stats.bytes_recv - self.prev_net_io[interface].bytes_recv
                            
                            upload_speed = self.format_bytes(bytes_sent) + "/s"
                            download_speed = self.format_bytes(bytes_recv) + "/s"
                            
                            self.network_frames[interface].configure(
                                text=f"↑{upload_speed}  ↓{download_speed}"
                            )
                
                self.prev_net_io = current_net_io

            # Update GPU usage
            if hasattr(self, 'gpu_frames'):
                try:
                    gpus = GPUtil.getGPUs()
                    for i, gpu in enumerate(gpus):
                        if i < len(self.gpu_frames):
                            frame = self.gpu_frames[i]
                            if all(widget.winfo_exists() for widget in frame.values()):
                                # Update GPU usage
                                frame['usage_label'].configure(text=f"{gpu.load*100:.1f}%")
                                frame['usage_progress'].set(gpu.load)
                                
                                # Update GPU memory
                                memory_total = gpu.memoryTotal / 1024
                                memory_used = gpu.memoryUsed / 1024
                                memory_percent = (memory_used / memory_total) * 100
                                frame['memory_label'].configure(
                                    text=f"{memory_used:.1f}/{memory_total:.1f}GB ({memory_percent:.1f}%)"
                                )
                                
                                # Update GPU temperature
                                frame['temp_label'].configure(text=f"Temp: {gpu.temperature}°C")
                except Exception as e:
                    print(f"Error updating GPU info: {e}")

            # Schedule next update if frame still exists
            if self.current_frame.winfo_exists():
                self.after(1000, self.update_home_resources)
            return True

        except Exception as e:
            print(f"Error updating home resources: {e}")
            return False

    def show_network_traffic(self):
        self.clear_main_frame()
        frame = ctk.CTkFrame(self.main_frame)
        frame.pack(fill="both", expand=True)
        self.current_frame = frame

        ctk.CTkLabel(frame, text="Network Traffic Analysis", font=("Helvetica", 16)).pack(pady=20)

    def show_anomaly_detection(self):
        """Display the anomaly detection page."""
        self.navigate_to(lambda: self._show_anomaly_detection())

    def _show_anomaly_detection(self):
        """Internal method to show anomaly detection page."""
        self.clear_main_frame()
        
        # Create main container with scrollable frame
        container = ctk.CTkScrollableFrame(self.main_frame)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        self.current_frame = container

        # Title
        ctk.CTkLabel(
            container, 
            text="Anomaly Detection",
            font=("Helvetica", 24, "bold")
        ).pack(anchor="w", pady=(0, 20))

        # Placeholder content
        info_frame = ctk.CTkFrame(container)
        info_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            info_frame,
            text="🔍 Anomaly Detection System",
            font=("Helvetica", 16, "bold")
        ).pack(pady=10, padx=15)

        ctk.CTkLabel(
            info_frame,
            text="This module will analyze network traffic and system behavior to detect anomalies.",
            font=("Helvetica", 12),
            wraplength=600
        ).pack(pady=(0, 10), padx=15)

        # Status section
        status_frame = ctk.CTkFrame(container)
        status_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            status_frame,
            text="System Status",
            font=("Helvetica", 14, "bold")
        ).pack(anchor="w", pady=10, padx=15)

        status_items = [
            ("🟢 Machine Learning Model", "Active and monitoring"),
            ("🔄 Last Update", "10 minutes ago"),
            ("📊 Detection Rate", "98.5% accuracy"),
            ("⚠️ False Positive Rate", "0.1%")
        ]

        for title, value in status_items:
            item_frame = ctk.CTkFrame(status_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=15, pady=2)
            
            ctk.CTkLabel(
                item_frame,
                text=title,
                font=("Helvetica", 12)
            ).pack(side="left")
            
            ctk.CTkLabel(
                item_frame,
                text=value,
                font=("Helvetica", 12),
                text_color="gray"
            ).pack(side="right")

    def show_admin_panel(self):
        """Display the admin panel."""
        self.navigate_to(lambda: self._show_admin_panel())

    def _show_admin_panel(self):
        """Internal method to show admin panel."""
        self.clear_main_frame()
        
        container = ctk.CTkScrollableFrame(self.main_frame)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        self.current_frame = container

        # Title
        ctk.CTkLabel(
            container, 
            text="Admin Panel",
            font=("Helvetica", 24, "bold")
        ).pack(anchor="w", pady=(0, 20))

        # Buttons Frame
        buttons_frame = ctk.CTkFrame(container)
        buttons_frame.pack(fill="x", pady=(0, 20))

        # Manage Processes Button
        manage_processes_btn = ctk.CTkButton(
            buttons_frame,
            text="Manage Whitelisted Processes",
            command=self.show_process_manager,
            font=("Helvetica", 14),
            height=40
        )
        manage_processes_btn.pack(pady=10, padx=20, fill="x")

        # Manage Resource Limits Button
        manage_limits_btn = ctk.CTkButton(
            buttons_frame,
            text="Manage Resource Limits",
            command=self.show_limits_manager,
            font=("Helvetica", 14),
            height=40
        )
        manage_limits_btn.pack(pady=10, padx=20, fill="x")

        # Display current settings
        self.display_current_settings(container)

    def display_current_settings(self, container):
        """Display current whitelist and resource limits."""
        # Display Resource Limits
        limits_frame = ctk.CTkFrame(container)
        limits_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            limits_frame,
            text="Current Resource Limits",
            font=("Helvetica", 16, "bold")
        ).pack(pady=10)

        for resource, limit in self.resource_limits.items():
            ctk.CTkLabel(
                limits_frame,
                text=f"{resource.upper()}: {limit}%",
                font=("Helvetica", 12)
            ).pack(pady=5)

        # Display Whitelisted Processes
        whitelist_frame = ctk.CTkFrame(container)
        whitelist_frame.pack(fill="x", pady=10)
        
        # Header frame with title and delete button
        header_frame = ctk.CTkFrame(whitelist_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            header_frame,
            text="Whitelisted Processes",
            font=("Helvetica", 16, "bold")
        ).pack(side="left")

        self.delete_mode = False
        self.process_frames = {}  # Store frames for each process
        self.process_checkboxes = {}
        
        def toggle_delete_mode():
            self.delete_mode = not self.delete_mode
            if self.delete_mode:
                # Show checkboxes and select all button
                delete_button.configure(text="Confirm Delete")
                select_all_btn.pack(side="right", padx=5)
                # Show checkboxes
                for process, (frame, checkbox) in self.process_frames.items():
                    checkbox.pack(side="right", padx=5)
            else:
                # Delete selected processes
                selected_processes = [proc for proc, var in self.process_checkboxes.items() 
                                   if var.get()]
                if selected_processes:
                    if messagebox.askyesno("Confirm Delete", 
                                         f"Delete {len(selected_processes)} selected processes?"):
                        for process in selected_processes:
                            self.process_whitelist.remove(process)
                        
                        # Update whitelist file
                        with open('process_whitelist.txt', 'w') as f:
                            for process in self.process_whitelist:
                                f.write(f"{process}\n")
                        
                        # Refresh display
                        self._show_admin_panel()
                        return

                # Reset UI
                delete_button.configure(text="Delete")
                select_all_btn.pack_forget()
                for _, (frame, checkbox) in self.process_frames.items():
                    checkbox.pack_forget()

        def select_all_processes():
            select_all = not all(var.get() for var in self.process_checkboxes.values())
            for var in self.process_checkboxes.values():
                var.set(select_all)

        # Create buttons
        delete_button = ctk.CTkButton(
            header_frame,
            text="Delete",
            command=toggle_delete_mode,
            font=("Helvetica", 12),
            height=32
        )
        delete_button.pack(side="right", padx=5)

        select_all_btn = ctk.CTkButton(
            header_frame,
            text="Select All",
            command=select_all_processes,
            font=("Helvetica", 12),
            height=32
        )

        # Display processes with hidden checkboxes
        for process in self.process_whitelist:
            process_frame = ctk.CTkFrame(whitelist_frame, fg_color="transparent")
            process_frame.pack(fill="x", pady=2, padx=10)
            
            # Process name
            ctk.CTkLabel(
                process_frame,
                text=process,
                font=("Helvetica", 12)
            ).pack(side="left")
            
            # Create checkbox (initially hidden)
            var = ctk.BooleanVar()
            checkbox = ctk.CTkCheckBox(
                process_frame,
                text="",
                variable=var,
                width=20,
                height=20
            )
            self.process_checkboxes[process] = var
            self.process_frames[process] = (process_frame, checkbox)

    def show_process_manager(self):
        """Show process whitelist management window."""
        manager_window = ctk.CTkToplevel(self)
        manager_window.title("Process Whitelist Manager")
        
        # Make the window modal (user must interact with it before using main window)
        manager_window.transient(self)
        manager_window.grab_set()
        
        # Set size
        popup_width = 400
        popup_height = 250
        
        # Get the main window's position and size
        main_x = self.winfo_x()
        main_y = self.winfo_y()
        main_width = self.winfo_width()
        
        # Calculate position for the popup (centered horizontally, 50px from top)
        popup_x = main_x + (main_width - popup_width) // 2
        popup_y = main_y + 50
        
        # Set the position and size
        manager_window.geometry(f"{popup_width}x{popup_height}+{popup_x}+{popup_y}")
        
        # Prevent resizing
        manager_window.resizable(False, False)
        
        # Create main frame with padding
        form_frame = ctk.CTkFrame(manager_window)
        form_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(
            form_frame,
            text="Add New Process",
            font=("Helvetica", 18, "bold")
        ).pack(pady=(0, 20))
        
        # Process name input with label
        input_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        input_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            input_frame,
            text="Process Name (with extension):",
            font=("Helvetica", 12)
        ).pack(anchor="w", pady=(0, 5))
        
        process_entry = ctk.CTkEntry(input_frame, height=35, font=("Helvetica", 12))
        process_entry.pack(fill="x")
        
        def add_process():
            process = process_entry.get().strip().lower()
            if process:
                self.add_to_whitelist(process)
                self._show_admin_panel()
                manager_window.destroy()
            else:
                messagebox.showerror("Error", "Please enter a process name")
        
        # Add button
        ctk.CTkButton(
            form_frame,
            text="Add Process",
            command=add_process,
            font=("Helvetica", 13),
            height=35
        ).pack(fill="x", pady=(20, 0))

    def show_limits_manager(self):
        """Show resource limits management window."""
        manager_window = ctk.CTkToplevel(self)
        manager_window.title("Resource Limits Manager")
        
        # Make the window modal (user must interact with it before using main window)
        manager_window.transient(self)
        manager_window.grab_set()
        
        # Set size
        popup_width = 400
        popup_height = 300
        
        # Get the main window's position and size
        main_x = self.winfo_x()
        main_y = self.winfo_y()
        main_width = self.winfo_width()
        
        # Calculate position for the popup (centered horizontally, 50px from top)
        popup_x = main_x + (main_width - popup_width) // 2
        popup_y = main_y + 50
        
        # Set the position and size
        manager_window.geometry(f"{popup_width}x{popup_height}+{popup_x}+{popup_y}")
        
        # Prevent resizing
        manager_window.resizable(False, False)
        
        # Create main frame with padding
        form_frame = ctk.CTkFrame(manager_window)
        form_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(
            form_frame,
            text="Set Resource Limits",
            font=("Helvetica", 18, "bold")
        ).pack(pady=(0, 20))
        
        # CPU limit input with label
        cpu_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        cpu_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(
            cpu_frame,
            text="CPU Limit (%):",
            font=("Helvetica", 12)
        ).pack(anchor="w", pady=(0, 5))
        
        cpu_entry = ctk.CTkEntry(cpu_frame, height=35, font=("Helvetica", 12))
        cpu_entry.insert(0, str(self.resource_limits['cpu']))
        cpu_entry.pack(fill="x")
        
        # Memory limit input with label
        memory_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        memory_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            memory_frame,
            text="Memory Limit (%):",
            font=("Helvetica", 12)
        ).pack(anchor="w", pady=(0, 5))
        
        memory_entry = ctk.CTkEntry(memory_frame, height=35, font=("Helvetica", 12))
        memory_entry.insert(0, str(self.resource_limits['memory']))
        memory_entry.pack(fill="x")
        
        def update_limits():
            try:
                cpu = float(cpu_entry.get())
                memory = float(memory_entry.get())
                
                if 0 <= cpu <= 100 and 0 <= memory <= 100:
                    self.update_resource_limits(cpu, memory)
                    self._show_admin_panel()
                    manager_window.destroy()
                else:
                    messagebox.showerror("Error", "Limits must be between 0 and 100")
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numbers")
        
        # Update button
        ctk.CTkButton(
            form_frame,
            text="Update Limits",
            command=update_limits,
            font=("Helvetica", 13),
            height=35
        ).pack(fill="x", pady=(20, 0))

    def update_resource_limits(self, cpu, memory):
        """Update resource limits and save to file."""
        self.resource_limits['cpu'] = cpu
        self.resource_limits['memory'] = memory
        
        try:
            with open('resource_limits.txt', 'w') as f:
                f.write(f"cpu,{cpu}\n")
                f.write(f"memory,{memory}\n")
            print("Resource limits updated successfully")
        except Exception as e:
            print(f"Error saving resource limits: {e}")

    def add_to_whitelist(self, process_name):
        """Add a new process to the whitelist."""
        try:
            if process_name not in self.process_whitelist:
                # Add to memory list
                self.process_whitelist.append(process_name)
                # Append to file
                with open('process_whitelist.txt', 'a') as f:
                    f.write(f"{process_name}\n")
                print(f"Added {process_name} to whitelist")
                # Refresh display
                self._show_admin_panel()
        except Exception as e:
            print(f"Error adding process to whitelist: {e}")

    def load_process_whitelist(self):
        """Load process whitelist from file."""
        try:
            whitelist = []
            with open('process_whitelist.txt', 'r') as f:
                for line in f:
                    process = line.strip()
                    if process:  # Skip empty lines
                        whitelist.append(process)
            print(f"Loaded {len(whitelist)} processes in whitelist")
            return whitelist
        except FileNotFoundError:
            print("Whitelist file not found, creating default whitelist")
            # Create default whitelist
            default_whitelist = [
                "chrome.exe",
                "code.exe",
                "python.exe",
                "explorer.exe",
                "discord.exe",
                "whatsapp.exe"
            ]
            # Save default whitelist
            with open('process_whitelist.txt', 'w') as f:
                for process in default_whitelist:
                    f.write(f"{process}\n")
            return default_whitelist
        except Exception as e:
            print(f"Error loading whitelist: {e}")
            return []

    def remove_from_whitelist(self, process_name):
        """Remove a process from the whitelist."""
        try:
            if process_name.lower() in self.process_whitelist:
                del self.process_whitelist[process_name.lower()]
                self.save_process_whitelist(self.process_whitelist)
                print(f"Removed {process_name} from whitelist")
        except Exception as e:
            print(f"Error removing process from whitelist: {e}")

    def show_users(self):
        """Display the users page."""
        self.navigate_to(lambda: self._show_users())

    def _show_users(self):
        """Internal method to show users page."""
        self.clear_main_frame()
        frame = ctk.CTkFrame(self.main_frame)
        frame.pack(fill="both", expand=True)
        self.current_frame = frame

        # Title
        ctk.CTkLabel(frame, text="Users Management", font=("Helvetica", 24, "bold")).pack(pady=20)
        
        # Add your users management content here
        ctk.CTkLabel(frame, text="User management functionality coming soon...", font=("Helvetica", 14)).pack(pady=20)

    def show_statistics(self):
        """Display the statistics page."""
        self.navigate_to(lambda: self._show_statistics())

    def _show_statistics(self):
        """Internal method to show statistics page."""
        self.clear_main_frame()
        frame = ctk.CTkFrame(self.main_frame)
        frame.pack(fill="both", expand=True)
        self.current_frame = frame

        # Title
        ctk.CTkLabel(frame, text="Statistics", font=("Helvetica", 24, "bold")).pack(pady=20)
        
        # Add your statistics content here
        ctk.CTkLabel(frame, text="Statistics functionality coming soon...", font=("Helvetica", 14)).pack(pady=20)

    def show_system_resources(self):
        """Display the system resources page."""
        self.navigate_to(lambda: self._show_system_resources())

    def _show_system_resources(self):
        """Internal method to show system resources page."""
        self.clear_main_frame()
        
        # Create main container with scrollable frame
        container = ctk.CTkScrollableFrame(self.main_frame)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        self.current_frame = container

        # Title
        ctk.CTkLabel(
            container, 
            text="System Resource Monitoring",
            font=("Helvetica", 24, "bold")
        ).pack(anchor="w", pady=(0, 30))

        # CPU Usage
        cpu_frame = ctk.CTkFrame(container, fg_color="transparent")
        cpu_frame.pack(fill="x", padx=15, pady=5)
        
        cpu_label_frame = ctk.CTkFrame(cpu_frame, fg_color="transparent")
        cpu_label_frame.pack(fill="x")
        ctk.CTkLabel(
            cpu_label_frame,
            text="CPU usage",
            font=("Helvetica", 12)
        ).pack(side="left")
        self.cpu_percent_label = ctk.CTkLabel(
            cpu_label_frame,
            text="0%",
            font=("Helvetica", 12)
        )
        self.cpu_percent_label.pack(side="right")
        
        self.cpu_progress = ctk.CTkProgressBar(cpu_frame, height=6)
        self.cpu_progress.pack(fill="x", pady=(5, 2))
        self.cpu_progress.set(0)
        
        self.cpu_freq_label = ctk.CTkLabel(
            cpu_frame,
            text="Calculating...",
            font=("Helvetica", 10),
            text_color="gray"
        )
        self.cpu_freq_label.pack(anchor="w")

        # Memory Usage
        memory_frame = ctk.CTkFrame(container, fg_color="transparent")
        memory_frame.pack(fill="x", padx=15, pady=5)
        
        memory_label_frame = ctk.CTkFrame(memory_frame, fg_color="transparent")
        memory_label_frame.pack(fill="x")
        ctk.CTkLabel(
            memory_label_frame,
            text="Memory usage",
            font=("Helvetica", 12)
        ).pack(side="left")
        self.memory_percent_label = ctk.CTkLabel(
            memory_label_frame,
            text="0%",
            font=("Helvetica", 12)
        )
        self.memory_percent_label.pack(side="right")
        
        self.memory_progress = ctk.CTkProgressBar(memory_frame, height=6)
        self.memory_progress.pack(fill="x", pady=(5, 2))
        self.memory_progress.set(0)
        
        self.memory_label = ctk.CTkLabel(
            memory_frame,
            text="Calculating...",
            font=("Helvetica", 10),
            text_color="gray"
        )
        self.memory_label.pack(anchor="w")

        # Disk Usage
        self.disk_frames = {}
        for partition in psutil.disk_partitions():
            if partition.fstype:
                disk_frame = ctk.CTkFrame(container, fg_color="transparent")
                disk_frame.pack(fill="x", padx=15, pady=5)
                
                disk_label_frame = ctk.CTkFrame(disk_frame, fg_color="transparent")
                disk_label_frame.pack(fill="x")
                ctk.CTkLabel(
                    disk_label_frame,
                    text=f"Disk usage ({partition.device})",
                    font=("Helvetica", 12)
                ).pack(side="left")
                disk_percent_label = ctk.CTkLabel(
                    disk_label_frame,
                    text="0%",
                    font=("Helvetica", 12)
                )
                disk_percent_label.pack(side="right")
                
                disk_progress = ctk.CTkProgressBar(disk_frame, height=6)
                disk_progress.pack(fill="x", pady=(5, 2))
                disk_progress.set(0)
                
                self.disk_frames[partition.device] = (disk_percent_label, disk_progress)

        # Network Usage
        self.network_frames = {}
        self.prev_net_io = psutil.net_io_counters(pernic=True)
        for interface in self.prev_net_io.keys():
            network_frame = ctk.CTkFrame(container, fg_color="transparent")
            network_frame.pack(fill="x", padx=15, pady=5)
            
            ctk.CTkLabel(
                network_frame,
                text=f"Network usage ({interface})",
                font=("Helvetica", 12)
            ).pack(anchor="w")
            
            network_label = ctk.CTkLabel(
                network_frame,
                text="↑0 B/s  ↓0 B/s",
                font=("Helvetica", 10),
                text_color="gray"
            )
            network_label.pack(anchor="w")
            
            self.network_frames[interface] = network_label

        # GPU Usage
        self.gpu_frames = []
        try:
            gpus = GPUtil.getGPUs()
            for gpu in gpus:
                gpu_frame = ctk.CTkFrame(container, fg_color="transparent")
                gpu_frame.pack(fill="x", padx=15, pady=5)
                
                gpu_label_frame = ctk.CTkFrame(gpu_frame, fg_color="transparent")
                gpu_label_frame.pack(fill="x")
                ctk.CTkLabel(
                    gpu_label_frame,
                    text=f"GPU {gpu.id} usage",
                    font=("Helvetica", 12)
                ).pack(side="left")
                gpu_percent_label = ctk.CTkLabel(
                    gpu_label_frame,
                    text="0%",
                    font=("Helvetica", 12)
                )
                gpu_percent_label.pack(side="right")
                
                gpu_progress = ctk.CTkProgressBar(gpu_frame, height=6)
                gpu_progress.pack(fill="x", pady=(5, 2))
                gpu_progress.set(0)
                
                gpu_memory_label = ctk.CTkLabel(
                    gpu_frame,
                    text="Calculating...",
                    font=("Helvetica", 10),
                    text_color="gray"
                )
                gpu_memory_label.pack(anchor="w")
                
                gpu_temp_label = ctk.CTkLabel(
                    gpu_frame,
                    text="Temp: Calculating...",
                    font=("Helvetica", 10),
                    text_color="gray"
                )
                gpu_temp_label.pack(anchor="w")
                
                self.gpu_frames.append({
                    'usage_label': gpu_percent_label,
                    'usage_progress': gpu_progress,
                    'memory_label': gpu_memory_label,
                    'temp_label': gpu_temp_label
                })
        except Exception as e:
            print(f"Error retrieving GPU information: {e}")

        # Start resource updates
        self.update_system_resources()

    def update_system_resources(self):
        """Update resource information on system resources page."""
        try:
            # Check if the frame exists and we're still on the system resources page
            if not hasattr(self, 'current_frame') or not self.current_frame.winfo_exists():
                return False

            # Update CPU usage
            if hasattr(self, 'cpu_percent_label') and self.cpu_percent_label.winfo_exists():
                cpu_percent = psutil.cpu_percent(interval=0.1)
                self.cpu_percent_label.configure(text=f"{cpu_percent:.1f}%")
                if hasattr(self, 'cpu_progress'):
                    self.cpu_progress.set(cpu_percent / 100)
            
            # Update CPU frequency if label exists
            if hasattr(self, 'cpu_freq_label') and self.cpu_freq_label.winfo_exists():
                try:
                    cpu_freq = psutil.cpu_freq()
                    if cpu_freq:
                        current_freq = cpu_freq.current / 1000.0
                        self.cpu_freq_label.configure(text=f"{current_freq:.2f} GHz")
                except Exception:
                    self.cpu_freq_label.configure(text="CPU frequency unavailable")

            # Update Memory usage
            if hasattr(self, 'memory_percent_label') and self.memory_percent_label.winfo_exists():
                memory = psutil.virtual_memory()
                self.memory_percent_label.configure(text=f"{memory.percent:.1f}%")
                
                if hasattr(self, 'memory_progress') and self.memory_progress.winfo_exists():
                    self.memory_progress.set(memory.percent / 100)
                
                if hasattr(self, 'memory_label') and self.memory_label.winfo_exists():
                    total_gb = memory.total / (1024**3)
                    used_gb = (memory.used) / (1024**3)  # Corrected to show used memory
                    self.memory_label.configure(text=f"{used_gb:.1f} GB of {total_gb:.1f} GB")

            # Update Disk usage
            if hasattr(self, 'disk_frames'):
                for partition in psutil.disk_partitions():
                    if partition.fstype and partition.device in self.disk_frames:
                        try:
                            usage = psutil.disk_usage(partition.mountpoint)
                            label, progress = self.disk_frames[partition.device]
                            if label.winfo_exists() and progress.winfo_exists():
                                total_gb = usage.total / (1024**3)
                                used_gb = usage.used / (1024**3)
                                label.configure(text=f"{used_gb:.1f}/{total_gb:.1f}GB ({usage.percent}%)")
                                progress.set(usage.percent / 100)
                        except Exception:
                            continue

            # Update Network usage
            if hasattr(self, 'network_frames') and hasattr(self, 'prev_net_io'):
                current_net_io = psutil.net_io_counters(pernic=True)
                for interface, stats in current_net_io.items():
                    if interface in self.network_frames and interface in self.prev_net_io:
                        if self.network_frames[interface].winfo_exists():
                            bytes_sent = stats.bytes_sent - self.prev_net_io[interface].bytes_sent
                            bytes_recv = stats.bytes_recv - self.prev_net_io[interface].bytes_recv
                            
                            upload_speed = self.format_bytes(bytes_sent) + "/s"
                            download_speed = self.format_bytes(bytes_recv) + "/s"
                            
                            self.network_frames[interface].configure(
                                text=f"↑{upload_speed}  ↓{download_speed}"
                            )
                
                self.prev_net_io = current_net_io

            # Update GPU usage
            if hasattr(self, 'gpu_frames'):
                try:
                    gpus = GPUtil.getGPUs()
                    for i, gpu in enumerate(gpus):
                        if i < len(self.gpu_frames):
                            frame = self.gpu_frames[i]
                            if all(widget.winfo_exists() for widget in frame.values()):
                                # Update GPU usage
                                frame['usage_label'].configure(text=f"{gpu.load*100:.1f}%")
                                frame['usage_progress'].set(gpu.load)
                                
                                # Update GPU memory
                                memory_total = gpu.memoryTotal / 1024
                                memory_used = gpu.memoryUsed / 1024
                                memory_percent = (memory_used / memory_total) * 100
                                frame['memory_label'].configure(
                                    text=f"{memory_used:.1f}/{memory_total:.1f}GB ({memory_percent:.1f}%)"
                                )
                                
                                # Update GPU temperature
                                frame['temp_label'].configure(text=f"Temp: {gpu.temperature}°C")
                except Exception as e:
                    print(f"Error updating GPU info: {e}")

            # Schedule next update if frame still exists
            if self.current_frame.winfo_exists():
                self.after(1000, self.update_system_resources)
            return True

        except Exception as e:
            print(f"Error updating system resources: {e}")
            return False

    def format_bytes(self, bytes):
        """Format bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024
        return f"{bytes:.1f} TB"

    def show_alerts(self):
        """Display the alerts page."""
        self.navigate_to(lambda: self._show_alerts())

    def _show_alerts(self):
        """Internal method to show alerts page."""
        self.clear_main_frame()
        
        # Create main container with scrollable frame
        container = ctk.CTkScrollableFrame(self.main_frame)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        self.current_frame = container

        # Title
        title_frame = ctk.CTkFrame(container, fg_color="transparent")
        title_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            title_frame, 
            text="System Alerts",
            font=("Helvetica", 24, "bold")
        ).pack(side="left")

        # Add refresh button to title frame
        refresh_btn = ctk.CTkButton(
            title_frame,
            text="Refresh Alerts",
            command=self._show_alerts,
            font=("Helvetica", 12),
            height=32
        )
        refresh_btn.pack(side="right", padx=10)

        if not self.alerts:
            ctk.CTkLabel(
                container,
                text="No alerts found.",
                font=("Helvetica", 14),
                text_color="gray"
            ).pack(anchor="w", padx=15, pady=10)
        else:
            # Table container
            table_frame = ctk.CTkFrame(container)
            table_frame.pack(fill="x", pady=(0, 2))
            
            # Define headers and their widths
            headers = ["Time", "Process", "Alert Type", "Resource Usage"]
            widths = [100, 150, 200, 300]  # Adjusted widths
            
            # Header row
            header_row = ctk.CTkFrame(table_frame, fg_color="gray25", height=28)
            header_row.pack(fill="x")
            header_row.pack_propagate(False)
            
            # Create headers
            for header, width in zip(headers, widths):
                header_cell = ctk.CTkFrame(header_row, width=width, fg_color="transparent")
                header_cell.pack(side="left", padx=3)
                header_cell.pack_propagate(False)
                
                ctk.CTkLabel(
                    header_cell,
                    text=header,
                    font=("Helvetica", 12, "bold"),
                    text_color=("gray10", "gray90")
                ).pack(expand=True, pady=3)

            # Create alert entries
            for i, alert in enumerate(self.alerts):
                row_color = "gray17" if i % 2 == 0 else "gray20"
                row_frame = ctk.CTkFrame(table_frame, fg_color=row_color, height=26)
                row_frame.pack(fill="x", pady=1)
                row_frame.pack_propagate(False)
                
                # Get process name from alert
                process_name = alert.get("process_name", "System")
                
                # Get resource usage from details
                details = alert.get("details", "")
                resource_usage = ""
                if "Resource Usage -" in details:
                    resource_usage = details.split("Resource Usage -")[1].split("\n")[0].strip()
                elif "usage is" in details:
                    resource_usage = details.split("usage is")[1].split(".")[0].strip()
                
                # Prepare cell data
                cells_data = [
                    (alert["time"], widths[0]),
                    (process_name, widths[1]),
                    (alert["message"], widths[2]),
                    (resource_usage, widths[3])
                ]
                
                for text, width in cells_data:
                    cell = ctk.CTkFrame(row_frame, width=width, fg_color="transparent")
                    cell.pack(side="left", padx=3)
                    cell.pack_propagate(False)
                    
                    label = ctk.CTkLabel(
                        cell,
                        text=text,
                        font=("Helvetica", 11)
                    )
                    label.pack(expand=True, pady=3)

    def show_logs(self):
        """Display logs page."""
        self.navigate_to(lambda: self._show_logs())

    def _show_logs(self):
        """Internal method to show logs page."""
        self.clear_main_frame()
        
        container = ctk.CTkScrollableFrame(self.main_frame)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        self.current_frame = container

        # Create header frame for title and refresh button
        header_frame = ctk.CTkFrame(container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))

        # Title and refresh button container
        title_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_container.pack(fill="x", padx=20)

        # Title
        ctk.CTkLabel(
            title_container, 
            text="System Logs",
            font=("Helvetica", 24, "bold")
        ).pack(side="left")

        # Refresh button
        refresh_btn = ctk.CTkButton(
            title_container,
            text="Refresh Logs",
            command=self._show_logs,
            font=("Helvetica", 12),
            height=32
        )
        refresh_btn.pack(side="right")

        if not self.logs:
            ctk.CTkLabel(
                container,
                text="No logs found.",
                font=("Helvetica", 14),
                text_color="gray"
            ).pack(anchor="w", padx=15, pady=10)
        else:
            # Table container
            table_frame = ctk.CTkFrame(container)
            table_frame.pack(fill="x", pady=(0, 2))
            
            # Added 2 more columns: Status and Action
            headers = ["Time", "IP", "Event", "Level", "Status", "Action", "User"]
            widths = [80, 120, 240, 70, 80, 100, 100]  # Adjusted widths to fit new columns
            
            # Header row
            header_row = ctk.CTkFrame(table_frame, fg_color="gray25", height=28)
            header_row.pack(fill="x")
            header_row.pack_propagate(False)
            
            # Create headers
            for header, width in zip(headers, widths):
                header_cell = ctk.CTkFrame(header_row, width=width, fg_color="transparent")
                header_cell.pack(side="left", padx=3)
                header_cell.pack_propagate(False)
                
                ctk.CTkLabel(
                    header_cell,
                    text=header,
                    font=("Helvetica", 12, "bold"),
                    text_color=("gray10", "gray90")
                ).pack(expand=True, pady=3)

            # Create log entries
            for i, log in enumerate(self.logs):
                row_color = "gray17" if i % 2 == 0 else "gray20"
                row_frame = ctk.CTkFrame(table_frame, fg_color=row_color, height=26)
                row_frame.pack(fill="x", pady=1)
                row_frame.pack_propagate(False)
                
                cells_data = [
                    (log["timestamp"], widths[0]),
                    (log["source_ip"], widths[1]),
                    (log["event"], widths[2]),
                    (log["severity"], widths[3]),
                    (log["status"], widths[4]),
                    (log["action"], widths[5]),
                    (log["user"], widths[6])
                ]
                
                for text, width in cells_data:
                    cell = ctk.CTkFrame(row_frame, width=width, fg_color="transparent")
                    cell.pack(side="left", padx=3)
                    cell.pack_propagate(False)
                    
                    # Special color coding for severity and status
                    if text in ["High", "Med"]:
                        text_color = "#FF4444" if text == "High" else "#FFA500"
                    elif text in ["Blocked", "Failed", "Alert"]:
                        text_color = "#FF4444"
                    elif text in ["Success", "Allowed"]:
                        text_color = "#00CC00"
                    elif text in ["Pending"]:
                        text_color = "#FFA500"
                    else:
                        text_color = None
                    
                    label = ctk.CTkLabel(
                        cell,
                        text=text,
                        font=("Helvetica", 11),
                        text_color=text_color if text_color else None
                    )
                    label.pack(expand=True, pady=3)

    def on_window_resize(self, event):
        """Handle window resize events."""
        if hasattr(self, 'main_frame'):
            current_width = self.winfo_width()
            
            # Toggle between hamburger and normal menu based on window width
            if current_width < self.RESPONSIVE_THRESHOLD and not self.is_hamburger_visible:
                self.switch_to_hamburger_menu()
            elif current_width >= self.RESPONSIVE_THRESHOLD and self.is_hamburger_visible:
                self.switch_to_normal_menu()

    def switch_to_hamburger_menu(self):
        """Switch to hamburger menu layout."""
        if hasattr(self, 'sidebar'):
            self.sidebar.pack_forget()
            self.hamburger_button.pack(side="left", padx=10, pady=5)
            self.is_hamburger_visible = True
            self.menu_visible = False

    def switch_to_normal_menu(self):
        """Switch to normal menu layout."""
        if hasattr(self, 'sidebar'):
            self.hamburger_button.pack_forget()
            self.sidebar.pack(side="left", fill="y", before=self.main_frame)
            self.is_hamburger_visible = False
            self.menu_visible = True

    def handle_alert(self, resource_type, value):
        """Handle alerts and log events when resource limits are exceeded."""
        try:
            # Strictly check if the value exceeds the limit
            threshold = float(self.resource_limits.get(resource_type.lower(), 90))
            if value <= threshold:
                return  # Exit if limit is not exceeded
            
            # print(f"Generating alert for {resource_type}: {value}% > {threshold}%")
            
            current_time = datetime.now()
            formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
            alert_message = f"System {resource_type} usage exceeded"

            # Create alert entry
            alert = {
                "priority": "High",
                "message": alert_message,
                "details": f"System {resource_type} usage is {value:.1f}%, which is above the threshold of {threshold}%.",
                "time": current_time.strftime("%H:%M:%S"),
                "process_name": "System"
            }

            # Create log entry
            log_entry = {
                "timestamp": formatted_time,
                "source_ip": "localhost",
                "event": alert_message,
                "severity": "High",
                "status": "Alert",
                "action": "System Monitoring",
                "user": "system",
                "process": "System"
            }

            # Add to in-memory lists
            self.alerts.insert(0, alert)
            self.logs.insert(0, log_entry)

            # Keep only the last 100 entries
            if len(self.alerts) > 100:
                self.alerts.pop()
            if len(self.logs) > 100:
                self.logs.pop()

            # Write to log file
            with open(self.log_file, 'a') as f:
                f.write(f"{formatted_time},{resource_type},{alert_message},High,Alert,System Monitoring,system\n")

            # Save alerts and logs to a file
            self.save_alerts_and_logs()

            # Force refresh of displays
            self.update_displays()

        except Exception as e:
            print(f"Error in handle_alert: {e}")  # Keep error prints for debugging

    def save_alerts_and_logs(self):
        """Save alerts and logs to a file."""
        with open('alerts_logs.json', 'w') as f:
            json.dump({'alerts': self.alerts, 'logs': self.logs}, f)

    def update_displays(self):
        """Force refresh of alerts and logs displays"""
        try:
            if self.current_page == self._show_alerts:
                self._show_alerts()
            elif self.current_page == self._show_logs:
                self._show_logs()
        except Exception as e:
            print(f"Error updating displays: {e}")

    def start_monitoring(self):
        """Start monitoring system resources."""
        # print("Starting monitoring...")  # Debug print
        self.monitoring_active = True
        
        # Cancel any existing monitoring task
        if self.monitoring_task:
            self.after_cancel(self.monitoring_task)
        
        # Start the monitoring loop
        self.monitor_resources()

    def monitor_resources(self):
        """Continuous monitoring loop with process checking."""
        try:
            # Get accurate CPU and Memory usage
            cpu_total = psutil.cpu_percent(interval=1)  # Get overall CPU usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent  # Get actual memory percentage
            
            # print("\n=== Current System Status ===")
            # print(f"Current Usage - CPU: {cpu_total:.1f}%, Memory: {memory_percent:.1f}%")
            # print(f"Current Limits - CPU: {self.resource_limits['cpu']}%, Memory: {self.resource_limits['memory']}%")
            # print("\nWhitelisted Processes:", [p.lower() for p in self.process_whitelist])
            
            # print("\n=== Running Processes ===")
            # Track if any non-whitelisted process is causing high usage
            high_usage_detected = False
            
            # Check all running processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower()
                    
                    # Get accurate process usage
                    process = psutil.Process(proc_info['pid'])
                    # Get process CPU percentage relative to total CPU
                    proc_cpu = process.cpu_percent() / psutil.cpu_count()
                    # Get process memory percentage relative to total memory
                    proc_memory = (process.memory_info().rss / memory.total) * 100
                    
                    # Print all processes with significant resource usage (above 1%)
                    # if proc_cpu > 1 or proc_memory > 1:
                    #     print(f"\nProcess: {proc_name}")
                    #     print(f"  PID: {proc_info['pid']}")
                    #     print(f"  CPU: {proc_cpu:.1f}%")
                    #     print(f"  Memory: {proc_memory:.1f}%")
                    #     print(f"  In Whitelist: {proc_name in [p.lower() for p in self.process_whitelist]}")
                    
                    # Check if process exceeds limits
                    cpu_exceeded = proc_cpu > float(self.resource_limits['cpu'])
                    mem_exceeded = proc_memory > float(self.resource_limits['memory'])
                    
                    if cpu_exceeded or mem_exceeded:
                        # print(f"\n=== High Usage Process Detected ===")
                        # print(f"Process: {proc_name}")
                        # print(f"  CPU: {proc_cpu:.1f}% (Limit: {self.resource_limits['cpu']}%)")
                        # print(f"  Memory: {proc_memory:.1f}% (Limit: {self.resource_limits['memory']}%)")
                        
                        # Check if process is in whitelist (case-insensitive)
                        is_whitelisted = any(whitelisted.lower() == proc_name for whitelisted in self.process_whitelist)
                        # print(f"  Is Whitelisted: {is_whitelisted}")
                        
                        if not is_whitelisted:
                            high_usage_detected = True
                            self.handle_process_alert(
                                proc_name, 
                                proc_cpu, 
                                proc_memory, 
                                "Process exceeding resource limits"
                            )
                        # else:
                        #     print(f"  Status: Ignoring (whitelisted)")
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            # Only generate system-wide alerts if no specific process was identified as the cause
            if not high_usage_detected:
                if cpu_total > float(self.resource_limits['cpu']):
                    # print(f"\nSystem CPU Alert: {cpu_total:.1f}% > {self.resource_limits['cpu']}%")
                    self.handle_alert("CPU", cpu_total)

                if memory_percent > float(self.resource_limits['memory']):
                    # print(f"\nSystem Memory Alert: {memory_percent:.1f}% > {self.resource_limits['memory']}%")
                    self.handle_alert("Memory", memory_percent)

            # Update UI regardless of alerts
            if hasattr(self, 'current_page'):
                if self.current_page == self._show_system_resources or self.current_page == self._show_home:
                    self.update_resource_displays(cpu_total, memory)

        except Exception as e:
            print(f"Error in monitor_resources: {e}")  # Keep error prints for debugging

        finally:
            if self.monitoring_active:
                self.monitoring_task = self.after(2000, self.monitor_resources)  # Check every 2 seconds

    def update_resource_displays(self, cpu_total, memory):
        """Update system resource displays if they exist."""
        try:
            if hasattr(self, 'cpu_percent_label') and self.cpu_percent_label.winfo_exists():
                self.cpu_percent_label.configure(text=f"{cpu_total:.1f}%")
                if hasattr(self, 'cpu_progress'):
                    self.cpu_progress.set(cpu_total / 100)
            
            if hasattr(self, 'memory_label') and self.memory_label.winfo_exists():
                total_gb = memory.total / (1024**3)
                used_gb = (memory.used) / (1024**3)  # Corrected to show used memory
                self.memory_label.configure(text=f"{used_gb:.1f} GB of {total_gb:.1f} GB")
                if hasattr(self, 'memory_progress'):
                    self.memory_progress.set(memory.percent / 100)
        except Exception as e:
            print(f"Error updating resource displays: {e}")

    def stop_monitoring(self):
        """Stop monitoring system resources."""
        # print("Stopping monitoring...")  # Debug print
        self.monitoring_active = False
        if self.monitoring_task:
            self.after_cancel(self.monitoring_task)
            self.monitoring_task = None

    def handle_process_alert(self, process_name, cpu_usage, memory_usage, reason):
        """Handle alerts for suspicious process activity."""
        try:
            # Strictly check if either CPU or memory usage exceeds limits
            if (cpu_usage <= float(self.resource_limits['cpu']) and 
                memory_usage <= float(self.resource_limits['memory'])):
                return  # Exit if no limits are exceeded
            
            # print(f"Generating process alert for {process_name}")
            # print(f"CPU: {cpu_usage}% > {self.resource_limits['cpu']}%")
            # print(f"Memory: {memory_usage}% > {self.resource_limits['memory']}%")
            
            current_time = datetime.now()
            formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Create more specific alert message
            exceeded_resources = []
            if cpu_usage > float(self.resource_limits['cpu']):
                exceeded_resources.append(f"CPU: {cpu_usage:.1f}% > {self.resource_limits['cpu']}%")
            if memory_usage > float(self.resource_limits['memory']):
                exceeded_resources.append(f"Memory: {memory_usage:.1f}% > {self.resource_limits['memory']}%")
            
            alert_message = f"Process {process_name} exceeded limits"
            
            # Create detailed alert
            alert = {
                "priority": "High",
                "message": alert_message,
                "details": (f"Process: {process_name}\n"
                          f"Resource Usage - {', '.join(exceeded_resources)}\n"
                          f"Reason: {reason}"),
                "time": current_time.strftime("%H:%M:%S"),
                "process_name": process_name
            }

            # Create log entry
            log_entry = {
                "timestamp": formatted_time,
                "source_ip": "localhost",
                "event": alert_message,
                "severity": "High",
                "status": "Alert",
                "action": "Process Monitoring",
                "user": "system",
                "process": process_name
            }

            # Add to in-memory lists
            self.alerts.insert(0, alert)
            self.logs.insert(0, log_entry)

            # Maintain list size
            if len(self.alerts) > 100:
                self.alerts.pop()
            if len(self.logs) > 100:
                self.logs.pop()

            # Write to log file
            with open(self.log_file, 'a') as f:
                f.write(f"{formatted_time},Process,{alert_message},High,Alert,Process Monitoring,system\n")

            # Save alerts and logs
            self.save_alerts_and_logs()
            
            # Force refresh of displays if on alerts or logs page
            if self.current_page in [self._show_alerts, self._show_logs]:
                self.current_page()

        except Exception as e:
            print(f"Error in handle_process_alert: {e}")  # Keep error prints for debugging

    def load_resource_limits(self):
        """Load resource limits from file."""
        try:
            with open('resource_limits.txt', 'r') as f:
                limits = {}
                for line in f:
                    resource, limit = line.strip().split(',')
                    limits[resource] = float(limit)
                return limits
        except FileNotFoundError:
            # Return default limits
            return {'cpu': 50, 'memory': 70}

    def start_packet_monitoring(self):
        """Start monitoring network packets using Scapy."""
        if not self.packet_monitoring_active:
            self.packet_monitoring_active = True
            self.packet_monitoring_thread = threading.Thread(target=self.monitor_packets)
            self.packet_monitoring_thread.daemon = True
            self.packet_monitoring_thread.start()
            print("Network packet monitoring started...")

    def stop_packet_monitoring(self):
        """Stop monitoring network packets."""
        self.packet_monitoring_active = False
        if self.packet_monitoring_thread:
            self.packet_monitoring_thread = None
            print("Network packet monitoring stopped...")

    def packet_callback(self, packet):
        """Callback function to process captured packets."""
        if not self.packet_monitoring_active:
            return

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "Unknown"
            src_port = "N/A"
            dst_port = "N/A"

            # Determine protocol and ports
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # Print packet information
            print(f"\nPacket detected:")
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Protocol: {protocol}")
            print(f"Source: {src_ip}:{src_port}")
            print(f"Destination: {dst_ip}:{dst_port}")
            print(f"Length: {len(packet)} bytes")

    def monitor_packets(self):
        """Monitor network packets continuously."""
        try:
            # Start packet capture
            sniff(prn=self.packet_callback, store=0)
        except Exception as e:
            print(f"Error in packet monitoring: {e}")


if __name__ == "__main__":
    app = IntrusionDetectionApp()
    app.mainloop()
