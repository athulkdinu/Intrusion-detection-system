import psutil
from datetime import datetime

class ResourceMonitor:
    def __init__(self, app):
        self.app = app
        self.monitoring_active = False
        self.monitoring_task = None

    def start_monitoring(self):
        self.monitoring_active = True
        if self.monitoring_task:
            self.app.after_cancel(self.monitoring_task)
        self.monitor_resources()

    def stop_monitoring(self):
        self.monitoring_active = False
        if self.monitoring_task:
            self.app.after_cancel(self.monitoring_task)
            self.monitoring_task = None

    def monitor_resources(self):
        try:
            cpu_total = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            high_usage_detected = False
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    self._check_process(proc, memory, high_usage_detected)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            if not high_usage_detected:
                self._check_system_resources(cpu_total, memory_percent)

        except Exception as e:
            print(f"Error in monitor_resources: {e}")

        finally:
            if self.monitoring_active:
                self.monitoring_task = self.app.after(2000, self.monitor_resources)

    def _check_process(self, proc, memory, high_usage_detected):
        # Process monitoring logic here
        pass

    def _check_system_resources(self, cpu_total, memory_percent):
        # System resource checking logic here
        pass