import time
import requests
import threading
from datetime import datetime

# --- SYSTEM CONFIGURATION ---
# In a real industry setup, these would be your actual microservice URLs
SERVICES = {
    "Auth-Service": "https://www.google.com",
    "Payment-Gateway": "https://www.stripe.com",
    "Inventory-DB": "https://httpbin.org/status/404", # Simulated failing service
    "User-Analytics": "https://httpbin.org/status/500" # Simulated crashed service
}

class AegisControlPlane:
    def __init__(self):
        self.logs = []
        self.status_map = {name: "INITIALIZING" for name in SERVICES}

    def heal_service(self, name):
        """Simulates an industry self-healing protocol (e.g., restarting a Docker container)"""
        self.status_map[name] = "RESTARTING"
        time.sleep(2) # Simulating boot time
        self.status_map[name] = "HEALED/STABLE"

    def check_health(self, name, url):
        try:
            response = requests.get(url, timeout=3)
            if response.status_code < 400:
                self.status_map[name] = "✅ HEALTHY"
            else:
                self.status_map[name] = f"❌ FAILED ({response.status_code})"
                threading.Thread(target=self.heal_service, args=(name,)).start()
        except:
            self.status_map[name] = "🔥 CRITICAL/DOWN"
            threading.Thread(target=self.heal_service, args=(name,)).start()

    def display_dashboard(self):
        while True:
            # Clear terminal for a real 'dashboard' feel
            print("\033c", end="") 
            print(f"🚀 AEGIS-X CENTRAL CONTROL PLANE | {datetime.now().strftime('%H:%M:%S')}")
            print("=" * 60)
            print(f"{'SERVICE NAME':<20} | {'STATUS':<20} | {'UPTIME'}")
            print("-" * 60)
            
            for name, url in SERVICES.items():
                self.check_health(name, url)
                status = self.status_map[name]
                print(f"{name:<20} | {status:<20} | 99.9%")
            
            print("-" * 60)
            print("[System Message]: Monitoring active. Auto-healing enabled.")
            time.sleep(3)

if __name__ == "__main__":
    controller = AegisControlPlane()
    controller.display_dashboard()