import random
import json
import re
from pymongo import MongoClient
from datetime import datetime, timedelta

# --- YAPILANDIRMA ---
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "middleware_db"

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

print("🧹 Eski veriler temizleniyor...")
db.apps_current.delete_many({})
db.ns_mappings.delete_many({})

# --- SAMPLE DATA SETLERİ ---
SERVERS = [f"srv-prod-{i:02d}" for i in range(1, 11)]
APP_BASES = ["PaymentSrv", "AuthAPI", "OrderGateway", "InventoryMgr", "NotificationSrv", "UserPortal", "ReportingUI"]
JAVA_VENDORS = ["OpenJDK", "IBM", "Oracle"]
NETSCALERS = ["10.10.1.10", "10.20.1.10"]
DATABASES = ["192.168.10.50:1521", "192.168.10.51:1521", "172.16.5.20:5432"]

def get_clean_app_name(raw_name):
    if not raw_name: return "Unknown"
    clean_name = re.sub(r'\d+$', '', raw_name).rstrip('_').rstrip('-')
    return clean_name

def generate_sample_data(count=100):
    print(f"🚀 {count} adet örnek veri üretiliyor...")
    
    for i in range(count):
        base_name = random.choice(APP_BASES)
        server = random.choice(SERVERS)
        node_id = random.randint(101, 105)
        instance_name = f"{base_name}_{node_id}"
        app_name = get_clean_app_name(instance_name)
        
        # Middleware tipini seçiyoruz
        mw_type = random.choice(["Tomcat", "Liberty", "Standalone"])
        
        # --- DNS MANTIĞI ---
        # Örn: paymentsrv-tomcat.company.com veya paymentsrv-liberty.company.com
        dns_entry = f"{app_name.lower()}-{mw_type.lower()}.company.com"
        
        # Drift ve Java simülasyonu
        java_ver = "11.0.12" if random.random() > 0.15 else "1.8.0_292"
        memory = "2g" if random.random() > 0.1 else "1g"
        port = random.choice(["8080", "8443", "9080", "7001"])
        server_ip = f"10.0.5.{random.randint(10, 200)}"
        
        app_doc = {
            "app_name": app_name,
            "instance_name": instance_name,
            "hostname": server,
            "server_ip": server_ip,
            "type": mw_type,
            "pid": str(random.randint(1000, 99999)),
            "java": {
                "vendor": random.choice(JAVA_VENDORS),
                "version": java_ver,
                "path": "/opt/java/bin/java"
            },
            "jvm_args": [
                f"-Xmx{memory}",
                f"-Xms{memory}",
                f"-Dinstance={instance_name}",
                "-Denv=prod",
                "-XX:+UseG1GC"
            ],
            "listen_ports": [port],
            "connected_dbs": [random.choice(DATABASES)],
            "dns_records": [dns_entry], # Middleware bazlı DNS
            "on_netscalers": [random.choice(NETSCALERS)],
            "is_running": True,
            "last_seen": datetime.utcnow()
        }

        doc_id = f"{server}_{instance_name}"

        db.apps_current.update_one(
            {"_id": doc_id},
            {"$set": app_doc},
            upsert=True
        )

        # NetScaler Cache
        mapping_id = f"{server_ip}:{port}"
        db.ns_mappings.update_one(
            {"_id": mapping_id},
            {
                "$set": {
                    "found_on_ns": app_doc['on_netscalers'],
                    "last_check": datetime.utcnow(),
                    "last_full_sweep": datetime.utcnow() - timedelta(days=random.randint(0, 45))
                }
            },
            upsert=True
        )

    print(f"✅ İşlem tamamlandı. DNS'ler middleware bazlı ayrıldı.")

if __name__ == "__main__":
    generate_sample_data(100)