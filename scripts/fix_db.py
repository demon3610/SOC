"""
One-time DB migration + diagnostics for an EXISTING database.

Run this only when the backend fails to start or behave on a database that
predates the current schema — it renames legacy fields, backfills missing
fields, seeds the admin user + default project on an empty DB, bootstraps
the counters used by get_next_id(), and ensures indexes exist.

Run from the repo root against a locally exposed Mongo:
    python scripts/fix_db.py
(or point MongoClient below at the docker-mapped port 27017).
For a full clean-slate reset instead, use scripts/reset_dev.py.
"""
from pymongo import MongoClient
from datetime import datetime, timezone

c = MongoClient('mongodb://localhost:27017')
db = c['soc_platform']

print("=== MongoDB Migration & Diagnostics ===\n")

# 1. Fix user schema: old code stored 'password', new code expects 'hashed_password'
r1 = db.users.update_many(
    {"password": {"$exists": True}, "hashed_password": {"$exists": False}},
    {"$rename": {"password": "hashed_password"}}
)
print(f"[1] Renamed 'password' -> 'hashed_password': {r1.modified_count} user(s) fixed")

# 2. Add missing 'created_at' field to any users that lack it
r2 = db.users.update_many(
    {"created_at": {"$exists": False}},
    {"$set": {"created_at": datetime.now(timezone.utc)}}
)
print(f"[2] Added missing 'created_at': {r2.modified_count} user(s) updated")

# Seed default admin user if no users exist
if db.users.count_documents({}) == 0:
    import bcrypt
    hashed = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode()
    db.users.insert_one({
        "id": 1,
        "email": "admin@soc.local",
        "hashed_password": hashed,
        "name": "Admin User",
        "created_at": datetime.now(timezone.utc)
    })
    print("[+] Seeded admin@soc.local user with password 'admin123'")

if db.projects.count_documents({}) == 0:
    db.projects.insert_one({
        "id": 1,
        "owner_id": 1,
        "name": "Default Security Project",
        "type": "system",
        "description": "Main SOC Monitoring Project",
        "created_at": datetime.now(timezone.utc)
    })
    print("[+] Seeded Default Security Project (ID 1)")

# 3. Bootstrap counters for all collections (so get_next_id() works)
collections = [
    "users", "projects", "api_keys", "agent_keys",
    "events_website", "events_windows", "events_linux",
    "incidents", "incident_evidence"
]
for col in collections:
    docs = list(db[col].find({}, {"id": 1, "_id": 0}).sort("id", -1).limit(1))
    max_id = docs[0]["id"] if docs else 0
    existing = db.counters.find_one({"_id": col})
    if not existing:
        db.counters.insert_one({"_id": col, "seq": max_id})
        print(f"[3] Created counter '{col}' at seq={max_id}")
    elif existing["seq"] < max_id:
        db.counters.update_one({"_id": col}, {"$set": {"seq": max_id}})
        print(f"[3] Updated counter '{col}' to seq={max_id}")
    else:
        print(f"[3] Counter '{col}' OK (seq={existing['seq']})")

# 4. Ensure indexes exist
db.users.create_index("email", unique=True)
db.api_keys.create_index("key_hash")
db.agent_keys.create_index("key_hash", unique=True)  # already exists as unique
db.agent_keys.create_index("created_by")
db.incidents.create_index("project_id")
db.incident_evidence.create_index("incident_id")
for source in ("website", "windows", "linux"):
    db[f"events_{source}"].create_index([("project_id", 1), ("timestamp", -1)])
for source in ("windows", "linux"):
    db[f"events_{source}"].create_index("agent_id")
print("[4] Indexes ensured")

# 5. Final summary
print("\n=== Final State ===")
u = db.users.find_one({}, {"_id": 0, "hashed_password": 0})
print(f"Users          : {db.users.count_documents({})}   sample={u}")
print(f"Projects       : {db.projects.count_documents({})}")
print(f"Agent Keys     : {db.agent_keys.count_documents({})}")
print(f"Events (total) : {sum(db[f'events_{s}'].count_documents({}) for s in ('website', 'windows', 'linux'))}")
print(f"Incidents      : {db.incidents.count_documents({})}")
print(f"Counters       : {list(db.counters.find({}, {'seq': 1}))}")

print("\n[OK] Migration complete! Restart the backend server now.")
