"""
Database reset and bootstrap script for SOC Platform.

Wipes all collections in MongoDB and indices in Elasticsearch, re-ensures
schema indexes, and seeds the initial admin user and default project.

Usage:
    python scripts/clear_db.py --yes
    python -m scripts.clear_db --yes
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from datetime import datetime, timezone
from app.database import get_db, get_next_id, ensure_indexes
from app.auth import hash_password
from app.config import MONGO_DB_NAME
from app.services.elastic import es, ELASTICSEARCH_INDEX, AGENT_LOGS_ES_INDEX, ensure_index


def clear_mongo():
    print("=" * 60)
    print("WIPING: MongoDB")
    print("=" * 60)
    db = get_db()
    collections = db.list_collection_names()
    print(f"  Found {len(collections)} collections: {collections}")
    for col in collections:
        res = db[col].delete_many({})
        print(f"  Cleared '{col}' ({res.deleted_count} documents)")
    print("  MongoDB wipe complete.\n")


def clear_elasticsearch():
    print("=" * 60)
    print("WIPING: Elasticsearch")
    print("=" * 60)
    for idx in [ELASTICSEARCH_INDEX, AGENT_LOGS_ES_INDEX]:
        try:
            if es.indices.exists(index=idx):
                es.indices.delete(index=idx)
                print(f"  Deleted index '{idx}'")
            es.indices.create(index=idx)
            print(f"  Created index '{idx}'")
        except Exception as e:
            print(f"  WARNING: Could not reset ES index '{idx}': {e}")
    print("  Elasticsearch wipe complete.\n")


def bootstrap_db():
    print("=" * 60)
    print("BOOTSTRAP: Initializing Schema & Seed Data")
    print("=" * 60)

    db = get_db()
    ensure_indexes()
    print("  Database indexes created/ensured.")

    # Admin user
    admin = {
        "id": get_next_id("users"),
        "email": "admin@soc.local",
        "hashed_password": hash_password("admin"),
        "name": "Admin",
        "created_at": datetime.now(timezone.utc),
    }
    db.users.insert_one(admin)
    print(f"  Created Admin user: ID={admin['id']}, Email={admin['email']}, Password=admin")

    # Primary project
    project = {
        "id": get_next_id("projects"),
        "owner_id": admin["id"],
        "name": "Main Security Project",
        "type": "system",
        "description": "Default SOC Monitoring Project",
        "created_at": datetime.now(timezone.utc),
    }
    db.projects.insert_one(project)
    print(f"  Created Project: ID={project['id']} ({project['name']})")

    # Initial Agent Key
    from app.models.agent_key import generate_raw_key, hash_raw_key
    raw_key = generate_raw_key()
    prefix = raw_key[:12]
    hashed = hash_raw_key(raw_key)
    agent_key = {
        "id": get_next_id("agent_keys"),
        "label": "dev-agent",
        "key_prefix": prefix,
        "key_hash": hashed,
        "status": "pending",
        "project_id": project["id"],
        "created_by": admin["id"],
        "created_at": datetime.now(timezone.utc),
        "enrolled_at": None,
        "last_seen_at": None,
        "revoked_at": None,
    }
    db.agent_keys.insert_one(agent_key)
    print(f"  Created Agent Key: {raw_key}")

    try:
        ensure_index()
        print("  Elasticsearch indices ensured.")
    except Exception as e:
        print(f"  WARNING: ES index initialization skipped: {e}")

    print()
    print("=" * 60)
    print("DATABASE CLEAR & INITIALIZATION COMPLETE")
    print("=" * 60)
    print(f"  Login Credentials : admin@soc.local / admin")
    print(f"  Default Project ID: {project['id']}")
    print(f"  Agent Key        : {raw_key}")
    print("=" * 60)


if __name__ == "__main__":
    force = "--yes" in sys.argv or "-y" in sys.argv
    print()
    print("!!! WARNING !!!")
    print(f"This will CLEAR ALL DATA in MongoDB '{MONGO_DB_NAME}'")
    print(f"and Elasticsearch indices '{ELASTICSEARCH_INDEX}', '{AGENT_LOGS_ES_INDEX}'.")
    print()

    if not force:
        try:
            confirm = input("Type 'yes' to proceed: ")
        except EOFError:
            print("Non-interactive shell. Use --yes or -y to skip confirmation.")
            sys.exit(1)
        if confirm.lower() != "yes":
            print("Aborted.")
            sys.exit(0)
    else:
        print("--yes flag set, proceeding with database reset.")

    clear_mongo()
    clear_elasticsearch()
    bootstrap_db()
