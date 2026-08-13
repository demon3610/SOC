"""
Full development database reset + bootstrap.
Usage:
    docker cp scripts soc-backend-1:/app/scripts
    docker exec soc-backend-1 python -m scripts.reset_dev
    docker restart soc-backend-1
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from datetime import datetime, timezone
from app.database import get_db, get_next_id
from app.auth import hash_password
from app.config import MONGO_DB_NAME
from app.services.elastic import es, ELASTICSEARCH_INDEX, AGENT_LOGS_ES_INDEX

db = get_db()


def reset_mongo():
    print("=" * 60)
    print("RESET: MongoDB")
    print("=" * 60)
    collections = db.list_collection_names()
    print(f"  Found {len(collections)} collections: {collections}")
    for col in collections:
        result = db[col].delete_many({})
        print(f"  Cleared '{col}' ({result.deleted_count} documents)")
    print("  MongoDB reset complete.\n")


def reset_elasticsearch():
    print("=" * 60)
    print("RESET: Elasticsearch")
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
    print("  Elasticsearch reset complete.\n")


def bootstrap():
    print("=" * 60)
    print("BOOTSTRAP: Creating default data")
    print("=" * 60)

    # Ensure indexes
    from app.database import ensure_indexes
    ensure_indexes()
    print("  Indexes ensured.")

    # Admin user
    admin = {
        "id": get_next_id("users"),
        "email": "admin@soc.local",
        "hashed_password": hash_password("admin"),
        "name": "Admin",
        "created_at": datetime.now(timezone.utc),
    }
    db.users.insert_one(admin)
    print(f"  Admin user: id={admin['id']} email={admin['email']} password=admin")

    # Sample project
    project = {
        "id": get_next_id("projects"),
        "owner_id": admin["id"],
        "name": "Demo Project",
        "type": "system",
        "description": "Auto-created dev project",
        "created_at": datetime.now(timezone.utc),
    }
    db.projects.insert_one(project)
    print(f"  Project: id={project['id']} name={project['name']}")

    # Agent key
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
    print(f"  Agent key: {raw_key}")

    from app.services.elastic import ensure_index
    try:
        ensure_index()
        print("  ES indices ensured.")
    except Exception as e:
        print(f"  WARNING: ES index creation failed: {e}")

    print()
    print("=" * 60)
    print("RESET + BOOTSTRAP COMPLETE")
    print("=" * 60)
    print(f"  Login:  admin@soc.local / admin")
    print(f"  Agent:  {raw_key}")
    print(f"  Project: {project['id']} ({project['name']})")
    print()
    print("  Next steps:")
    print("    1. docker restart soc-backend-1")
    print("    2. Login at http://localhost:5173")
    print("=" * 60)


if __name__ == "__main__":
    force = "--yes" in sys.argv or "-y" in sys.argv

    print()
    print("!!! WARNING !!!")
    print(f"  This will DELETE ALL DATA in MongoDB '{MONGO_DB_NAME}'")
    print(f"  and Elasticsearch indices '{ELASTICSEARCH_INDEX}', '{AGENT_LOGS_ES_INDEX}'.")
    print()

    if not force:
        try:
            confirm = input("  Type 'yes' to proceed: ")
        except EOFError:
            print("  Non-interactive shell. Use --yes or -y to skip confirmation.")
            sys.exit(1)
        if confirm.lower() != "yes":
            print("  Aborted.")
            sys.exit(0)
    else:
        print("  --yes flag set, proceeding without confirmation.")

    reset_mongo()
    reset_elasticsearch()
    bootstrap()
