import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

PUBLIC_BACKEND_URL = os.getenv("PUBLIC_BACKEND_URL", "http://localhost:8000")
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "soc_platform")
ELASTICSEARCH_HOSTS = os.getenv("ELASTICSEARCH_HOSTS", "http://localhost:9200")
ES_USERNAME = os.getenv("ES_USERNAME", "")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")
ELASTICSEARCH_INDEX = "soc-events"
AGENT_LOGS_ES_INDEX = "soc-agent-logs"

GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "")
THREAT_FEED_URL = os.getenv("THREAT_FEED_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
THREAT_FEED_REFRESH_HOURS = int(os.getenv("THREAT_FEED_REFRESH_HOURS", "6"))

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")

# Serve the session cookie with Secure only when the backend itself is on
# HTTPS (set SECURE_COOKIES=1 in production); dev over plain HTTP keeps False
# so login keeps working locally.
SECURE_COOKIES = os.getenv("SECURE_COOKIES", "0") == "1"

# Reverse proxies we allow to set X-Forwarded-For / X-Real-IP (comma-separated
# IPs or CIDRs). Requests from any other source are treated as direct clients
# and their forwarded headers are ignored to prevent IP spoofing. The default
# covers localhost (dev) and Docker's default 172.16.0.0/12 bridge networks
# (the compose nginx frontend runs on one of these).
TRUSTED_PROXY_IPS = os.getenv("TRUSTED_PROXY_IPS", "127.0.0.1,::1,172.16.0.0/12").split(",")
