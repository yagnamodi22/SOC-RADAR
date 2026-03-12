"""
PSY9 Radar configuration.

For security, provide API keys via environment variables.
"""

import os

# ---------------------------------------------------------------------------
# AbuseIPDB keys (rotation supported)
# Provide as a comma-separated list in ABUSEIPDB_API_KEYS.
# Example:
#   set ABUSEIPDB_API_KEYS=key1,key2,key3
# ---------------------------------------------------------------------------
ABUSEIPDB_API_KEYS = [
    k.strip()
    for k in os.environ.get("ABUSEIPDB_API_KEYS", "").split(",")
    if k.strip()
]

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# AbuseIPDB endpoint
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

# Maximum age (in days) for report lookback
MAX_AGE_DAYS = 90

# Maximum parallelism (used for async semaphore defaults and legacy paths)
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "20"))

# ---------------------------------------------------------------------------
# VirusTotal configuration
# ---------------------------------------------------------------------------
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/api/v3/urls/{id}"
VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files/{hash}"

# ---------------------------------------------------------------------------
# AlienVault OTX configuration
# ---------------------------------------------------------------------------
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
OTX_IP_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
OTX_URL_URL = "https://otx.alienvault.com/api/v1/indicators/url/{url}/general"

# ---------------------------------------------------------------------------
# SOC Sheet configuration (optional)
# ---------------------------------------------------------------------------
SOC_SHEET_CSV_URL = os.environ.get("SOC_SHEET_CSV_URL", "")
