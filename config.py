"""
SOC Radar configuration.

For security, provide API keys via environment variables.
"""

import os

# ---------------------------------------------------------------------------
# AbuseIPDB keys (rotation supported)
# Provide as a comma-separated list in ABUSEIPDB_API_KEYS.
# Example:
#   set ABUSEIPDB_API_KEYS=key1,key2,key3
# ---------------------------------------------------------------------------
_ABUSEIPDB_KEYS_ENV = os.getenv("ABUSEIPDB_KEYS")
if _ABUSEIPDB_KEYS_ENV:
    ABUSEIPDB_API_KEYS = [k.strip() for k in _ABUSEIPDB_KEYS_ENV.split(",") if k.strip()]
else:
    ABUSEIPDB_API_KEYS = ["YOUR ABUSEIPDB_API_KEY"]
ABUSEIPDB_API_KEY = ABUSEIPDB_API_KEYS[0] if ABUSEIPDB_API_KEYS else ""

# AbuseIPDB endpoint
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

# Maximum age (in days) for report lookback
MAX_AGE_DAYS = 90

# Thread-pool size for parallel IP lookups
MAX_WORKERS = 20

# ---------------------------------------------------------------------------
# VirusTotal configuration
# ---------------------------------------------------------------------------
VIRUSTOTAL_API_KEY = "YOUR VIRUSTOTAL_API_KEY"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/api/v3/urls/{id}"
VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files/{hash}"

# ---------------------------------------------------------------------------
# AlienVault OTX configuration
# ---------------------------------------------------------------------------
OTX_API_KEY = "YOUR OTX_API_KEY"
OTX_IP_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

# ---------------------------------------------------------------------------
# SOC Sheet configuration (optional)
# ---------------------------------------------------------------------------
SOC_SHEET_CSV_URL ="YOUR SOC SHEET URL"
OTX_URL_URL = "https://otx.alienvault.com/api/v1/indicators/url/{url}/general"
