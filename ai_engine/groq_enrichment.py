# ==============================================================================
# EagleEye SIEM: AI SOAR & Alert Enrichment Module
# ==============================================================================
# os   → file paths and environment variables
# re   → masking sensitive data before sending to external AI API
# yaml → read AI settings from config.yaml
import os, re, yaml
# Groq is the AI provider — fastest inference available, free tier sufficient for SIEM demo
from groq import Groq

# Read AI settings from config.yaml — model/temperature/tokens tunable without touching code
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(_ROOT, "config.yaml")) as f:
    _AI = yaml.safe_load(f).get("ai", {})
MODEL       = _AI.get("model",       "llama-3.1-8b-instant")
TEMPERATURE = _AI.get("temperature",  0.3)
MAX_TOKENS  = _AI.get("max_tokens",   500)   # 500 prevents cut-off responses

# API key loaded from .env by engine.py before this module is imported
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    print("[-] WARNING: GROQ_API_KEY not found. Check your .env file.")

try:
    # Groq client created once at module load — not on every alert (faster)
    client = Groq(api_key=GROQ_API_KEY)
except Exception as e:
    client = None
    print(f"[-] Groq API connection error: {e}")

# ANSI escape codes = terminal color sequences e.g. \x1B[31m=red \x1B[0m=reset
# engine.py uses colorama which adds these — must strip before sending to AI
ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

# IPv4 pattern — matches any standard IPv4 address e.g. 192.168.100.22
IPV4_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# IPv6 pattern — matches ::1, fe80::1, full IPv6 addresses
IPV6_RE = re.compile(r'(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}')

# Catches any form the AI might write the placeholder back as:
# [REDACTED_IP], REDACTED_IP, <REDACTED_IP>, `REDACTED_IP`, redacted_ip
RESTORE_IPV4_RE = re.compile(r'[\[<`]?REDACTED_IP[\]>`]?', re.IGNORECASE)
RESTORE_IPV6_RE = re.compile(r'[\[<`]?REDACTED_IPv6[\]>`]?', re.IGNORECASE)


# ==============================================================================
def enrich_alert_with_ai(original_message):
    if not client:
        raise ValueError("Groq client not initialized. Check GROQ_API_KEY in .env")

    # PHASE 1: Strip ANSI color codes — AI sees plain text only
    clean = ANSI_ESCAPE.sub("", str(original_message)) if original_message else ""

    # PHASE 2: Detect OS → AI gives platform-specific commands in playbook
    # Linux alerts contain "Linux" in the message (from our rule names)
    # SSH is always Linux-side in our setup
    if "Linux" in clean or "ssh" in clean.lower():
        context = "You are analyzing a Linux/Ubuntu security alert. "
    else:
        context = "You are analyzing a Windows security alert. "

    # PHASE 3: Mask IP addresses before sending to external Groq API
    # IP addresses are the most sensitive data — should not leave the network in plaintext
    # We save the real IPs, replace with placeholders, restore after AI responds
    masked = clean

    # mask IPv4 — e.g. 192.168.100.22 → [REDACTED_IP]
    ipv4_match = IPV4_RE.search(masked)
    real_ipv4  = ipv4_match.group(0) if ipv4_match else None
    if real_ipv4:
        masked = masked.replace(real_ipv4, "[REDACTED_IP]")

    # mask IPv6 — e.g. ::1 → [REDACTED_IPv6]
    ipv6_match = IPV6_RE.search(masked)
    real_ipv6  = ipv6_match.group(0) if ipv6_match else None
    if real_ipv6:
        masked = masked.replace(real_ipv6, "[REDACTED_IPv6]")

    prompt = context + masked

    # PHASE 4: System prompt — strict format to get exactly 3 steps every time
    system_prompt = (
        "You are an expert Tier 3 SOC Analyst responding to a live security alert.\n"
        "Your job: produce a concise, actionable Incident Response Playbook.\n\n"
        "STRICT RULES:\n"
        "- Write EXACTLY 3 numbered steps. No more, no less.\n"
        "- Each step must be ONE clear action (contain, investigate, or remediate).\n"
        "- Use the SPECIFIC details from the alert: IP addresses, usernames, hostnames.\n"
        "- Be technical and direct. No preamble, no filler text, no extra sections.\n\n"
        "FORMAT (follow exactly):\n"
        "--> AI Analysis & Playbook:\n"
        "1. [Action verb]: [specific action using alert details]\n"
        "2. [Action verb]: [specific action using alert details]\n"
        "3. [Action verb]: [specific action using alert details]"
    )

    try:
        resp = client.chat.completions.create(
            messages=[
                # system role = permanent rules and persona for the AI
                {"role": "system", "content": system_prompt},
                # user role = the actual alert to analyze
                {"role": "user",   "content": f"Analyze this alert:\n{prompt}"}
            ],
            model=MODEL, temperature=TEMPERATURE, max_tokens=MAX_TOKENS
        )
        playbook = resp.choices[0].message.content

        # PHASE 5: Restore real IPs so analyst sees actual addresses
        # Use regex replacement to catch any variant the AI writes the placeholder as
        if real_ipv4:
            playbook = RESTORE_IPV4_RE.sub(real_ipv4, playbook)
        if real_ipv6:
            playbook = RESTORE_IPV6_RE.sub(real_ipv6, playbook)

        return playbook

    except Exception as e:
        raise Exception(f"Groq API Error: {str(e)}")
