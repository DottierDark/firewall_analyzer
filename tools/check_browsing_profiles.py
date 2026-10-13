import sys
from pathlib import Path
import pandas as pd

# ==========================================================
# Remove old output files before creating new ones
# ==========================================================

for file_name in [
    "OUTPUT_all_protected_channel_rules.csv",
    "OUTPUT_FLAGGED_no_profile.csv"
]:
    path = Path(file_name)
    if path.exists():
        path.unlink()

# ==========================================================
# Load CSV / Excel
# ==========================================================

input_file = sys.argv[1] 

if input_file.lower().endswith((".xlsx", ".xls")):
    df = pd.read_excel(input_file)
else:
    df = pd.read_csv(input_file)

print(f"Loaded {len(df)} rules from: {input_file}")

# ==========================================================
# Find Security Profile column
# ==========================================================

profile_col = None

for col in df.columns:
    if "profile" in str(col).lower():
        profile_col = col
        break

# ==========================================================
# Browsing definitions
# ==========================================================

BROWSING_SERVICES = {
    "http",
    "https",
    "service-http",
    "service-https",
    "tcp-80",
    "tcp_80",
    "tcp_80_http",
    "tcp-443",
    "tcp_443",
    "tcp_443_tls",
}

BROWSING_APPS = {
    "web-browsing",
    "ssl",
}

# ==========================================================
# Management definitions
# ==========================================================

MANAGEMENT_SERVICES = {
    "ssh",
    "tcp-22",
    "tcp_22_ssh",
    "tcp-3389",
    "tcp_3389_rdp",
    "tcp-5985",
    "tcp-5986",
}

MANAGEMENT_APPS = {
    "ssh",
    "ms-rdp",
    "winrm",
}

# ==========================================================
# Helpers
# ==========================================================

def contains_token(value, valid_tokens):
    for token in str(value).split(";"):
        if token.strip().lower() in valid_tokens:
            return True
    return False


def has_profile(value):
    return str(value).strip().lower() not in (
        "",
        "none",
        "nan",
        "-"
    )

# ==========================================================
# Detect Browsing Rules
# ==========================================================

df["Browsing_Service"] = df["Service"].apply(
    lambda x: contains_token(x, BROWSING_SERVICES)
)

df["Browsing_App"] = df["Application"].apply(
    lambda x: contains_token(x, BROWSING_APPS)
)

# ==========================================================
# Detect Management Rules
# ==========================================================

df["Management_Service"] = df["Service"].apply(
    lambda x: contains_token(x, MANAGEMENT_SERVICES)
)

df["Management_App"] = df["Application"].apply(
    lambda x: contains_token(x, MANAGEMENT_APPS)
)

# ==========================================================
# Protected Channels
# ==========================================================

df["Protected_Channel"] = (
    df["Browsing_Service"]
    |
    df["Browsing_App"]
    |
    df["Management_Service"]
    |
    df["Management_App"]
)

# ==========================================================
# Enabled Rules Only
# ==========================================================

df["Enabled"] = ~df["Action"].astype(str).str.lower().str.contains(
    r"\[disabled\]"
)

protected_rules = df[
    (df["Protected_Channel"]) &
    (df["Enabled"])
].copy()

print(f"Protected channel rules found: {len(protected_rules)}")

# ==========================================================
# Security Profile Check
# ==========================================================

if profile_col is None:

    print("\nNo Security Profile column found.")

    protected_rules.to_csv(
        "OUTPUT_all_protected_channel_rules.csv",
        index=False
    )

    print("Saved OUTPUT_all_protected_channel_rules.csv")

    sys.exit(0)

protected_rules["HasProfile"] = protected_rules[
    profile_col
].apply(has_profile)

flagged = protected_rules[
    ~protected_rules["HasProfile"]
].copy()

# ==========================================================
# Save Outputs
# ==========================================================

protected_rules.to_csv(
    "OUTPUT_all_protected_channel_rules.csv",
    index=False
)

flagged.to_csv(
    "OUTPUT_FLAGGED_no_profile.csv",
    index=False
)

# ==========================================================
# Summary
# ==========================================================

print("-" * 60)
print(f"Protected channel rules: {len(protected_rules)}")
print(f"Missing Security Profile: {len(flagged)}")
print("-" * 60)

print("Saved OUTPUT_all_protected_channel_rules.csv")
print("Saved OUTPUT_FLAGGED_no_profile.csv")