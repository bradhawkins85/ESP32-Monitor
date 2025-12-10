Import("env")
import os

# Load .env file
try:
    with open(".env", "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()
except FileNotFoundError:
    print("Warning: .env file not found, using defaults from config.h")

# Inject environment variables as build flags
# Separate boolean flags from string values
bool_vars = {
    "DISCORD_ENABLED": os.environ.get("DISCORD_ENABLED", "false"),
    "NTFY_ENABLED": os.environ.get("NTFY_ENABLED", "true"),
    "EMAIL_ENABLED": os.environ.get("EMAIL_ENABLED", "false"),
    "WEBHOOK_ENABLED": os.environ.get("WEBHOOK_ENABLED", "false"),
}

string_vars = {
    # WiFi Configuration
    "WIFI_SSID": os.environ.get("WIFI_SSID", "your_wifi_ssid"),
    "WIFI_PASSWORD": os.environ.get("WIFI_PASSWORD", "your_wifi_password"),
    
    # LoRa/MeshCore Channel Configuration
    "CHANNEL_NAME": os.environ.get("CHANNEL_NAME", "BCAlerts"),
    "CHANNEL_SECRET": os.environ.get("CHANNEL_SECRET", ""),
    
    # Discord Configuration
    "DISCORD_WEBHOOK_URL": os.environ.get("DISCORD_WEBHOOK_URL", ""),
    
    # Ntfy Configuration
    "NTFY_SERVER": os.environ.get("NTFY_SERVER", "https://ntfy.sh"),
    "NTFY_TOPIC": os.environ.get("NTFY_TOPIC", "esp32_uptime"),
    
    # Email/SMTP Configuration
    "SMTP_HOST": os.environ.get("SMTP_HOST", "smtp.gmail.com"),
    "SMTP_PORT": os.environ.get("SMTP_PORT", "587"),
    "EMAIL_RECIPIENT": os.environ.get("EMAIL_RECIPIENT", ""),
    "EMAIL_SENDER": os.environ.get("EMAIL_SENDER", ""),
    "SMTP_USER": os.environ.get("SMTP_USER", ""),
    "SMTP_PASSWORD": os.environ.get("SMTP_PASSWORD", ""),
    
    # Generic Webhook Configuration
    "WEBHOOK_URL": os.environ.get("WEBHOOK_URL", ""),
    "WEBHOOK_METHOD": os.environ.get("WEBHOOK_METHOD", "POST"),
}

# Handle boolean values (no quotes needed for preprocessor)
for key, value in bool_vars.items():
    bool_value = value.lower() in ['true', '1', 'yes', 'on']
    env.Append(CPPDEFINES=[(key, '1' if bool_value else '0')])

# Handle string values (need quotes)
for key, value in string_vars.items():
    # Escape quotes in the value
    value = value.replace('"', '\\"')
    env.Append(CPPDEFINES=[(key, f'\\"{value}\\"')])
