Import("env")
import os
import subprocess

# Load .env file
try:
    with open(".env", "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                # Remove surrounding quotes if present
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                os.environ[key] = value
                # Debug output for sensitive fields
                if key in ["NTFY_PASSWORD", "NTFY_USERNAME", "NTFY_TOKEN"]:
                    print(f"Loaded {key}: length={len(value)}")
except FileNotFoundError:
    print("Warning: .env file not found, using defaults from config.h")

# Determine FIRMWARE_VERSION: .env > environment variable > git tag > fallback
def get_firmware_version():
    # 1. Already set in .env or environment
    ver = os.environ.get("FIRMWARE_VERSION", "")
    if ver:
        print(f"Firmware version from env: {ver}")
        return ver
    # 2. Derive from git tag (e.g. v1.0.2 -> 1.0.2)
    try:
        tag = subprocess.check_output(
            ["git", "describe", "--tags", "--abbrev=0"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        if tag.startswith("v"):
            tag = tag[1:]
        print(f"Firmware version from git tag: {tag}")
        return tag
    except Exception:
        pass
    # 3. Derive from git describe (e.g. v1.0.0-3-gabcdef -> 1.0.0-dev.3)
    try:
        desc = subprocess.check_output(
            ["git", "describe", "--tags", "--always"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        if desc.startswith("v"):
            desc = desc[1:]
        # Convert vX.Y.Z-N-gHASH to X.Y.Z-dev.N
        parts = desc.split("-")
        if len(parts) >= 3:
            base = parts[0]
            commits = parts[1]
            return f"{base}-dev.{commits}"
        print(f"Firmware version from git describe: {desc}")
        return desc
    except Exception:
        pass
    print("Warning: Could not determine firmware version, using 0.0.0-unknown")
    return "0.0.0-unknown"

firmware_version = get_firmware_version()
os.environ["FIRMWARE_VERSION"] = firmware_version

# Inject environment variables as build flags
# Separate boolean flags from string values
bool_vars = {
    "LORA_ENABLED": os.environ.get("LORA_ENABLED", "true"),
    "LORA_IP_ALERTS": os.environ.get("LORA_IP_ALERTS", "true"),
    "DISCORD_ENABLED": os.environ.get("DISCORD_ENABLED", "false"),
    "DISCORD_IP_ALERTS": os.environ.get("DISCORD_IP_ALERTS", "true"),
    "NTFY_ENABLED": os.environ.get("NTFY_ENABLED", "true"),
    "NTFY_IP_ALERTS": os.environ.get("NTFY_IP_ALERTS", "true"),
    "EMAIL_ENABLED": os.environ.get("EMAIL_ENABLED", "false"),
    "EMAIL_IP_ALERTS": os.environ.get("EMAIL_IP_ALERTS", "true"),
    "WEBHOOK_ENABLED": os.environ.get("WEBHOOK_ENABLED", "false"),
    "WEBHOOK_IP_ALERTS": os.environ.get("WEBHOOK_IP_ALERTS", "true"),
    "MQTT_ENABLED": os.environ.get("MQTT_ENABLED", "false"),
    "MQTT_IP_ALERTS": os.environ.get("MQTT_IP_ALERTS", "true"),
    "NTFY_MESH_RELAY": os.environ.get("NTFY_MESH_RELAY", "true"),
    "DISCORD_MESH_RELAY": os.environ.get("DISCORD_MESH_RELAY", "true"),
    "WEBHOOK_MESH_RELAY": os.environ.get("WEBHOOK_MESH_RELAY", "false"),
    "EMAIL_MESH_RELAY": os.environ.get("EMAIL_MESH_RELAY", "false"),
    "MQTT_MESH_RELAY": os.environ.get("MQTT_MESH_RELAY", "false"),
    "SHOW_BOOT_CREDENTIALS": os.environ.get("SHOW_BOOT_CREDENTIALS", "true"),
    "AUTO_OTA_ENABLED": os.environ.get("AUTO_OTA_ENABLED", "false"),
}

string_vars = {
    # WiFi Configuration
    "WIFI_SSID": os.environ.get("WIFI_SSID", "your_wifi_ssid"),
    "WIFI_PASSWORD": os.environ.get("WIFI_PASSWORD", "your_wifi_password"),

    # Captive Portal Hotspot
    "HOTSPOT_IP": os.environ.get("HOTSPOT_IP", "192.168.4.1"),

    # Admin Authentication
    "ADMIN_USERNAME": os.environ.get("ADMIN_USERNAME", "admin"),

    # LoRa/MeshCore Channel Configuration
    "CHANNEL_NAME": os.environ.get("CHANNEL_NAME", "BCAlerts"),
    "LORA_NODE_NAME": os.environ.get("LORA_NODE_NAME", ""),
    "CHANNEL_SECRET": os.environ.get("CHANNEL_SECRET", ""),
    
    # Discord Configuration
    "DISCORD_WEBHOOK_URL": os.environ.get("DISCORD_WEBHOOK_URL", ""),
    
    # Ntfy Configuration
    "NTFY_SERVER": os.environ.get("NTFY_SERVER", "https://ntfy.sh"),
    "NTFY_TOPIC": os.environ.get("NTFY_TOPIC", "esp32_uptime"),
    "NTFY_USERNAME": os.environ.get("NTFY_USERNAME", ""),
    "NTFY_PASSWORD": os.environ.get("NTFY_PASSWORD", ""),
    "NTFY_TOKEN": os.environ.get("NTFY_TOKEN", ""),
    
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

    # MQTT Configuration
    "MQTT_BROKER": os.environ.get("MQTT_BROKER", ""),
    "MQTT_PORT": os.environ.get("MQTT_PORT", "1883"),
    "MQTT_TOPIC": os.environ.get("MQTT_TOPIC", "esp32-monitor/alerts"),
    "MQTT_USERNAME": os.environ.get("MQTT_USERNAME", ""),
    "MQTT_PASSWORD": os.environ.get("MQTT_PASSWORD", ""),

    # Auto OTA Configuration
    "FIRMWARE_VERSION": firmware_version,
    "AUTO_OTA_URL": os.environ.get("AUTO_OTA_URL", ""),
}

# Numeric vars (no quotes)
int_vars = {
    "LED_PIN": os.environ.get("LED_PIN", "35"),
    "LORA_SPREADING_FACTOR": os.environ.get("LORA_SPREADING_FACTOR", "7"),
    "LORA_CODING_RATE": os.environ.get("LORA_CODING_RATE", "5"),
    "MQTT_QOS": os.environ.get("MQTT_QOS", "0"),
    "AUTO_OTA_CHECK_INTERVAL": os.environ.get("AUTO_OTA_CHECK_INTERVAL", "3600"),
}

# Float vars (no quotes)
float_vars = {
    "LORA_FREQ": os.environ.get("LORA_FREQ", "915.0"),
    "LORA_BANDWIDTH": os.environ.get("LORA_BANDWIDTH", "125.0"),
}

# Handle boolean values (no quotes needed for preprocessor)
bool_defines = {}
for key, value in bool_vars.items():
    bool_value = value.lower() in ['true', '1', 'yes', 'on']
    bool_defines[key] = '1' if bool_value else '0'
    env.Append(CPPDEFINES=[(key, bool_defines[key])])

# Generate a header for string values to avoid shell/SCons mangling of characters like '$'
header_lines = [
    "// Auto-generated by load_env.py. Do not edit manually.",
    "#pragma once",
    ""
]

def c_escape(val: str) -> str:
    return val.replace('\\', '\\\\').replace('"', '\\"')

for key, value in string_vars.items():
    if key in ["NTFY_PASSWORD", "NTFY_USERNAME", "NTFY_TOKEN"]:
        print(f"Injecting {key}: original_len={len(os.environ.get(key, ''))}, escaped_len={len(value)}")
    escaped = c_escape(value)
    header_lines.append(f'#define {key} "{escaped}"')

for key, value in int_vars.items():
    header_lines.append(f'#define {key} {value}')

for key, value in float_vars.items():
    header_lines.append(f'#define {key} {value}')

for key, value in bool_defines.items():
    header_lines.append(f'#define {key} {value}')

os.makedirs("include", exist_ok=True)
header_path = os.path.join("include", "generated_env.h")
with open(header_path, "w", encoding="ascii") as header_file:
    header_file.write("\n".join(header_lines))
print(f"Wrote {header_path}")
