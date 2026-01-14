#ifndef CONFIG_H
#define CONFIG_H

// Generated overrides from .env (if present)
#if defined(__has_include)
#if __has_include("generated_env.h")
#include "generated_env.h"
#endif
#endif

// ============================================
// Build-time Configuration
// ============================================

// WiFi Configuration
#ifndef WIFI_SSID
#define WIFI_SSID "your_wifi_ssid"
#endif

#ifndef WIFI_PASSWORD
#define WIFI_PASSWORD "your_wifi_password"
#endif

// IP Configuration
#ifndef IP_MODE
#define IP_MODE "DHCP"  // "DHCP" or "STATIC"
#endif

#ifndef STATIC_IP
#define STATIC_IP "192.168.1.100"
#endif

#ifndef STATIC_GATEWAY
#define STATIC_GATEWAY "192.168.1.1"
#endif

#ifndef STATIC_SUBNET
#define STATIC_SUBNET "255.255.255.0"
#endif

// DNS Configuration
#ifndef DNS_MODE
#define DNS_MODE "DHCP"  // "DHCP" or "STATIC"
#endif

#ifndef STATIC_DNS1
#define STATIC_DNS1 "8.8.8.8"
#endif

#ifndef STATIC_DNS2
#define STATIC_DNS2 "8.8.4.4"
#endif

// Captive portal hotspot (starts when STA WiFi can't connect)
// Hotspot SSID is generated per-device as: ESP32NM-<MAC>
#ifndef HOTSPOT_IP
#define HOTSPOT_IP "192.168.4.1"
#endif

#ifndef HOTSPOT_PASSWORD
#define HOTSPOT_PASSWORD "esp32monitor"
#endif

// Status LED (onboard). Override in .env via ADMIN_LED_PIN if different.
#ifndef LED_PIN
#define LED_PIN 35
#endif

// Battery monitor (Heltec WSL3 VBAT is available on GPIO1)
// Note: Vext (GPIO 36) and ADC_CTRL (GPIO 37) must be LOW to read battery.
#ifndef BATTERY_ADC_PIN
#define BATTERY_ADC_PIN 1
#endif

#ifndef BATTERY_READ_CONTROL_PIN
#define BATTERY_READ_CONTROL_PIN 37
#endif

#ifndef BATTERY_DIVIDER_RATIO
#define BATTERY_DIVIDER_RATIO 5.04f  // Calibrated from 5.00f (4.09V -> 4.12V)
#endif

#ifndef BATTERY_FULL_V
#define BATTERY_FULL_V 4.20f
#endif

#ifndef BATTERY_EMPTY_V
#define BATTERY_EMPTY_V 3.30f
#endif

#ifndef BATTERY_SAMPLES
#define BATTERY_SAMPLES 8
#endif

// Admin Authentication (used for UI/API/OTA access)
#ifndef ADMIN_USERNAME
#define ADMIN_USERNAME "admin"
#endif

#ifndef ADMIN_PASSWORD
#define ADMIN_PASSWORD "admin"
#endif

// LoRa Configuration
#ifndef LORA_FREQ
#define LORA_FREQ 915.0  // MHz: 915.0 for US, 868.0 for EU, 433.0 for Asia
#endif

#ifndef LORA_SPREADING_FACTOR
#define LORA_SPREADING_FACTOR 7  // 7-12 (lower = faster but shorter range)
#endif

#ifndef LORA_CODING_RATE
#define LORA_CODING_RATE 5  // 5-8 for 4/5 to 4/8 (higher = more error correction)
#endif

#ifndef LORA_BANDWIDTH
#define LORA_BANDWIDTH 125.0  // kHz: 125.0, 250.0, or 500.0
#endif

#ifndef LORA_ENABLED
#define LORA_ENABLED true
#endif

#ifndef LORA_IP_ALERTS
#define LORA_IP_ALERTS true
#endif

#ifndef LORA_NODE_NAME
#define LORA_NODE_NAME ""  // Default: first 8 hex chars of public key
#endif

#ifndef LORA_SYNC_WORD
#define LORA_SYNC_WORD 0x1424  // MeshCore private sync word
#endif

#ifndef LORA_PREAMBLE_LENGTH
#define LORA_PREAMBLE_LENGTH 16  // MeshCore uses 16-symbol preamble
#endif

// SX1262 Pin Definitions for Heltec Wireless Stick Lite V3
#ifndef LORA_NSS
#define LORA_NSS 8
#endif

#ifndef LORA_DIO1
#define LORA_DIO1 14
#endif

#ifndef LORA_RST
#define LORA_RST 12
#endif

#ifndef LORA_BUSY
#define LORA_BUSY 13
#endif

#ifndef LORA_MOSI
#define LORA_MOSI 10
#endif

#ifndef LORA_MISO
#define LORA_MISO 11
#endif

#ifndef LORA_SCK
#define LORA_SCK 9
#endif

#ifndef LORA_VEXT_PIN
#define LORA_VEXT_PIN 36
#endif

#ifndef LORA_TCXO_VOLTAGE
#define LORA_TCXO_VOLTAGE 1.6
#endif

#ifndef CHANNEL_NAME
#define CHANNEL_NAME "BCAlerts"  // Must match transmitter
#endif

#ifndef CHANNEL_SECRET
#define CHANNEL_SECRET "f7d32d9d09982b83c2c1086a5ea2239a"  // Must match transmitter
#endif

// Operating Mode - All devices now listen and can transmit
// No need for MODE_RX/MODE_TX distinction anymore

#ifndef TX_PING_INTERVAL_MS
#define TX_PING_INTERVAL_MS 30000  // How often to send ping in TX mode
#endif

#ifndef TX_PING_TEXT
#define TX_PING_TEXT "ping"  // Message prefix for TX pings
#endif

// Ntfy Configuration
#ifndef NTFY_ENABLED
#define NTFY_ENABLED true
#endif

#ifndef NTFY_IP_ALERTS
#define NTFY_IP_ALERTS true
#endif

#ifndef NTFY_SERVER
#define NTFY_SERVER "https://ntfy.sh"
#endif

#ifndef NTFY_TOPIC
#define NTFY_TOPIC "esp32_uptime"
#endif

#ifndef NTFY_USERNAME
#define NTFY_USERNAME ""  // Leave empty if not using username/password auth
#endif

#ifndef NTFY_PASSWORD
#define NTFY_PASSWORD ""  // Leave empty if not using username/password auth
#endif

#ifndef NTFY_TOKEN
#define NTFY_TOKEN ""  // Leave empty if not using token auth (token takes precedence over username/password)
#endif

#ifndef NTFY_MESH_RELAY
#define NTFY_MESH_RELAY true  // Relay mesh messages to Ntfy
#endif

// Email Configuration (SMTP)
#ifndef EMAIL_ENABLED
#define EMAIL_ENABLED false
#endif

#ifndef EMAIL_IP_ALERTS
#define EMAIL_IP_ALERTS true
#endif

#ifndef SMTP_HOST
#define SMTP_HOST "smtp.gmail.com"
#endif

#ifndef SMTP_PORT
#define SMTP_PORT 587
#endif

#ifndef EMAIL_RECIPIENT
#define EMAIL_RECIPIENT "recipient@example.com"
#endif

#ifndef EMAIL_SENDER
#define EMAIL_SENDER "esp32@example.com"
#endif

#ifndef EMAIL_MESH_RELAY
#define EMAIL_MESH_RELAY false  // Relay mesh messages to Email
#endif

// Discord Configuration
#ifndef DISCORD_ENABLED
#define DISCORD_ENABLED false
#endif

#ifndef DISCORD_IP_ALERTS
#define DISCORD_IP_ALERTS true
#endif

#ifndef DISCORD_WEBHOOK_URL
#define DISCORD_WEBHOOK_URL "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
#endif

#ifndef DISCORD_MESH_RELAY
#define DISCORD_MESH_RELAY true  // Relay mesh messages to Discord
#endif

// Generic Webhook Configuration
#ifndef WEBHOOK_ENABLED
#define WEBHOOK_ENABLED false
#endif

#ifndef WEBHOOK_IP_ALERTS
#define WEBHOOK_IP_ALERTS true
#endif

#ifndef WEBHOOK_URL
#define WEBHOOK_URL "https://example.com/webhook"
#endif

#ifndef WEBHOOK_MESH_RELAY
#define WEBHOOK_MESH_RELAY false  // Relay mesh messages to Webhook
#endif

#ifndef WEBHOOK_METHOD
#define WEBHOOK_METHOD "POST"
#endif

// MQTT Notification Configuration
#ifndef MQTT_ENABLED
#define MQTT_ENABLED false
#endif

#ifndef MQTT_IP_ALERTS
#define MQTT_IP_ALERTS true
#endif

#ifndef MQTT_MESH_RELAY
#define MQTT_MESH_RELAY false  // Relay mesh messages to MQTT
#endif

#ifndef MQTT_BROKER
#define MQTT_BROKER ""
#endif

#ifndef MQTT_PORT
#define MQTT_PORT 1883
#endif

#ifndef MQTT_TOPIC
#define MQTT_TOPIC "esp32-monitor/alerts"
#endif

#ifndef MQTT_QOS
#define MQTT_QOS 0  // 0, 1, or 2
#endif

#ifndef MQTT_USERNAME
#define MQTT_USERNAME ""
#endif

#ifndef MQTT_PASSWORD
#define MQTT_PASSWORD ""
#endif

// Display Configuration
#ifndef ENABLE_DISPLAY
#define ENABLE_DISPLAY true
#endif

#endif // CONFIG_H
