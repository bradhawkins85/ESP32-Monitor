#ifndef CONFIG_H
#define CONFIG_H

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
#define LORA_VEXT_PIN 21
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

#ifndef NTFY_SERVER
#define NTFY_SERVER "https://ntfy.sh"
#endif

#ifndef NTFY_TOPIC
#define NTFY_TOPIC "esp32_uptime"
#endif

// Email Configuration (SMTP)
#ifndef EMAIL_ENABLED
#define EMAIL_ENABLED false
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

// Discord Configuration
#ifndef DISCORD_ENABLED
#define DISCORD_ENABLED false
#endif

#ifndef DISCORD_WEBHOOK_URL
#define DISCORD_WEBHOOK_URL "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
#endif

// Generic Webhook Configuration
#ifndef WEBHOOK_ENABLED
#define WEBHOOK_ENABLED false
#endif

#ifndef WEBHOOK_URL
#define WEBHOOK_URL "https://example.com/webhook"
#endif

#ifndef WEBHOOK_METHOD
#define WEBHOOK_METHOD "POST"
#endif

// Display Configuration
#ifndef ENABLE_DISPLAY
#define ENABLE_DISPLAY true
#endif

#endif // CONFIG_H
