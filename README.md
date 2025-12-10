# ESP32-Uptime-Receiver

An ESP32-based LoRa message receiver for Heltec Wireless Stick Lite v3 that forwards received messages to various web services including Ntfy, Email, Discord, and custom webhooks.

## Features

- 📡 **LoRa Message Reception**: Receives messages on a predetermined channel with authentication
- 🔐 **Secure Authentication**: Verifies channel name and secret before processing messages
- 📨 **Multiple Notification Services**:
  - Ntfy push notifications
  - Email (SMTP)
  - Discord webhooks
  - Generic HTTP webhooks
- 🖥️ **OLED Display**: Real-time status and message display
- 📶 **WiFi Connectivity**: Automatic connection and reconnection handling
- ⚙️ **Build-time Configuration**: All settings configurable at compile time

## Hardware Requirements

- **Heltec Wireless Stick Lite v3** (ESP32-S3 based board with LoRa and OLED)
- USB-C cable for programming and power

## Software Requirements

- [PlatformIO](https://platformio.org/) (recommended) or Arduino IDE
- PlatformIO Core (CLI) or PlatformIO IDE (VS Code extension)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/bradhawkins85/ESP32-Uptime-Receiver.git
   cd ESP32-Uptime-Receiver
   ```

2. Install PlatformIO if you haven't already:
   ```bash
   pip install platformio
   ```

## Configuration

The project uses a `.env` file for secure configuration management. This keeps your secrets out of version control.

### Setup Steps

1. **Copy the example environment file**:
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` with your actual credentials**:
   ```bash
   # WiFi Configuration
   WIFI_SSID=your_actual_wifi_name
   WIFI_PASSWORD=your_actual_wifi_password
   
   # LoRa/MeshCore Channel Configuration
   CHANNEL_NAME=BCAlerts
   CHANNEL_SECRET=your_actual_secret_key
   
   # Discord Notification (optional)
   DISCORD_ENABLED=true
   DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_ACTUAL_WEBHOOK
   
   # Ntfy Configuration (optional)
   NTFY_ENABLED=true
   NTFY_SERVER=https://ntfy.sh
   NTFY_TOPIC=your_topic_name
   
   # Email/SMTP Configuration (optional)
   EMAIL_ENABLED=false
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   EMAIL_RECIPIENT=recipient@example.com
   EMAIL_SENDER=sender@example.com
   SMTP_USER=your_email@gmail.com
   SMTP_PASSWORD=your_app_specific_password
   ```

3. **The `.env` file is automatically loaded** during the build process via `load_env.py`

> **Note**: The `.env` file is git-ignored and will never be committed to the repository. This keeps your credentials safe.

### Alternative: Override with platformio_override.ini

You can also use `platformio_override.ini` (also git-ignored) for configuration:

```ini
[env:heltec-wireless-stick-lite-v3]
build_flags = 
    -D WIFI_SSID='"YourWiFiSSID"'
    -D WIFI_PASSWORD='"YourWiFiPassword"'
    -D CHANNEL_NAME='"BCAlerts"'
    -D CHANNEL_SECRET='"your_secret"'
```

### Default Configuration

If no `.env` or override file is provided, the system will use defaults from `include/config.h`.
### LoRa Configuration

LoRa settings can be configured in `include/config.h`:

```cpp
#define LORA_FREQ 915.0  // MHz: 915.0 for US, 868.0 for EU, 433.0 for Asia
#define LORA_SPREADING_FACTOR 7  // 7-12 (lower = faster but shorter range)
#define LORA_CODING_RATE 5  // 5-8 for 4/5 to 4/8
#define LORA_BANDWIDTH 125.0  // kHz: 125.0, 250.0, or 500.0
```

## Building and Uploading

### Using PlatformIO CLI

1. Build the project:
   ```bash
   pio run
   ```

2. Upload to the board:
   ```bash
   pio run --target upload
   ```

3. Monitor serial output:
   ```bash
   pio device monitor
   ```

Or do all at once:
```bash
pio run --target upload && pio device monitor
```

### Using PlatformIO IDE (VS Code)

1. Open the project folder in VS Code
2. Click the PlatformIO icon in the sidebar
3. Under "Project Tasks", click:
   - "Build" to compile
   - "Upload" to flash the board
   - "Monitor" to view serial output

## Message Format

The receiver expects messages in the following format:
```
CHANNEL|SECRET|MESSAGE_CONTENT
```

Example:
```
uptime_channel|your_secret_key|Server is down!
```

Only messages with matching channel name and secret will be processed and forwarded.

## How It Works

1. **Initialization**: The device starts up, initializes the OLED display, connects to WiFi, and configures the LoRa radio
2. **Message Reception**: Continuously listens for LoRa packets on the configured frequency
3. **Verification**: When a message is received, it verifies the channel name and secret
4. **Forwarding**: Valid messages are forwarded to all enabled notification services
5. **Display**: Status and received messages are shown on the OLED display

## Troubleshooting

### WiFi Won't Connect
- Double-check SSID and password in configuration
- Ensure the board is within range of your WiFi router
- Check serial monitor for error messages

### No LoRa Messages Received
- Verify the LORA_FREQ matches your transmitter (915MHz for US, 868MHz for EU)
- Ensure both transmitter and receiver use the same channel name and secret
- Check that the LoRa antenna is properly connected
- Verify transmitter is within range

### Messages Not Forwarding
- Check WiFi connection status in serial monitor
- Verify service configuration (URLs, tokens, etc.)
- Review serial output for HTTP error codes
- Test service endpoints manually to ensure they're accessible

## Development

### Project Structure
```
ESP32-Uptime-Receiver/
├── include/
│   └── config.h          # Configuration header
├── src/
│   └── main.cpp          # Main application code
├── platformio.ini        # PlatformIO configuration
└── README.md             # This file
```

### Adding New Services

To add a new notification service:

1. Add configuration defines to `include/config.h`
2. Create a forwarding function (e.g., `forwardToNewService()`)
3. Call the function in `handleLoRaMessage()` when enabled
4. Update documentation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Built for the Heltec Wireless Stick Lite v3
- Uses the Heltec ESP32 library for LoRa and display functionality