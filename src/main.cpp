#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <RadioLib.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <Ed25519.h>
#include <RNG.h>
#include <time.h>
#include "config.h"
#include <driver/adc.h>
#include <lwip/inet_chksum.h>
#include <lwip/ip.h>
#include <lwip/ip4.h>
#include <lwip/err.h>
#include <lwip/icmp.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netdb.h>
#include <lwip/dns.h>
#include <LittleFS.h>
#include <ESPAsyncWebServer.h>
// #include <ElegantOTA.h>  // Temporarily disabled due to header conflicts
#include <cstdlib>
#include <Update.h>
#include <DNSServer.h>
#include <esp_system.h>
#include <AsyncMqttClient.h>

// --- MeshCore protocol constants ---
#define CIPHER_BLOCK_SIZE 16
#define CIPHER_MAC_SIZE 2
#define PAYLOAD_TYPE_GRP_TXT 0x05
#define PAYLOAD_TYPE_ADVERT 0x04
#define TXT_TYPE_PLAIN 0x00
#define ROUTE_TYPE_TRANSPORT_FLOOD 0x00  // flood mode + transport codes
#define ROUTE_TYPE_FLOOD 0x01            // flood mode, needs 'path' to be built up
#define ROUTE_TYPE_DIRECT 0x02           // direct route, 'path' is supplied (zero hop = direct with no path)
#define ROUTE_TYPE_TRANSPORT_DIRECT 0x03 // direct route + transport codes

// --- Uptime Monitoring Types and Struct ---
enum ServiceType {
  TYPE_HTTP_GET,
  TYPE_PING,
  TYPE_SNMP_GET,
  TYPE_PORT,
  TYPE_PUSH,
  TYPE_UPTIME,
  TYPE_UNKNOWN
};

enum CompareOp {
  OP_EQ, OP_NE, OP_GT, OP_LT, OP_GE, OP_LE
};

struct Service {
  String id;
  String name;
  ServiceType type;
  String host;
  int port;
  String path;
  String url;
  String expectedResponse;
  int checkInterval;
  int passThreshold;
  int failThreshold;
  int rearmCount;
  bool enabled;
  int consecutivePasses;
  int consecutiveFails;
  bool isUp;
  bool hasBeenUp;
  bool isPending;
  unsigned long lastCheck;
  String lastError;
  // SNMP fields
  String snmpOid;
  String snmpCommunity;
  CompareOp snmpCompareOp;
  String snmpExpectedValue;
  // Uptime-specific fields
  int uptimeThreshold;
  CompareOp uptimeCompareOp;
  // Push-specific fields
  String pushToken;
  unsigned long lastPush;
  // Pause fields
  unsigned long pauseUntil;
};

// --- Service Array and Count ---
#define MAX_SERVICES 16
Service services[MAX_SERVICES];
int serviceCount = 0;

// ============================================
// Service Status History (LittleFS)
// Stores minimal event records: <unix_epoch_seconds>,<U|D>\n
// Only logs UP<->DOWN transitions (not Pending).
// Total history budget: 542336 bytes. Enforced via per-service cap.
// ============================================
static const char* HISTORY_DIR = "/history";
static const size_t HISTORY_TOTAL_BUDGET_BYTES = 542336;
static const size_t HISTORY_PER_SERVICE_BUDGET_BYTES = (HISTORY_TOTAL_BUDGET_BYTES / MAX_SERVICES);

static String sanitizeForPath(const String &in) {
  String out;
  out.reserve(in.length());
  for (size_t i = 0; i < in.length(); i++) {
    char c = in[i];
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    if (ok) out += c;
    else out += '_';
  }
  if (out.length() == 0) out = "svc";
  if (out.length() > 48) out = out.substring(0, 48);
  return out;
}

static String historyFileForServiceId(const String &serviceId) {
  return String(HISTORY_DIR) + "/" + sanitizeForPath(serviceId) + ".log";
}

static void ensureHistoryDir() {
  if (!LittleFS.exists(HISTORY_DIR)) {
    LittleFS.mkdir(HISTORY_DIR);
  }
}

static void trimFileToSize(const String &path, size_t maxBytes) {
  if (!LittleFS.exists(path)) return;
  File f = LittleFS.open(path, "r");
  if (!f) return;
  size_t sz = f.size();
  if (sz <= maxBytes) {
    f.close();
    return;
  }

  size_t start = (sz > maxBytes) ? (sz - maxBytes) : 0;
  if (start > 0) {
    f.seek(start);
    // Align to next newline to avoid partial record
    while (f.available()) {
      int ch = f.read();
      if (ch == '\n') break;
    }
  }

  String remainder = f.readString();
  f.close();

  String tmpPath = path + ".tmp";
  File out = LittleFS.open(tmpPath, "w");
  if (!out) return;
  out.print(remainder);
  out.close();

  LittleFS.remove(path);
  LittleFS.rename(tmpPath, path);
}

static void appendServiceStatusEvent(const Service &service, bool isUp) {
  ensureHistoryDir();

  time_t now = time(nullptr);
  if (now < 1000000000) {
    Serial.println("[History] Time not synced; skipping history log");
    return;
  }

  String path = historyFileForServiceId(service.id);
  File f = LittleFS.open(path, "a");
  if (!f) {
    Serial.println("[History] Failed to open history file for append");
    return;
  }

  char line[32];
  snprintf(line, sizeof(line), "%lu,%c\n", (unsigned long)now, isUp ? 'U' : 'D');
  f.print(line);
  f.close();

  trimFileToSize(path, HISTORY_PER_SERVICE_BUDGET_BYTES);
}

static void deleteServiceHistory(const String &serviceId) {
  String path = historyFileForServiceId(serviceId);
  if (LittleFS.exists(path)) {
    LittleFS.remove(path);
  }
}

// --- Global Variables ---
SX1262 radio = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY);
int lastRssi = 0;
float lastSnr = 0;
bool wifiConnected = false;
unsigned long lastMessageTime = 0;
int messageCount = 0;
unsigned long lastPingTime = 0;

// Ed25519 key pair for node identity
uint8_t ed25519_private_key[32];
uint8_t ed25519_public_key[32];
bool ed25519_keys_loaded = false;
static const char* ED25519_KEY_FILE = "/ed25519_keys.bin";

// Scheduled reboot (used when settings require restart)
bool pendingRestart = false;
unsigned long restartAtMs = 0;

// ============================================
// Runtime Settings (defaults from .env at build time; overrides from /settings)
// ============================================
struct Settings {
  // WiFi
  String wifiSsid;
  String wifiPassword;

  // IP Configuration
  String ipMode;          // "DHCP" or "STATIC"
  String staticIp;
  String staticGateway;
  String staticSubnet;

  // DNS Configuration
  String dnsMode;         // "DHCP" or "STATIC"
  String staticDns1;
  String staticDns2;

  // Admin
  String adminUsername;
  String adminPassword;

  // LoRa / MeshCore channel
  String channelName;
  String channelSecret;

  // LoRa radio parameters
  bool loraEnabled;
  bool loraIpAlerts;
  String loraNodeName;
  float loraFreq;
  float loraBandwidth;
  int loraSpreadingFactor;
  int loraCodingRate;

  // Ntfy
  bool ntfyEnabled;
  bool ntfyMeshRelay;
  bool ntfyIpAlerts;
  String ntfyServer;
  String ntfyTopic;
  String ntfyUsername;
  String ntfyPassword;
  String ntfyToken;

  // Discord
  bool discordEnabled;
  bool discordMeshRelay;
  bool discordIpAlerts;
  String discordWebhookUrl;

  // Webhook
  bool webhookEnabled;
  bool webhookMeshRelay;
  bool webhookIpAlerts;
  String webhookUrl;
  String webhookMethod;

  // Email (placeholder)
  bool emailEnabled;
  bool emailMeshRelay;
  bool emailIpAlerts;
  String smtpHost;
  int smtpPort;
  String emailRecipient;
  String emailSender;
  String smtpUser;
  String smtpPassword;

  // MQTT
  bool mqttEnabled;
  bool mqttMeshRelay;
  bool mqttIpAlerts;
  String mqttBroker;
  int mqttPort;
  String mqttTopic;
  int mqttQos;
  String mqttUsername;
  String mqttPassword;
};

Settings settings;

Settings defaultSettingsFromBuild() {
  Settings s;
  s.wifiSsid = String(WIFI_SSID);
  s.wifiPassword = String(WIFI_PASSWORD);

  s.ipMode = String(IP_MODE);
  s.staticIp = String(STATIC_IP);
  s.staticGateway = String(STATIC_GATEWAY);
  s.staticSubnet = String(STATIC_SUBNET);

  s.dnsMode = String(DNS_MODE);
  s.staticDns1 = String(STATIC_DNS1);
  s.staticDns2 = String(STATIC_DNS2);

  s.adminUsername = String(ADMIN_USERNAME);
  s.adminPassword = String(ADMIN_PASSWORD);

  s.channelName = String(CHANNEL_NAME);
  s.channelSecret = String(CHANNEL_SECRET);

  s.loraEnabled = (LORA_ENABLED != 0);
  s.loraIpAlerts = (LORA_IP_ALERTS != 0);
  s.loraNodeName = String(LORA_NODE_NAME);
  s.loraFreq = (float)LORA_FREQ;
  s.loraBandwidth = (float)LORA_BANDWIDTH;
  s.loraSpreadingFactor = (int)LORA_SPREADING_FACTOR;
  s.loraCodingRate = (int)LORA_CODING_RATE;

  s.ntfyEnabled = (NTFY_ENABLED != 0);
  s.ntfyMeshRelay = (NTFY_MESH_RELAY != 0);
  s.ntfyIpAlerts = (NTFY_IP_ALERTS != 0);
  s.ntfyServer = String(NTFY_SERVER);
  s.ntfyTopic = String(NTFY_TOPIC);
  s.ntfyUsername = String(NTFY_USERNAME);
  s.ntfyPassword = String(NTFY_PASSWORD);
  s.ntfyToken = String(NTFY_TOKEN);

  s.discordEnabled = (DISCORD_ENABLED != 0);
  s.discordMeshRelay = (DISCORD_MESH_RELAY != 0);
  s.discordIpAlerts = (DISCORD_IP_ALERTS != 0);
  s.discordWebhookUrl = String(DISCORD_WEBHOOK_URL);

  s.webhookEnabled = (WEBHOOK_ENABLED != 0);
  s.webhookMeshRelay = (WEBHOOK_MESH_RELAY != 0);
  s.webhookIpAlerts = (WEBHOOK_IP_ALERTS != 0);
  s.webhookUrl = String(WEBHOOK_URL);
  s.webhookMethod = String(WEBHOOK_METHOD);

  s.emailEnabled = (EMAIL_ENABLED != 0);
  s.emailMeshRelay = (EMAIL_MESH_RELAY != 0);
  s.emailIpAlerts = (EMAIL_IP_ALERTS != 0);
  s.smtpHost = String(SMTP_HOST);
  s.smtpPort = String(SMTP_PORT).toInt();
  s.emailRecipient = String(EMAIL_RECIPIENT);
  s.emailSender = String(EMAIL_SENDER);
  s.smtpUser = String(SMTP_USER);
  s.smtpPassword = String(SMTP_PASSWORD);

  s.mqttEnabled = (MQTT_ENABLED != 0);
  s.mqttMeshRelay = (MQTT_MESH_RELAY != 0);
  s.mqttIpAlerts = (MQTT_IP_ALERTS != 0);
  s.mqttBroker = String(MQTT_BROKER);
  s.mqttPort = String(MQTT_PORT).toInt();
  if (s.mqttPort <= 0) s.mqttPort = 1883;
  s.mqttTopic = String(MQTT_TOPIC);
  s.mqttQos = String(MQTT_QOS).toInt();
  if (s.mqttQos < 0) s.mqttQos = 0;
  if (s.mqttQos > 2) s.mqttQos = 2;
  s.mqttUsername = String(MQTT_USERNAME);
  s.mqttPassword = String(MQTT_PASSWORD);
  return s;
}

static const char* SETTINGS_FILE = "/settings.json";

void applySettingsDefaults() {
  settings = defaultSettingsFromBuild();
}

void loadSettingsOverrides() {
  if (!LittleFS.exists(SETTINGS_FILE)) {
    return;
  }

  File file = LittleFS.open(SETTINGS_FILE, "r");
  if (!file) {
    Serial.println("Failed to open settings.json");
    return;
  }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, file);
  file.close();
  if (err) {
    Serial.printf("Failed to parse settings.json: %s\n", err.c_str());
    return;
  }

  // Strings
  if (doc["WIFI_SSID"].is<String>()) settings.wifiSsid = doc["WIFI_SSID"].as<String>();
  if (doc["WIFI_PASSWORD"].is<String>()) settings.wifiPassword = doc["WIFI_PASSWORD"].as<String>();
  
  if (doc["IP_MODE"].is<String>()) settings.ipMode = doc["IP_MODE"].as<String>();
  if (doc["STATIC_IP"].is<String>()) settings.staticIp = doc["STATIC_IP"].as<String>();
  if (doc["STATIC_GATEWAY"].is<String>()) settings.staticGateway = doc["STATIC_GATEWAY"].as<String>();
  if (doc["STATIC_SUBNET"].is<String>()) settings.staticSubnet = doc["STATIC_SUBNET"].as<String>();
  
  if (doc["DNS_MODE"].is<String>()) settings.dnsMode = doc["DNS_MODE"].as<String>();
  if (doc["STATIC_DNS1"].is<String>()) settings.staticDns1 = doc["STATIC_DNS1"].as<String>();
  if (doc["STATIC_DNS2"].is<String>()) settings.staticDns2 = doc["STATIC_DNS2"].as<String>();
  
  if (doc["ADMIN_USERNAME"].is<String>()) settings.adminUsername = doc["ADMIN_USERNAME"].as<String>();
  if (doc["ADMIN_PASSWORD"].is<String>()) settings.adminPassword = doc["ADMIN_PASSWORD"].as<String>();
  if (doc["CHANNEL_NAME"].is<String>()) settings.channelName = doc["CHANNEL_NAME"].as<String>();
  if (doc["CHANNEL_SECRET"].is<String>()) settings.channelSecret = doc["CHANNEL_SECRET"].as<String>();

  // LoRa radio parameters
  if (doc["LORA_ENABLED"].is<bool>()) settings.loraEnabled = doc["LORA_ENABLED"].as<bool>();
  if (doc["LORA_IP_ALERTS"].is<bool>()) settings.loraIpAlerts = doc["LORA_IP_ALERTS"].as<bool>();
  if (doc["LORA_FREQ"].is<float>()) settings.loraFreq = doc["LORA_FREQ"].as<float>();
  if (doc["LORA_FREQ"].is<double>()) settings.loraFreq = (float)doc["LORA_FREQ"].as<double>();
  if (doc["LORA_FREQ"].is<String>()) settings.loraFreq = doc["LORA_FREQ"].as<String>().toFloat();

  if (doc["LORA_BANDWIDTH"].is<float>()) settings.loraBandwidth = doc["LORA_BANDWIDTH"].as<float>();
  if (doc["LORA_BANDWIDTH"].is<double>()) settings.loraBandwidth = (float)doc["LORA_BANDWIDTH"].as<double>();
  if (doc["LORA_BANDWIDTH"].is<String>()) settings.loraBandwidth = doc["LORA_BANDWIDTH"].as<String>().toFloat();

  if (doc["LORA_SPREADING_FACTOR"].is<int>()) settings.loraSpreadingFactor = doc["LORA_SPREADING_FACTOR"].as<int>();
  if (doc["LORA_SPREADING_FACTOR"].is<String>()) settings.loraSpreadingFactor = doc["LORA_SPREADING_FACTOR"].as<String>().toInt();

  if (doc["LORA_CODING_RATE"].is<int>()) settings.loraCodingRate = doc["LORA_CODING_RATE"].as<int>();
  if (doc["LORA_CODING_RATE"].is<String>()) settings.loraCodingRate = doc["LORA_CODING_RATE"].as<String>().toInt();

  if (doc["NTFY_SERVER"].is<String>()) settings.ntfyServer = doc["NTFY_SERVER"].as<String>();
  if (doc["NTFY_TOPIC"].is<String>()) settings.ntfyTopic = doc["NTFY_TOPIC"].as<String>();
  if (doc["NTFY_USERNAME"].is<String>()) settings.ntfyUsername = doc["NTFY_USERNAME"].as<String>();
  if (doc["NTFY_PASSWORD"].is<String>()) settings.ntfyPassword = doc["NTFY_PASSWORD"].as<String>();
  if (doc["NTFY_TOKEN"].is<String>()) settings.ntfyToken = doc["NTFY_TOKEN"].as<String>();

  if (doc["DISCORD_WEBHOOK_URL"].is<String>()) settings.discordWebhookUrl = doc["DISCORD_WEBHOOK_URL"].as<String>();
  if (doc["WEBHOOK_URL"].is<String>()) settings.webhookUrl = doc["WEBHOOK_URL"].as<String>();
  if (doc["WEBHOOK_METHOD"].is<String>()) settings.webhookMethod = doc["WEBHOOK_METHOD"].as<String>();

  if (doc["SMTP_HOST"].is<String>()) settings.smtpHost = doc["SMTP_HOST"].as<String>();
  if (doc["SMTP_PORT"].is<int>()) settings.smtpPort = doc["SMTP_PORT"].as<int>();
  if (doc["SMTP_PORT"].is<String>()) settings.smtpPort = doc["SMTP_PORT"].as<String>().toInt();
  if (doc["EMAIL_RECIPIENT"].is<String>()) settings.emailRecipient = doc["EMAIL_RECIPIENT"].as<String>();
  if (doc["EMAIL_SENDER"].is<String>()) settings.emailSender = doc["EMAIL_SENDER"].as<String>();
  if (doc["SMTP_USER"].is<String>()) settings.smtpUser = doc["SMTP_USER"].as<String>();
  if (doc["SMTP_PASSWORD"].is<String>()) settings.smtpPassword = doc["SMTP_PASSWORD"].as<String>();

  // MQTT strings
  if (doc["MQTT_BROKER"].is<String>()) settings.mqttBroker = doc["MQTT_BROKER"].as<String>();
  if (doc["MQTT_PORT"].is<int>()) settings.mqttPort = doc["MQTT_PORT"].as<int>();
  if (doc["MQTT_PORT"].is<String>()) settings.mqttPort = doc["MQTT_PORT"].as<String>().toInt();
  if (doc["MQTT_TOPIC"].is<String>()) settings.mqttTopic = doc["MQTT_TOPIC"].as<String>();
  if (doc["MQTT_QOS"].is<int>()) settings.mqttQos = doc["MQTT_QOS"].as<int>();
  if (doc["MQTT_QOS"].is<String>()) settings.mqttQos = doc["MQTT_QOS"].as<String>().toInt();
  if (doc["MQTT_USERNAME"].is<String>()) settings.mqttUsername = doc["MQTT_USERNAME"].as<String>();
  if (doc["MQTT_PASSWORD"].is<String>()) settings.mqttPassword = doc["MQTT_PASSWORD"].as<String>();

  // Booleans
  if (doc["NTFY_ENABLED"].is<bool>()) settings.ntfyEnabled = doc["NTFY_ENABLED"].as<bool>();
  if (doc["NTFY_MESH_RELAY"].is<bool>()) settings.ntfyMeshRelay = doc["NTFY_MESH_RELAY"].as<bool>();
  if (doc["NTFY_IP_ALERTS"].is<bool>()) settings.ntfyIpAlerts = doc["NTFY_IP_ALERTS"].as<bool>();
  if (doc["DISCORD_ENABLED"].is<bool>()) settings.discordEnabled = doc["DISCORD_ENABLED"].as<bool>();
  if (doc["DISCORD_MESH_RELAY"].is<bool>()) settings.discordMeshRelay = doc["DISCORD_MESH_RELAY"].as<bool>();
  if (doc["DISCORD_IP_ALERTS"].is<bool>()) settings.discordIpAlerts = doc["DISCORD_IP_ALERTS"].as<bool>();
  if (doc["WEBHOOK_ENABLED"].is<bool>()) settings.webhookEnabled = doc["WEBHOOK_ENABLED"].as<bool>();
  if (doc["WEBHOOK_MESH_RELAY"].is<bool>()) settings.webhookMeshRelay = doc["WEBHOOK_MESH_RELAY"].as<bool>();
  if (doc["WEBHOOK_IP_ALERTS"].is<bool>()) settings.webhookIpAlerts = doc["WEBHOOK_IP_ALERTS"].as<bool>();
  if (doc["EMAIL_ENABLED"].is<bool>()) settings.emailEnabled = doc["EMAIL_ENABLED"].as<bool>();
  if (doc["EMAIL_MESH_RELAY"].is<bool>()) settings.emailMeshRelay = doc["EMAIL_MESH_RELAY"].as<bool>();
  if (doc["EMAIL_IP_ALERTS"].is<bool>()) settings.emailIpAlerts = doc["EMAIL_IP_ALERTS"].as<bool>();

  if (doc["MQTT_ENABLED"].is<bool>()) settings.mqttEnabled = doc["MQTT_ENABLED"].as<bool>();
  if (doc["MQTT_MESH_RELAY"].is<bool>()) settings.mqttMeshRelay = doc["MQTT_MESH_RELAY"].as<bool>();
  if (doc["MQTT_IP_ALERTS"].is<bool>()) settings.mqttIpAlerts = doc["MQTT_IP_ALERTS"].as<bool>();

  // Normalize
  if (settings.mqttPort <= 0) settings.mqttPort = 1883;
  if (settings.mqttQos < 0) settings.mqttQos = 0;
  if (settings.mqttQos > 2) settings.mqttQos = 2;
}

bool saveSettingsOverrides() {
  File file = LittleFS.open(SETTINGS_FILE, "w");
  if (!file) {
    Serial.println("Failed to open settings.json for writing");
    return false;
  }

  JsonDocument doc;
  doc["WIFI_SSID"] = settings.wifiSsid;
  doc["WIFI_PASSWORD"] = settings.wifiPassword;
  
  doc["IP_MODE"] = settings.ipMode;
  doc["STATIC_IP"] = settings.staticIp;
  doc["STATIC_GATEWAY"] = settings.staticGateway;
  doc["STATIC_SUBNET"] = settings.staticSubnet;
  
  doc["DNS_MODE"] = settings.dnsMode;
  doc["STATIC_DNS1"] = settings.staticDns1;
  doc["STATIC_DNS2"] = settings.staticDns2;
  
  doc["ADMIN_USERNAME"] = settings.adminUsername;
  doc["ADMIN_PASSWORD"] = settings.adminPassword;
  doc["CHANNEL_NAME"] = settings.channelName;
  doc["CHANNEL_SECRET"] = settings.channelSecret;

  doc["LORA_ENABLED"] = settings.loraEnabled;
  doc["LORA_IP_ALERTS"] = settings.loraIpAlerts;
  doc["LORA_FREQ"] = settings.loraFreq;
  doc["LORA_BANDWIDTH"] = settings.loraBandwidth;
  doc["LORA_SPREADING_FACTOR"] = settings.loraSpreadingFactor;
  doc["LORA_CODING_RATE"] = settings.loraCodingRate;

  doc["NTFY_ENABLED"] = settings.ntfyEnabled;
  doc["NTFY_MESH_RELAY"] = settings.ntfyMeshRelay;
  doc["NTFY_IP_ALERTS"] = settings.ntfyIpAlerts;
  doc["NTFY_SERVER"] = settings.ntfyServer;
  doc["NTFY_TOPIC"] = settings.ntfyTopic;
  doc["NTFY_USERNAME"] = settings.ntfyUsername;
  doc["NTFY_PASSWORD"] = settings.ntfyPassword;
  doc["NTFY_TOKEN"] = settings.ntfyToken;

  doc["DISCORD_ENABLED"] = settings.discordEnabled;
  doc["DISCORD_MESH_RELAY"] = settings.discordMeshRelay;
  doc["DISCORD_IP_ALERTS"] = settings.discordIpAlerts;
  doc["DISCORD_WEBHOOK_URL"] = settings.discordWebhookUrl;

  doc["WEBHOOK_ENABLED"] = settings.webhookEnabled;
  doc["WEBHOOK_MESH_RELAY"] = settings.webhookMeshRelay;
  doc["WEBHOOK_IP_ALERTS"] = settings.webhookIpAlerts;
  doc["WEBHOOK_URL"] = settings.webhookUrl;
  doc["WEBHOOK_METHOD"] = settings.webhookMethod;

  doc["EMAIL_ENABLED"] = settings.emailEnabled;
  doc["EMAIL_MESH_RELAY"] = settings.emailMeshRelay;
  doc["EMAIL_IP_ALERTS"] = settings.emailIpAlerts;
  doc["SMTP_HOST"] = settings.smtpHost;
  doc["SMTP_PORT"] = settings.smtpPort;
  doc["EMAIL_RECIPIENT"] = settings.emailRecipient;
  doc["EMAIL_SENDER"] = settings.emailSender;
  doc["SMTP_USER"] = settings.smtpUser;
  doc["SMTP_PASSWORD"] = settings.smtpPassword;

  doc["MQTT_ENABLED"] = settings.mqttEnabled;
  doc["MQTT_MESH_RELAY"] = settings.mqttMeshRelay;
  doc["MQTT_IP_ALERTS"] = settings.mqttIpAlerts;
  doc["MQTT_BROKER"] = settings.mqttBroker;
  doc["MQTT_PORT"] = settings.mqttPort;
  doc["MQTT_TOPIC"] = settings.mqttTopic;
  doc["MQTT_QOS"] = settings.mqttQos;
  doc["MQTT_USERNAME"] = settings.mqttUsername;
  doc["MQTT_PASSWORD"] = settings.mqttPassword;

  if (serializeJson(doc, file) == 0) {
    file.close();
    Serial.println("Failed to write settings.json");
    return false;
  }
  file.close();
  return true;
}

// ============================================
// MQTT
// ============================================
extern bool captivePortalActive;
static String macNoColons();

static AsyncMqttClient mqttClient;
static bool mqttConnecting = false;
static unsigned long mqttLastConnectAttemptMs = 0;

static const size_t MQTT_DEDUP_SIZE = 32;
static String mqttRecentMessageIds[MQTT_DEDUP_SIZE];
static uint8_t mqttRecentMessageIdsHead = 0;

static bool mqttRecentlyPublished(const String &messageId) {
  if (messageId.length() == 0) return false;
  for (size_t i = 0; i < MQTT_DEDUP_SIZE; i++) {
    if (mqttRecentMessageIds[i] == messageId) return true;
  }
  return false;
}

static void mqttRememberPublished(const String &messageId) {
  if (messageId.length() == 0) return;
  mqttRecentMessageIds[mqttRecentMessageIdsHead] = messageId;
  mqttRecentMessageIdsHead = (uint8_t)((mqttRecentMessageIdsHead + 1) % MQTT_DEDUP_SIZE);
}

static String mqttClientId() {
  return String("ESP32NM-") + macNoColons();
}

static void applyMqttConfigFromSettings() {
  mqttClient.setServer(settings.mqttBroker.c_str(), (uint16_t)settings.mqttPort);
  mqttClient.setClientId(mqttClientId().c_str());
  if (settings.mqttUsername.length() > 0) {
    mqttClient.setCredentials(settings.mqttUsername.c_str(), settings.mqttPassword.c_str());
  } else {
    mqttClient.setCredentials(nullptr, nullptr);
  }
  mqttClient.setKeepAlive(15);
}

static bool ensureMqttConnected() {
  if (!settings.mqttEnabled) return false;
  if (captivePortalActive) return false;
  if (WiFi.status() != WL_CONNECTED) return false;
  if (settings.mqttBroker.length() == 0) return false;
  if (settings.mqttPort <= 0) return false;

  if (mqttClient.connected()) return true;
  if (mqttConnecting) return false;

  unsigned long now = millis();
  if (now - mqttLastConnectAttemptMs < 10000) return false;
  mqttLastConnectAttemptMs = now;

  applyMqttConfigFromSettings();

  Serial.printf("[MQTT] Connecting to %s:%d as %s\n", settings.mqttBroker.c_str(), settings.mqttPort, mqttClientId().c_str());
  mqttConnecting = true;
  mqttClient.connect();
  return false;
}

static void mqttOnConnect(bool sessionPresent) {
  (void)sessionPresent;
  mqttConnecting = false;
  Serial.println("[MQTT] Connected");
}

static void mqttOnDisconnect(AsyncMqttClientDisconnectReason reason) {
  mqttConnecting = false;
  Serial.printf("[MQTT] Disconnected (reason=%d)\n", (int)reason);
}

static void initMqttClientOnce() {
  static bool inited = false;
  if (inited) return;
  inited = true;
  mqttClient.onConnect(mqttOnConnect);
  mqttClient.onDisconnect(mqttOnDisconnect);
}

static String sha256HexShort(const String &input, size_t hexChars) {
  unsigned char out[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, (const unsigned char*)input.c_str(), input.length());
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);

  static const char* hex = "0123456789abcdef";
  String s;
  s.reserve(64);
  for (size_t i = 0; i < 32; i++) {
    s += hex[(out[i] >> 4) & 0x0F];
    s += hex[out[i] & 0x0F];
  }
  if (hexChars > 64) hexChars = 64;
  return s.substring(0, (int)hexChars);
}

static String messageIdForBody(const String &body) {
  // Stable ID derived from message content; avoids duplicates on repeated sends.
  return sha256HexShort(body, 16);
}

static String addMessageIdPrefix(const String &body, const String &messageId) {
  if (messageId.length() == 0) return body;
  return String("MessageID: ") + messageId + "\n" + body;
}

void forwardToMqtt(String message);

void forwardToMqtt(String message) {
  initMqttClientOnce();

  String messageId = messageIdForBody(message);
  if (mqttRecentlyPublished(messageId)) {
    Serial.println("[MQTT] Duplicate MessageID; skipping publish");
    return;
  }

  if (!settings.mqttEnabled) {
    Serial.println("MQTT disabled, skipping");
    return;
  }
  if (settings.mqttTopic.length() == 0) {
    Serial.println("MQTT topic empty, skipping");
    return;
  }
  if (settings.mqttQos < 0) settings.mqttQos = 0;
  if (settings.mqttQos > 2) settings.mqttQos = 2;
  if (!ensureMqttConnected()) {
    Serial.println("MQTT not connected, skipping publish");
    return;
  }

  String payload = addMessageIdPrefix(message, messageId);
  uint16_t pid = mqttClient.publish(settings.mqttTopic.c_str(), (uint8_t)settings.mqttQos, false, payload.c_str(), payload.length());
  if (pid > 0 || settings.mqttQos == 0) {
    mqttRememberPublished(messageId);
    Serial.printf("[MQTT] Published to %s (qos=%d)\n", settings.mqttTopic.c_str(), settings.mqttQos);
  } else {
    Serial.println("[MQTT] Publish failed");
  }
}

// Battery monitoring (Heltec Wireless Stick Lite V3 VBAT on GPIO1)
struct BatteryStats {
  float voltage;
  int percent;
  bool valid;
};

BatteryStats lastBatteryStats = {0.0f, 0, false};
unsigned long lastBatterySampleMs = 0;
const unsigned long BATTERY_REFRESH_MS = 10000;  // Re-sample every 10s to limit ADC noise

void initBatteryMonitor() {
#ifdef BATTERY_READ_CONTROL_PIN
  pinMode(BATTERY_READ_CONTROL_PIN, OUTPUT);
  digitalWrite(BATTERY_READ_CONTROL_PIN, LOW);
  delay(10); // Wait for voltage to stabilize
#endif

#ifdef BATTERY_ADC_PIN
  pinMode(BATTERY_ADC_PIN, INPUT);
  analogReadResolution(12);
  analogSetPinAttenuation(BATTERY_ADC_PIN, ADC_11db);
  adcAttachPin(BATTERY_ADC_PIN);
#endif
}

BatteryStats sampleBatteryStats() {
#ifdef BATTERY_READ_CONTROL_PIN
  pinMode(BATTERY_READ_CONTROL_PIN, OUTPUT);
  digitalWrite(BATTERY_READ_CONTROL_PIN, LOW);
  delay(20); // Allow voltage to stabilize
#endif

#ifdef BATTERY_ADC_PIN
  uint32_t mvSum = 0;
  for (int i = 0; i < BATTERY_SAMPLES; i++) {
    mvSum += analogReadMilliVolts(BATTERY_ADC_PIN);
    delay(2);  // Short delay to stabilize successive ADC readings
  }

#ifdef BATTERY_READ_CONTROL_PIN
  // digitalWrite(BATTERY_READ_CONTROL_PIN, HIGH); // Disable to save power?
#endif

  float avgMv = mvSum / (float)BATTERY_SAMPLES;
  float voltage = (avgMv / 1000.0f) * BATTERY_DIVIDER_RATIO;
  
  // Debug battery reading
  Serial.printf("Battery: Raw=%0.1fmV, Voltage=%0.3fV (Pin 37=LOW)\n", avgMv, voltage);

  float bounded = constrain(voltage, BATTERY_EMPTY_V, BATTERY_FULL_V);
  int percent = (int)((bounded - BATTERY_EMPTY_V) / (BATTERY_FULL_V - BATTERY_EMPTY_V) * 100.0f + 0.5f);
  percent = constrain(percent, 0, 100);

  return {voltage, percent, true};
#else
  return {0.0f, 0, false};
#endif
}

BatteryStats getBatteryStats() {
  unsigned long now = millis();
  if (!lastBatteryStats.valid || now - lastBatterySampleMs > BATTERY_REFRESH_MS) {
    lastBatteryStats = sampleBatteryStats();
    lastBatterySampleMs = now;
  }
  return lastBatteryStats;
}

// Simple session tracking for UI/API authentication
String sessionToken = "";
unsigned long sessionIssuedAt = 0;

String generatePushToken() {
  uint32_t seed = esp_random();
  randomSeed(seed ^ micros());
  char token[17];
  const char* hex = "0123456789abcdef";
  for (int i = 0; i < 16; i++) {
    token[i] = hex[random(0, 16)];
  }
  token[16] = '\0';
  return String(token);
}

String getPushUrl(const Service& service) {
  if (service.pushToken.length() == 0) return "";
  return String("http://") + WiFi.localIP().toString() + "/push/" + service.pushToken;
}

// --- Web Server ---
AsyncWebServer server(80);

// --- Captive portal ---
DNSServer dnsServer;
bool captivePortalActive = false;
String captiveApSsid;
IPAddress captiveApIp;
IPAddress captiveApNetmask(255, 255, 255, 0);

// One-time notification after captive WiFi provisioning
static const char* WIFI_PROVISION_FLAG_FILE = "/wifi_provisioned.flag";
static bool pendingWifiProvisionNotify = false;
static String pendingWifiProvisionNotifyMessage;

// Notify on IP changes (persist last known IP across reboots)
static const char* LAST_IP_FILE = "/last_ip.txt";
static String lastKnownStaIp = "";
static bool lastKnownStaIpLoaded = false;

static String macWithColons();
void forwardToNtfy(String message);
void forwardToEmail(String message);
void forwardToDiscord(String message);
void forwardToWebhook(String message);
void forwardToMqtt(String message);
void sendLoRaNotification(const String& serviceName, bool isUp, const String& message);

static void fanOutInternetNotificationsWithId(const String &message) {
  String messageId = messageIdForBody(message);
  String bodyWithId = addMessageIdPrefix(message, messageId);

  if (settings.ntfyEnabled) forwardToNtfy(bodyWithId);
  if (settings.discordEnabled) forwardToDiscord(bodyWithId);
  if (settings.webhookEnabled) forwardToWebhook(bodyWithId);
  if (settings.emailEnabled) forwardToEmail(bodyWithId);
  if (settings.mqttEnabled) forwardToMqtt(message);  // forwardToMqtt adds its own MessageID prefix and de-dups
}

static bool loraReady = false;
static bool pendingLoRaNotify = false;
static String pendingLoRaNotifyMessage;

static void loadLastKnownStaIp() {
  if (!LittleFS.exists(LAST_IP_FILE)) {
    lastKnownStaIp = "";
    lastKnownStaIpLoaded = true;
    return;
  }

  File f = LittleFS.open(LAST_IP_FILE, "r");
  if (!f) {
    Serial.println("[WiFi] Failed to open last IP file");
    lastKnownStaIp = "";
    lastKnownStaIpLoaded = true;
    return;
  }

  lastKnownStaIp = f.readStringUntil('\n');
  lastKnownStaIp.trim();
  f.close();
  lastKnownStaIpLoaded = true;
}

static void saveLastKnownStaIp(const String &ip) {
  File f = LittleFS.open(LAST_IP_FILE, "w");
  if (!f) {
    Serial.println("[WiFi] Failed to write last IP file");
    return;
  }
  f.println(ip);
  f.close();
}

static void notifyIpChangeIfNeeded(const String &newIp, const String &reason) {
  if (newIp.length() == 0 || newIp == "0.0.0.0") return;

  // If this is our first ever observed IP (no persisted baseline), notify once as "assigned".
  if (!lastKnownStaIpLoaded) {
    lastKnownStaIpLoaded = true;
    lastKnownStaIp = "";
  }

  if (newIp == lastKnownStaIp) return;

  String oldIp = lastKnownStaIp;
  lastKnownStaIp = newIp;
  saveLastKnownStaIp(newIp);

  String ssid = WiFi.SSID();
  ssid.trim();

  String msg;
  if (oldIp.length() == 0) {
    msg = "IP address assigned\n";
    if (ssid.length() > 0) msg += "SSID: " + ssid + "\n";
    msg += "MAC: " + macWithColons() + "\n";
    msg += "IP: " + newIp;
  } else {
    msg = "IP address changed\n";
    if (ssid.length() > 0) msg += "SSID: " + ssid + "\n";
    msg += "MAC: " + macWithColons() + "\n";
    msg += "Old IP: " + oldIp + "\n";
    msg += "New IP: " + newIp;
  }
  if (reason.length() > 0) msg += "\nReason: " + reason;

  Serial.println("[WiFi] IP changed; sending notifications");
  String messageId = messageIdForBody(msg);
  String bodyWithId = addMessageIdPrefix(msg, messageId);
  if (settings.ntfyEnabled && settings.ntfyIpAlerts) forwardToNtfy(bodyWithId);
  if (settings.discordEnabled && settings.discordIpAlerts) forwardToDiscord(bodyWithId);
  if (settings.webhookEnabled && settings.webhookIpAlerts) forwardToWebhook(bodyWithId);
  if (settings.emailEnabled && settings.emailIpAlerts) forwardToEmail(bodyWithId);
  if (settings.mqttEnabled && settings.mqttIpAlerts) forwardToMqtt(msg);

  if (settings.loraEnabled && settings.loraIpAlerts) {
    if (loraReady) {
      sendLoRaNotification("WiFi", true, msg);
    } else {
      pendingLoRaNotify = true;
      pendingLoRaNotifyMessage = msg;
    }
  }
}

static bool parseIp4(const String &ipStr, IPAddress &out) {
  int parts[4] = {-1, -1, -1, -1};
  int part = 0;
  String token = "";
  for (size_t i = 0; i < ipStr.length(); i++) {
    char c = ipStr[i];
    if (c == '.') {
      if (part > 3) return false;
      parts[part++] = token.toInt();
      token = "";
    } else {
      token += c;
    }
  }
  if (part != 3) return false;
  parts[part] = token.toInt();
  for (int i = 0; i < 4; i++) {
    if (parts[i] < 0 || parts[i] > 255) return false;
  }
  out = IPAddress(parts[0], parts[1], parts[2], parts[3]);
  return true;
}

static String macNoColons() {
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  char buf[13];
  snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

static String macWithColons() {
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

static void writeWifiProvisionFlag(const String &ssid) {
  File f = LittleFS.open(WIFI_PROVISION_FLAG_FILE, "w");
  if (!f) {
    Serial.println("[CaptivePortal] Failed to write wifi provision flag");
    return;
  }
  f.println(ssid);
  f.close();
}

static bool consumeWifiProvisionFlag(String &outSsid) {
  if (!LittleFS.exists(WIFI_PROVISION_FLAG_FILE)) return false;
  File f = LittleFS.open(WIFI_PROVISION_FLAG_FILE, "r");
  if (!f) {
    Serial.println("[WiFi] Failed to read wifi provision flag");
    LittleFS.remove(WIFI_PROVISION_FLAG_FILE);
    return true;
  }
  outSsid = f.readStringUntil('\n');
  outSsid.trim();
  f.close();
  LittleFS.remove(WIFI_PROVISION_FLAG_FILE);
  return true;
}

static String captivePortalHtml() {
  String page = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  page += "<title>WiFi Setup</title><style>";
  page += "*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f7fafc;margin:0;padding:24px;color:#2d3748}";
  page += ".card{max-width:520px;margin:0 auto;background:#fff;border-radius:14px;padding:22px;box-shadow:0 8px 24px rgba(0,0,0,0.08)}";
  page += "h1{margin:0 0 8px;font-size:22px}p{margin:0 0 16px;color:#4a5568;font-size:13px;line-height:1.4}";
  page += "label{display:block;font-weight:700;margin:10px 0 6px;font-size:13px}";
  page += "input{width:100%;padding:10px 12px;border:2px solid #e2e8f0;border-radius:10px;font-size:14px}input:focus{outline:none;border-color:#667eea}";
  page += "button{margin-top:14px;width:100%;padding:12px 14px;border:none;border-radius:10px;background:#667eea;color:#fff;font-weight:800;cursor:pointer}";
  page += ".muted{opacity:0.85}code{background:#edf2f7;padding:2px 6px;border-radius:6px}";
  page += "</style></head><body><div class='card'>";
  page += "<h1>WiFi Setup</h1>";
  page += "<p class='muted'>This device couldn't connect to the configured WiFi. Enter WiFi credentials below and the device will reboot.</p>";
  page += "<p class='muted'>Hotspot: <code>" + captiveApSsid + "</code> · Portal IP: <code>" + captiveApIp.toString() + "</code></p>";
  page += "<form method='post' action='/captive/save'>";
  page += "<label for='ssid'>WiFi SSID</label>";
  page += "<input id='ssid' name='ssid' value='" + settings.wifiSsid + "' required>";
  page += "<label for='password'>WiFi Password</label>";
  page += "<input id='password' name='password' type='password' value='' placeholder='(leave blank for open networks)'>";
  page += "<button type='submit'>Save & Reboot</button>";
  page += "</form>";
  page += "</div></body></html>";
  return page;
}

static void startCaptivePortal() {
  if (captivePortalActive) return;

  IPAddress ip;
  if (!parseIp4(String(HOTSPOT_IP), ip)) {
    ip = IPAddress(192, 168, 4, 1);
  }
  captiveApIp = ip;
  captiveApSsid = String("ESP32NM-") + macNoColons();

  WiFi.disconnect(true);
  delay(50);
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(captiveApIp, captiveApIp, captiveApNetmask);

  String apPass = String(HOTSPOT_PASSWORD);
  bool ok;
  if (apPass.length() >= 8) {
    ok = WiFi.softAP(captiveApSsid.c_str(), apPass.c_str());
  } else {
    Serial.println("[CaptivePortal] HOTSPOT_PASSWORD too short (<8). Starting open AP.");
    ok = WiFi.softAP(captiveApSsid.c_str());
  }

  if (!ok) {
    Serial.println("[CaptivePortal] Failed to start SoftAP");
    return;
  }

  dnsServer.start(53, "*", captiveApIp);
  captivePortalActive = true;
  Serial.printf("[CaptivePortal] Started SSID=%s IP=%s\n", captiveApSsid.c_str(), captiveApIp.toString().c_str());
}

// --- Function Declarations ---
void initDemoServices();
bool checkHttpGet(Service& service);
bool checkPing(Service& service);
bool checkPort(Service& service);
bool checkSnmpGet(Service& service);
bool checkPush(Service& service);
bool checkUptime(Service& service);
void updateServiceStatus(Service& service, bool checkResult);
void sendLoRaNotification(const String& serviceName, bool isUp, const String& message);
bool isAuthenticated(AsyncWebServerRequest *request, bool sendUnauthorized = true);
String generateSessionToken();

// --- Service Persistence ---
void saveServices() {
  File file = LittleFS.open("/services.json", "w");
  if (!file) {
    Serial.println("Failed to open services.json for writing");
    return;
  }
  
  JsonDocument doc;
  JsonArray array = doc["services"].to<JsonArray>();
  
  for (int i = 0; i < serviceCount; i++) {
    JsonObject svc = array.add<JsonObject>();
    svc["id"] = services[i].id;
    svc["name"] = services[i].name;
    svc["type"] = (int)services[i].type;
    svc["host"] = services[i].host;
    svc["port"] = services[i].port;
    svc["path"] = services[i].path;
    svc["url"] = services[i].url;
    svc["expectedResponse"] = services[i].expectedResponse;
    svc["checkInterval"] = services[i].checkInterval;
    svc["passThreshold"] = services[i].passThreshold;
    svc["failThreshold"] = services[i].failThreshold;
    svc["rearmCount"] = services[i].rearmCount;
    svc["enabled"] = services[i].enabled;
    svc["snmpOid"] = services[i].snmpOid;
    svc["snmpCommunity"] = services[i].snmpCommunity;
    svc["snmpCompareOp"] = (int)services[i].snmpCompareOp;
    svc["snmpExpectedValue"] = services[i].snmpExpectedValue;
    svc["uptimeThreshold"] = services[i].uptimeThreshold;
    svc["uptimeCompareOp"] = (int)services[i].uptimeCompareOp;
    svc["pushToken"] = services[i].pushToken;
  }
  
  serializeJson(doc, file);
  file.close();
  Serial.println("Services saved to LittleFS");
}

void loadServices() {
  File file = LittleFS.open("/services.json", "r");
  if (!file) {
    Serial.println("No services.json found, using demo services");
    initDemoServices();
    saveServices();  // Save demo services for next boot
    return;
  }
  
  JsonDocument doc;
  DeserializationError error = deserializeJson(doc, file);
  file.close();
  
  if (error) {
    Serial.print("Failed to parse services.json: ");
    Serial.println(error.c_str());
    initDemoServices();
    saveServices();
    return;
  }
  
  if (!doc["services"].is<JsonArray>()) {
    Serial.println("Invalid services.json format");
    initDemoServices();
    saveServices();
    return;
  }
  
  JsonArray array = doc["services"].as<JsonArray>();
  serviceCount = 0;
  
  for (JsonObject svc : array) {
    if (serviceCount >= MAX_SERVICES) break;
    
    services[serviceCount].id = svc["id"].as<String>();
    services[serviceCount].name = svc["name"].as<String>();
    services[serviceCount].type = (ServiceType)svc["type"].as<int>();
    services[serviceCount].host = svc["host"].as<String>();
    services[serviceCount].port = svc["port"].as<int>();
    services[serviceCount].path = svc["path"].as<String>();
    services[serviceCount].url = svc["url"].as<String>();
    services[serviceCount].expectedResponse = svc["expectedResponse"].as<String>();
    services[serviceCount].checkInterval = svc["checkInterval"].as<int>();
    services[serviceCount].passThreshold = svc["passThreshold"].as<int>();
    services[serviceCount].failThreshold = svc["failThreshold"].as<int>();
    services[serviceCount].rearmCount = svc["rearmCount"].as<int>();
    services[serviceCount].enabled = svc["enabled"].as<bool>();
    services[serviceCount].snmpOid = svc["snmpOid"].as<String>();
    services[serviceCount].snmpCommunity = svc["snmpCommunity"].as<String>();
    services[serviceCount].snmpCompareOp = (CompareOp)svc["snmpCompareOp"].as<int>();
    services[serviceCount].snmpExpectedValue = svc["snmpExpectedValue"].as<String>();
    services[serviceCount].uptimeThreshold = svc["uptimeThreshold"].as<int>();
    services[serviceCount].uptimeCompareOp = (CompareOp)svc["uptimeCompareOp"].as<int>();
    services[serviceCount].pushToken = svc["pushToken"].as<String>();

    if (services[serviceCount].type == TYPE_PUSH && services[serviceCount].pushToken.length() == 0) {
      services[serviceCount].pushToken = generatePushToken();
    }
    
    // Reset runtime fields
    services[serviceCount].consecutivePasses = 0;
    services[serviceCount].consecutiveFails = 0;
    services[serviceCount].isUp = false;
    services[serviceCount].hasBeenUp = false;
    services[serviceCount].isPending = true;
    services[serviceCount].lastCheck = 0;
    services[serviceCount].lastError = "";
    services[serviceCount].lastPush = 0;
    services[serviceCount].pauseUntil = 0;
    
    serviceCount++;
  }
  
  Serial.printf("Loaded %d services from LittleFS\n", serviceCount);
}

// --- Service Initialization ---
void initDemoServices() {
  serviceCount = 0;
  // Example HTTP GET service
  Service httpSvc;
  httpSvc.id = "svc1";
  httpSvc.name = "Example HTTP";
  httpSvc.type = TYPE_HTTP_GET;
  httpSvc.url = "http://example.com";
  httpSvc.expectedResponse = "Example Domain";
  httpSvc.checkInterval = 10; // seconds
  httpSvc.passThreshold = 1;
  httpSvc.failThreshold = 2;
  httpSvc.enabled = true;
  httpSvc.consecutivePasses = 0;
  httpSvc.consecutiveFails = 0;
  httpSvc.isUp = false;
  httpSvc.hasBeenUp = false;
  httpSvc.isPending = true;
  httpSvc.lastCheck = 0;
  services[serviceCount++] = httpSvc;

  // Example Ping service
  Service pingSvc;
  pingSvc.id = "svc2";
  pingSvc.name = "Ping Google";
  pingSvc.type = TYPE_PING;
  pingSvc.host = "8.8.8.8";
  pingSvc.checkInterval = 15; // seconds
  pingSvc.passThreshold = 1;
  pingSvc.failThreshold = 2;
  pingSvc.enabled = true;
  pingSvc.consecutivePasses = 0;
  pingSvc.consecutiveFails = 0;
  pingSvc.isUp = false;
  pingSvc.hasBeenUp = false;
  pingSvc.isPending = true;
  pingSvc.lastCheck = 0;
  services[serviceCount++] = pingSvc;

  // Example SNMP service (stub)
  Service snmpSvc;
  snmpSvc.id = "svc3";
  snmpSvc.name = "SNMP Device";
  snmpSvc.type = TYPE_SNMP_GET;
  snmpSvc.host = "192.168.1.100";
  snmpSvc.snmpOid = "1.3.6.1.2.1.1.1.0";
  snmpSvc.snmpCommunity = "public";
  snmpSvc.snmpCompareOp = OP_EQ;
  snmpSvc.snmpExpectedValue = "Linux";
  snmpSvc.checkInterval = 20; // seconds
  snmpSvc.passThreshold = 1;
  snmpSvc.failThreshold = 2;
  snmpSvc.enabled = true;
  snmpSvc.consecutivePasses = 0;
  snmpSvc.consecutiveFails = 0;
  snmpSvc.isUp = false;
  snmpSvc.hasBeenUp = false;
  snmpSvc.isPending = true;
  snmpSvc.lastCheck = 0;
  services[serviceCount++] = snmpSvc;
}

// --- Periodic Service Checking ---
unsigned long lastServiceCheck = 0;
void checkAllServices() {
  unsigned long now = millis();
  for (int i = 0; i < serviceCount; i++) {
    Service& svc = services[i];
    if (!svc.enabled) continue;
    if (svc.lastCheck == 0 || now - svc.lastCheck >= (unsigned long)svc.checkInterval * 1000) {
      bool result = false;
      switch (svc.type) {
        case TYPE_HTTP_GET:
          result = checkHttpGet(svc);
          break;
        case TYPE_PING:
          result = checkPing(svc);
          break;
        case TYPE_PORT:
          result = checkPort(svc);
          break;
        case TYPE_SNMP_GET:
          result = checkSnmpGet(svc);
          break;
        case TYPE_PUSH:
          result = checkPush(svc);
          break;
        case TYPE_UPTIME:
          result = checkUptime(svc);
          break;
        default:
          svc.lastError = "Unknown type";
          result = false;
      }
      updateServiceStatus(svc, result);
    }
  }
}

// ============================================
// Function Declarations
// ============================================
void setupWiFi();
void setupLoRa();
void syncNTP();
void handleLoRaMessage(String message);
void sendPingPacket();
void sendBootAdvert();
void loadOrGenerateEd25519Keys();
bool verifyMessage(String message);
void forwardToNtfy(String message);
void forwardToEmail(String message);
void forwardToDiscord(String message);
void forwardToWebhook(String message);
size_t encryptAndSign(const uint8_t* secret, size_t secretLen, uint8_t* output, size_t maxOutput, const uint8_t* input, size_t inputLen);
void deriveChannelKey(const char* channelName, const char* channelSecret, uint8_t* hash, uint8_t* key, size_t* keyLen);

// Helper function to get services as JSON string
String getServicesJson() {
  String json = "[";
  for (int i = 0; i < serviceCount; i++) {
    if (i > 0) json += ",";
    json += "{";
    json += "\"name\":\"" + services[i].name + "\",";
    json += "\"type\":" + String(services[i].type) + ",";
    json += "\"enabled\":" + String(services[i].enabled ? "true" : "false") + ",";
    json += "\"host\":\"" + services[i].host + "\",";
    json += "\"port\":" + String(services[i].port) + ",";
    json += "\"url\":\"" + services[i].url + "\",";
    json += "\"expectedResponse\":\"" + services[i].expectedResponse + "\",";
    json += "\"pushToken\":\"" + services[i].pushToken + "\",";
    json += "\"snmpOid\":\"" + services[i].snmpOid + "\",";
    json += "\"snmpCommunity\":\"" + services[i].snmpCommunity + "\",";
    json += "\"snmpCompareOp\":" + String((int)services[i].snmpCompareOp) + ",";
    json += "\"snmpExpectedValue\":\"" + services[i].snmpExpectedValue + "\",";
    json += "\"uptimeThreshold\":" + String(services[i].uptimeThreshold) + ",";
    json += "\"uptimeCompareOp\":" + String((int)services[i].uptimeCompareOp) + ",";
    json += "\"checkInterval\":" + String(services[i].checkInterval) + ",";
    json += "\"passThreshold\":" + String(services[i].passThreshold) + ",";
    json += "\"failThreshold\":" + String(services[i].failThreshold);
    json += "}";
  }
  json += "]";
  return json;
}

String generateSessionToken() {
  const char* hex = "0123456789abcdef";
  uint32_t seed = esp_random();
  randomSeed(seed ^ micros());
  char token[33];
  for (int i = 0; i < 32; i++) {
    token[i] = hex[random(0, 16)];
  }
  token[32] = '\0';
  return String(token);
}

bool isAuthenticated(AsyncWebServerRequest *request, bool sendUnauthorized) {
  if (sessionToken.length() == 0) {
    if (sendUnauthorized) {
      AsyncWebServerResponse *resp = request->beginResponse(401, "text/plain", "Unauthorized");
      resp->addHeader("WWW-Authenticate", "FormBased realm=\"ESP32 Monitor\"");
      request->send(resp);
    }
    return false;
  }

  if (!request->hasHeader("Cookie")) {
    if (sendUnauthorized) request->send(401, "text/plain", "Unauthorized");
    return false;
  }

  String cookie = request->header("Cookie");
  int pos = cookie.indexOf("SESSION=");
  if (pos < 0) {
    if (sendUnauthorized) request->send(401, "text/plain", "Unauthorized");
    return false;
  }

  int end = cookie.indexOf(';', pos);
  String token = (end < 0) ? cookie.substring(pos + 8) : cookie.substring(pos + 8, end);
  token.trim();

  if (token == sessionToken) {
    return true;
  }

  if (sendUnauthorized) request->send(401, "text/plain", "Unauthorized");
  return false;
}
void forwardToWebhook(String message);
size_t encryptAndSign(const uint8_t* secret, size_t secretLen, uint8_t* output, size_t maxOutput, const uint8_t* input, size_t inputLen);

// Global variable to store our node ID for filtering own messages
uint32_t ourNodeId = 0;
String ourNodeName = "";

void loadOrGenerateEd25519Keys() {
  // Try to load existing keys from LittleFS
  if (LittleFS.exists(ED25519_KEY_FILE)) {
    File f = LittleFS.open(ED25519_KEY_FILE, "r");
    if (f && f.size() == 64) {  // 32 bytes private + 32 bytes public
      f.read(ed25519_private_key, 32);
      f.read(ed25519_public_key, 32);
      f.close();
      ed25519_keys_loaded = true;
      Serial.println("[Ed25519] Loaded existing key pair");
      return;
    }
    if (f) f.close();
  }
  
  // Generate new key pair
  Serial.println("[Ed25519] Generating new key pair...");
  
  // Seed RNG with hardware RNG and other entropy sources
  RNG.begin("ESP32 Monitor");
  RNG.rand(ed25519_private_key, 32);  // Generate random private key
  
  // Derive public key from private key
  Ed25519::derivePublicKey(ed25519_public_key, ed25519_private_key);
  
  // Save to LittleFS
  File f = LittleFS.open(ED25519_KEY_FILE, "w");
  if (f) {
    f.write(ed25519_private_key, 32);
    f.write(ed25519_public_key, 32);
    f.close();
    Serial.println("[Ed25519] Key pair generated and saved");
  } else {
    Serial.println("[Ed25519] WARNING: Failed to save key pair to filesystem");
  }
  
  ed25519_keys_loaded = true;
}

void initNodeIdentity() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  ourNodeId = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
  char nodeName[18];
  snprintf(nodeName, sizeof(nodeName), "%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  ourNodeName = String(nodeName);
  Serial.printf("Node identity: %s (ID: 0x%08X)\n", ourNodeName.c_str(), ourNodeId);
  
  // Load or generate Ed25519 keys for signing adverts
  loadOrGenerateEd25519Keys();
}

// Send LoRa notification for service status changes
void sendLoRaNotification(const String& serviceName, bool isUp, const String& message) {
  if (!settings.loraEnabled) return;
  String notification = "[Monitor] " + serviceName + ": " + (isUp ? "UP" : "DOWN");
  if (message.length() > 0) {
    notification += " - " + message;
  }

  String messageId = messageIdForBody(notification);
  notification = "[MessageID:" + messageId + "] " + notification;
  
  // Derive channel hash and key
  uint8_t channelHash;
  uint8_t channelKey[32];
  size_t channelKeyLen = 0;
  deriveChannelKey(settings.channelName.c_str(), settings.channelSecret.c_str(), &channelHash, channelKey, &channelKeyLen);
  
  // Get MAC address for node name
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char nodeName[18];
  snprintf(nodeName, sizeof(nodeName), "%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  
  // Format message as "nodeName: text" to match MeshCore group message format
  String formattedMsg = String(nodeName) + ": " + notification;
  size_t textLen = formattedMsg.length();
  if (textLen > 220) textLen = 220;  // Leave room for timestamp + txt_type + padding
  
  // Build plaintext: [timestamp(4)][txt_type(1)][message]
  uint8_t plaintext[256];
  size_t idx = 0;
  uint32_t timestamp = (uint32_t)time(nullptr);
  plaintext[idx++] = (uint8_t)(timestamp & 0xFF);
  plaintext[idx++] = (uint8_t)((timestamp >> 8) & 0xFF);
  plaintext[idx++] = (uint8_t)((timestamp >> 16) & 0xFF);
  plaintext[idx++] = (uint8_t)((timestamp >> 24) & 0xFF);
  plaintext[idx++] = TXT_TYPE_PLAIN;  // txt_type (upper 6 bits), attempt (lower 2 bits) = 0
  memcpy(&plaintext[idx], formattedMsg.c_str(), textLen);
  idx += textLen;
  
  // Encrypt and compute MAC
  uint8_t macAndCipher[256];
  size_t macCipherLen = encryptAndSign(channelKey, channelKeyLen, macAndCipher, sizeof(macAndCipher), plaintext, idx);
  if (macCipherLen == 0) {
    Serial.println("[LoRa] ERROR: Failed to encrypt notification");
    return;
  }
  
  // Build complete packet: [header][path_len][path][channel_hash][MAC+ciphertext]
  uint8_t packet[260];
  size_t pktIdx = 0;
  
  // Header: version(0) + payload_type(GRP_TXT=5) + route_type(FLOOD=1)
  uint8_t header = (uint8_t)((ROUTE_TYPE_FLOOD & 0x03) | ((PAYLOAD_TYPE_GRP_TXT & 0x0F) << 2));
  packet[pktIdx++] = header;
  
  // Path (use node ID from MAC address for tracking)
  uint32_t nodeId = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
  packet[pktIdx++] = 4;  // path_len
  packet[pktIdx++] = (uint8_t)(nodeId & 0xFF);
  packet[pktIdx++] = (uint8_t)((nodeId >> 8) & 0xFF);
  packet[pktIdx++] = (uint8_t)((nodeId >> 16) & 0xFF);
  packet[pktIdx++] = (uint8_t)((nodeId >> 24) & 0xFF);
  
  // Channel hash (1 byte)
  packet[pktIdx++] = channelHash;
  
  // MAC + ciphertext
  if (pktIdx + macCipherLen > sizeof(packet)) {
    Serial.println("[LoRa] ERROR: Packet buffer too small");
    return;
  }
  memcpy(packet + pktIdx, macAndCipher, macCipherLen);
  pktIdx += macCipherLen;
  
  // Transmit
  int state = radio.transmit(packet, pktIdx);
  if (state == RADIOLIB_ERR_NONE) {
    Serial.printf("[LoRa] Sent notification: %s (timestamp=%u, len=%u)\n", 
                  notification.c_str(), timestamp, (unsigned int)pktIdx);
  } else {
    Serial.printf("[LoRa] Failed to send notification, code: %d\n", state);
  }
  
  // Return to RX mode
  radio.startReceive();
}

// Send boot advert to announce device presence on the mesh
void sendBootAdvert() {
  if (!settings.loraEnabled || !ed25519_keys_loaded) {
    if (!ed25519_keys_loaded) {
      Serial.println("[LoRa] Cannot send advert: Ed25519 keys not loaded");
    }
    return;
  }
  
  // Get MAC address for node ID
  uint8_t mac[6];
  WiFi.macAddress(mac);
  uint32_t nodeId = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
  
  // Use configured node name, or default to first 8 chars of public key
  String nodeNameStr = settings.loraNodeName;
  if (nodeNameStr.length() == 0) {
    // Default: first 8 hex chars of public key
    char hexBuf[17];
    for (int i = 0; i < 4; i++) {
      snprintf(hexBuf + (i * 2), 3, "%02X", ed25519_public_key[i]);
    }
    hexBuf[8] = '\0';
    nodeNameStr = String(hexBuf);
  }
  
  char nodeName[33];
  strncpy(nodeName, nodeNameStr.c_str(), sizeof(nodeName) - 1);
  nodeName[sizeof(nodeName) - 1] = '\0';
  size_t nodeNameLen = strlen(nodeName);
  
  // Timestamp (4 bytes, little-endian)
  uint32_t timestamp = (uint32_t)time(nullptr);
  uint8_t timestampBytes[4];
  timestampBytes[0] = (uint8_t)(timestamp & 0xFF);
  timestampBytes[1] = (uint8_t)((timestamp >> 8) & 0xFF);
  timestampBytes[2] = (uint8_t)((timestamp >> 16) & 0xFF);
  timestampBytes[3] = (uint8_t)((timestamp >> 24) & 0xFF);
  
  // Build app_data first (app_flags + node_name)
  uint8_t app_data[64];
  size_t app_data_len = 0;
  
  // App flags (1 byte) - bit 0-3: role (1=Chat Node), bit 4: location (0=No), bit 7: name (1=Yes)
  app_data[app_data_len++] = 0x81;  // Binary: 10000001 (Chat Node with name)
  
  // Node name (variable length UTF-8 string)
  memcpy(&app_data[app_data_len], nodeName, nodeNameLen);
  app_data_len += nodeNameLen;
  
  // Create signature over public_key + timestamp + app_data
  // Per MeshCore docs: "Ed25519 signature of public key, timestamp, and app data"
  uint8_t signedData[128];
  size_t signedDataLen = 0;
  memcpy(&signedData[signedDataLen], ed25519_public_key, 32);
  signedDataLen += 32;
  memcpy(&signedData[signedDataLen], timestampBytes, 4);
  signedDataLen += 4;
  memcpy(&signedData[signedDataLen], app_data, app_data_len);
  signedDataLen += app_data_len;
  
  uint8_t signature[64];
  Ed25519::sign(signature, ed25519_private_key, ed25519_public_key, signedData, signedDataLen);
  
  // Build advert payload: [public_key(32)][timestamp(4)][signature(64)][app_data]
  uint8_t payload[256];
  size_t payloadIdx = 0;
  
  // Public key (32 bytes)
  memcpy(&payload[payloadIdx], ed25519_public_key, 32);
  payloadIdx += 32;
  
  // Timestamp (4 bytes)
  memcpy(&payload[payloadIdx], timestampBytes, 4);
  payloadIdx += 4;
  
  // Signature (64 bytes)
  memcpy(&payload[payloadIdx], signature, 64);
  payloadIdx += 64;
  
  // App data (flags + name)
  memcpy(&payload[payloadIdx], app_data, app_data_len);
  payloadIdx += app_data_len;
  
  // Build complete packet: [header][path_len][path][payload]
  uint8_t packet[300];
  size_t pktIdx = 0;
  
  // --- Send Flood Advert (header = 0x11) ---
  // Header: version(0) + payload_type(ADVERT=4) + route_type(FLOOD=1)
  uint8_t floodHeader = (uint8_t)((ROUTE_TYPE_FLOOD & 0x03) | ((PAYLOAD_TYPE_ADVERT & 0x0F) << 2));
  packet[pktIdx++] = floodHeader;
  
  // Path (last byte of MAC address only)
  packet[pktIdx++] = 1;  // path_len (1 byte)
  packet[pktIdx++] = mac[5];  // Last byte of MAC (e.g., E0)
  
  // Advert payload
  if (pktIdx + payloadIdx > sizeof(packet)) {
    Serial.println("[LoRa] ERROR: Packet buffer too small for advert");
    return;
  }
  memcpy(packet + pktIdx, payload, payloadIdx);
  pktIdx += payloadIdx;
  
  // Transmit flood advert
  int state = radio.transmit(packet, pktIdx);
  if (state == RADIOLIB_ERR_NONE) {
    Serial.printf("[LoRa] Flood advert sent: Node %s (header=0x%02X, len=%u)\n", 
                  nodeName, floodHeader, (unsigned int)pktIdx);
    Serial.print("[Ed25519] Public key: ");
    for (int i = 0; i < 8; i++) {
      Serial.printf("%02X", ed25519_public_key[i]);
    }
    Serial.println("...");
  } else {
    Serial.printf("[LoRa] Failed to send flood advert, code: %d\n", state);
  }
  
  // Return to RX mode
  radio.startReceive();
}

// Uptime Monitoring Check Functions
bool checkHttpGet(Service& service) {
  if (WiFi.status() != WL_CONNECTED) {
    service.lastError = "WiFi not connected";
    return false;
  }
  HTTPClient http;
  http.setConnectTimeout(5000);
  http.setTimeout(10000);
  http.setReuse(false);
  http.begin(service.url);
  http.addHeader("Connection", "close");
  
  int httpCode = http.GET();
  if (httpCode > 0) {
    String payload = http.getString();
    http.end();
    if (service.expectedResponse == "*" || payload.indexOf(service.expectedResponse) != -1) {
      service.lastError = "HTTP OK (" + String(httpCode) + ")";
      return true;
    } else {
      service.lastError = "Unexpected response";
      return false;
    }
  } else {
    http.end();
    service.lastError = "HTTP error: " + String(httpCode);
    return false;
  }
}

// Simple ICMP ping implementation using lwIP raw sockets
bool sendIcmpPing(const IPAddress& ip, uint32_t timeout_ms) {
  int sock = socket(AF_INET, SOCK_RAW, IP_PROTO_ICMP);
  if (sock < 0) {
    return false;
  }
  
  struct timeval timeout;
  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = (uint32_t)ip;
  
  // Build ICMP echo request
  struct icmp_echo_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint16_t id;
    uint16_t seqno;
  } packet;
  
  packet.type = ICMP_ECHO;
  packet.code = 0;
  packet.chksum = 0;
  packet.id = htons(random(0xFFFF));
  packet.seqno = htons(1);
  packet.chksum = inet_chksum(&packet, sizeof(packet));
  
  // Send ping
  if (sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
    close(sock);
    return false;
  }
  
  // Wait for reply
  uint8_t buf[64];
  struct sockaddr_in from;
  socklen_t fromlen = sizeof(from);
  int len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
  
  close(sock);
  return (len > 0);
}

bool checkPing(Service& service) {
  if (WiFi.status() != WL_CONNECTED) {
    service.lastError = "WiFi not connected";
    return false;
  }
  
  IPAddress ip;
  if (!WiFi.hostByName(service.host.c_str(), ip)) {
    service.lastError = "Host not found";
    return false;
  }
  
  // Send 3 ICMP ping packets
  uint32_t pingCount = 3;
  uint32_t successCount = 0;
  
  for (uint32_t i = 0; i < pingCount; i++) {
    if (sendIcmpPing(ip, 2000)) {
      successCount++;
    }
    delay(200); // Small delay between pings
  }
  
  if (successCount > 0) {
    service.lastError = "Ping OK (" + ip.toString() + ", " + String(successCount) + "/" + String(pingCount) + " replies)";
    return true;
  } else {
    service.lastError = "Ping timeout (" + ip.toString() + ", 0/" + String(pingCount) + " replies)";
    return false;
  }
}

bool checkPort(Service& service) {
  if (WiFi.status() != WL_CONNECTED) {
    service.lastError = "WiFi not connected";
    return false;
  }
  
  IPAddress ip;
  if (!WiFi.hostByName(service.host.c_str(), ip)) {
    service.lastError = "Host not found";
    return false;
  }
  
  WiFiClient client;
  client.setTimeout(5000);
  
  if (client.connect(ip, service.port, 5000)) {
    client.stop();
    delay(10); // Small delay to ensure clean disconnect
    service.lastError = "Port " + String(service.port) + " open";
    return true;
  } else {
    client.stop();
    service.lastError = "Port " + String(service.port) + " closed/filtered";
    return false;
  }
}

bool parseSnmpLength(const uint8_t* data, size_t length, size_t& index, size_t& outLen) {
  if (index >= length) return false;
  uint8_t first = data[index++];
  if ((first & 0x80) == 0) {
    outLen = first;
    return index + outLen <= length;
  }

  uint8_t numBytes = first & 0x7F;
  if (numBytes == 0 || index + numBytes > length) return false;

  size_t value = 0;
  for (uint8_t i = 0; i < numBytes; i++) {
    value = (value << 8) | data[index++];
  }
  outLen = value;
  return index + outLen <= length;
}

bool encodeOid(const String& oidStr, uint8_t* output, size_t& outLen, size_t maxLen) {
  int parts[32];
  int partCount = 0;
  int start = 0;
  for (int i = 0; i <= oidStr.length(); i++) {
    if (i == oidStr.length() || oidStr[i] == '.') {
      if (partCount >= 32) return false;
      parts[partCount++] = oidStr.substring(start, i).toInt();
      start = i + 1;
    }
  }
  if (partCount < 2) return false;

  size_t pos = 0;
  int firstByte = parts[0] * 40 + parts[1];
  if (pos >= maxLen) return false;
  output[pos++] = (uint8_t)firstByte;

  for (int i = 2; i < partCount; i++) {
    unsigned long value = parts[i];
    uint8_t temp[5];
    int tempPos = 0;
    do {
      temp[tempPos++] = value & 0x7F;
      value >>= 7;
    } while (value > 0 && tempPos < 5);

    if (pos + tempPos > maxLen) return false;
    for (int j = tempPos - 1; j >= 0; j--) {
      uint8_t byte = temp[j];
      if (j != 0) byte |= 0x80;
      output[pos++] = byte;
    }
  }

  outLen = pos;
  return true;
}

bool decodeInteger(const uint8_t* data, size_t length, size_t& index, long& valueOut) {
  if (index >= length || data[index++] != 0x02) return false;
  size_t len = 0;
  if (!parseSnmpLength(data, length, index, len) || len > sizeof(long) || index + len > length) return false;
  long value = 0;
  for (size_t i = 0; i < len; i++) {
    value = (value << 8) | data[index++];
  }
  valueOut = value;
  return true;
}

bool decodeValueString(const uint8_t* data, size_t length, size_t& index, String& valueOut) {
  if (index >= length) return false;
  uint8_t type = data[index++];
  size_t len = 0;
  if (!parseSnmpLength(data, length, index, len) || index + len > length) return false;

  switch (type) {
    case 0x02: {  // Integer
      long intValue = 0;
      for (size_t i = 0; i < len; i++) {
        intValue = (intValue << 8) | data[index++];
      }
      valueOut = String(intValue);
      return true;
    }
    case 0x04: {  // Octet String
      valueOut = String();
      for (size_t i = 0; i < len; i++) valueOut += (char)data[index++];
      return true;
    }
    default: {
      // Unsupported type: represent as hex string
      valueOut = "0x";
      for (size_t i = 0; i < len; i++) {
        if (data[index + i] < 16) valueOut += "0";
        valueOut += String(data[index + i], HEX);
      }
      index += len;
      return true;
    }
  }
}

bool parseSnmpResponse(const uint8_t* data, size_t length, long expectedRequestId, String& valueOut, String& errorOut) {
  size_t index = 0;
  if (index >= length || data[index++] != 0x30) {
    errorOut = "Invalid SNMP sequence";
    return false;
  }
  size_t len = 0;
  if (!parseSnmpLength(data, length, index, len)) {
    errorOut = "Invalid SNMP length";
    return false;
  }

  // Version
  long version = 0;
  if (!decodeInteger(data, length, index, version) || version != 0) {
    errorOut = "Unsupported SNMP version";
    return false;
  }

  // Community
  if (index >= length || data[index++] != 0x04) {
    errorOut = "Missing community";
    return false;
  }
  size_t communityLen = 0;
  if (!parseSnmpLength(data, length, index, communityLen) || index + communityLen > length) {
    errorOut = "Invalid community";
    return false;
  }
  index += communityLen;

  if (index >= length || data[index++] != 0xA2) {
    errorOut = "Not a GetResponse";
    return false;
  }

  size_t pduLen = 0;
  if (!parseSnmpLength(data, length, index, pduLen) || index + pduLen > length) {
    errorOut = "Invalid PDU";
    return false;
  }

  long requestId = 0;
  if (!decodeInteger(data, length, index, requestId) || requestId != expectedRequestId) {
    errorOut = "Request ID mismatch";
    return false;
  }

  long errorStatus = 0;
  if (!decodeInteger(data, length, index, errorStatus)) {
    errorOut = "Error status missing";
    return false;
  }
  if (errorStatus != 0) {
    errorOut = "SNMP error status " + String(errorStatus);
    return false;
  }

  long errorIndex = 0;
  if (!decodeInteger(data, length, index, errorIndex)) {
    errorOut = "Error index missing";
    return false;
  }

  // VarBind list
  if (index >= length || data[index++] != 0x30) {
    errorOut = "Missing varbind list";
    return false;
  }
  size_t vblLen = 0;
  if (!parseSnmpLength(data, length, index, vblLen) || index + vblLen > length) {
    errorOut = "Invalid varbind list";
    return false;
  }

  if (index >= length || data[index++] != 0x30) {
    errorOut = "Missing varbind";
    return false;
  }
  size_t vbLen = 0;
  if (!parseSnmpLength(data, length, index, vbLen) || index + vbLen > length) {
    errorOut = "Invalid varbind";
    return false;
  }

  // OID
  if (index >= length || data[index++] != 0x06) {
    errorOut = "Missing OID";
    return false;
  }
  size_t oidLen = 0;
  if (!parseSnmpLength(data, length, index, oidLen) || index + oidLen > length) {
    errorOut = "Invalid OID";
    return false;
  }
  index += oidLen;

  if (!decodeValueString(data, length, index, valueOut)) {
    errorOut = "Failed to decode value";
    return false;
  }

  return true;
}

bool compareSnmpValue(const String& actual, const String& expected, CompareOp op) {
  auto parseDouble = [](const String& str, double& out) {
    const char* cstr = str.c_str();
    char* endPtr;
    out = strtod(cstr, &endPtr);
    return endPtr != cstr && *endPtr == '\0';
  };

  double actualNum, expectedNum;
  bool actualIsNum = parseDouble(actual, actualNum);
  bool expectedIsNum = parseDouble(expected, expectedNum);

  if (actualIsNum && expectedIsNum) {
    switch (op) {
      case OP_EQ: return actualNum == expectedNum;
      case OP_NE: return actualNum != expectedNum;
      case OP_GT: return actualNum > expectedNum;
      case OP_LT: return actualNum < expectedNum;
      case OP_GE: return actualNum >= expectedNum;
      case OP_LE: return actualNum <= expectedNum;
      default: return false;
    }
  }

  // Fallback to string comparison for equality/non-equality
  if (op == OP_EQ) return actual == expected;
  if (op == OP_NE) return actual != expected;
  return false;
}

bool checkSnmpGet(Service& service) {
  if (WiFi.status() != WL_CONNECTED) {
    service.lastError = "WiFi not connected";
    return false;
  }

  IPAddress ip;
  if (!WiFi.hostByName(service.host.c_str(), ip)) {
    service.lastError = "Host not found";
    return false;
  }

  uint8_t oidEncoded[64];
  size_t oidLen = 0;
  if (!encodeOid(service.snmpOid, oidEncoded, oidLen, sizeof(oidEncoded))) {
    service.lastError = "Invalid OID";
    return false;
  }

  uint8_t packet[256];
  size_t pos = 0;

  auto startSequence = [&](uint8_t type) {
    size_t lenPos = pos + 1;
    packet[pos++] = type;
    packet[pos++] = 0;  // placeholder for length (<128)
    return lenPos;
  };

  auto finishSequence = [&](size_t lenPos) {
    packet[lenPos] = pos - lenPos - 1;
  };

  auto writeInteger = [&](long value) -> bool {
    if (pos + 6 > sizeof(packet)) return false;
    packet[pos++] = 0x02;
    packet[pos++] = 4;
    packet[pos++] = (value >> 24) & 0xFF;
    packet[pos++] = (value >> 16) & 0xFF;
    packet[pos++] = (value >> 8) & 0xFF;
    packet[pos++] = value & 0xFF;
    return true;
  };

  // Build SNMP message (assuming lengths < 128)
  size_t msgLenPos = startSequence(0x30);

  if (!writeInteger(0)) {  // version v1
    service.lastError = "Failed to encode version";
    return false;
  }

  if (pos + 2 + service.snmpCommunity.length() > sizeof(packet)) {
    service.lastError = "Community too long";
    return false;
  }
  packet[pos++] = 0x04;
  packet[pos++] = service.snmpCommunity.length();
  memcpy(packet + pos, service.snmpCommunity.c_str(), service.snmpCommunity.length());
  pos += service.snmpCommunity.length();

  size_t pduLenPos = startSequence(0xA0);

  long requestId = random(1, 0x7FFFFFFF);
  if (!writeInteger(requestId)) {
    service.lastError = "Failed to encode request id";
    return false;
  }
  if (!writeInteger(0) || !writeInteger(0)) {  // error-status, error-index
    service.lastError = "Failed to encode error fields";
    return false;
  }

  size_t vbListLenPos = startSequence(0x30);
  size_t vbLenPos = startSequence(0x30);

  if (pos + 2 + oidLen + 2 > sizeof(packet)) {
    service.lastError = "OID too long";
    return false;
  }
  packet[pos++] = 0x06;
  packet[pos++] = oidLen;
  memcpy(packet + pos, oidEncoded, oidLen);
  pos += oidLen;
  packet[pos++] = 0x05;  // NULL value
  packet[pos++] = 0x00;

  finishSequence(vbLenPos);
  finishSequence(vbListLenPos);
  finishSequence(pduLenPos);
  finishSequence(msgLenPos);

  WiFiUDP udp;
  udp.begin(0);
  if (!udp.beginPacket(ip, 161)) {
    service.lastError = "Failed to open UDP";
    return false;
  }
  udp.write(packet, pos);
  udp.endPacket();

  uint8_t response[512];
  int responseLen = 0;
  unsigned long start = millis();
  while (millis() - start < 3000) {
    int size = udp.parsePacket();
    if (size > 0) {
      responseLen = udp.read(response, min(size, (int)sizeof(response)));
      break;
    }
    delay(50);
  }

  if (responseLen <= 0) {
    service.lastError = "SNMP timeout";
    return false;
  }

  String value;
  String parseError;
  if (!parseSnmpResponse(response, responseLen, requestId, value, parseError)) {
    service.lastError = parseError;
    return false;
  }

  bool comparison = compareSnmpValue(value, service.snmpExpectedValue, service.snmpCompareOp);
  service.lastError = "SNMP value: " + value;
  return comparison;
}

bool checkPush(Service& service) {
  unsigned long now = millis();
  if (service.lastPush == 0) {
    service.lastError = "No push received yet";
    return false;
  }

  unsigned long since = now - service.lastPush;
  if (since <= (unsigned long)service.checkInterval * 1000) {
    service.lastError = "Last push " + String(since / 1000) + "s ago";
    return true;
  }

  service.lastError = "Push timeout (" + String(since / 1000) + "s ago)";
  return false;
}

bool checkUptime(Service& service) {
  unsigned long uptimeSeconds = millis() / 1000;
  int threshold = service.uptimeThreshold;
  bool result = false;
  switch (service.uptimeCompareOp) {
    case OP_EQ: result = (uptimeSeconds == threshold); break;
    case OP_NE: result = (uptimeSeconds != threshold); break;
    case OP_GT: result = (uptimeSeconds > threshold); break;
    case OP_LT: result = (uptimeSeconds < threshold); break;
    case OP_GE: result = (uptimeSeconds >= threshold); break;
    case OP_LE: result = (uptimeSeconds <= threshold); break;
    default: service.lastError = "Invalid comparison op"; return false;
  }
  service.lastError = "Uptime " + String(uptimeSeconds) + "s";
  return result;
}

// Pass/Fail threshold logic
void updateServiceStatus(Service& service, bool checkResult) {
  bool wasUp = service.isUp;
  bool wasPending = service.isPending;
  
  if (checkResult) {
    service.consecutivePasses++;
    service.consecutiveFails = 0;
    if (service.consecutivePasses >= service.passThreshold) {
      service.isUp = true;
      service.hasBeenUp = true;
      service.isPending = false;
    }
  } else {
    service.consecutiveFails++;
    service.consecutivePasses = 0;
    if (service.consecutiveFails >= service.failThreshold) {
      service.isUp = false;
      service.isPending = false;
    }
  }
  
  // Send LoRa notification on status change (but not for initial pending -> up/down transition)
  if (wasUp != service.isUp && !wasPending) {
    appendServiceStatusEvent(service, service.isUp);
    if (service.isUp) {
      Serial.printf("[Status] %s is now UP\n", service.name.c_str());
      sendLoRaNotification(service.name, true, service.lastError);
    } else {
      Serial.printf("[Status] %s is now DOWN\n", service.name.c_str());
      sendLoRaNotification(service.name, false, service.lastError);
    }
  } else if (wasPending && !service.isPending) {
    Serial.printf("[Status] %s initial state: %s\n", service.name.c_str(), service.isUp ? "UP" : "DOWN");
  }
  
  service.lastCheck = millis();
}

// ============================================
// MeshCore Crypto Functions
// ============================================

/**
 * Verify MAC and decrypt MeshCore packet
 * @param secret Channel secret key
 * @param secretLen Length of secret
 * @param output Buffer for decrypted plaintext
 * @param input Encrypted packet (MAC + ciphertext)
 * @param inputLen Length of encrypted packet
 * @return Length of decrypted plaintext, or 0 on failure
 */
size_t verifyAndDecrypt(const uint8_t* secret, size_t secretLen, uint8_t* output, const uint8_t* input, size_t inputLen) {
  if (inputLen < CIPHER_MAC_SIZE) {
    Serial.println("Packet too short for MAC");
    return 0;
  }
  
  size_t ciphertextLen = inputLen - CIPHER_MAC_SIZE;
  const uint8_t* receivedMAC = input;
  const uint8_t* ciphertext = input + CIPHER_MAC_SIZE;
  
  // Compute HMAC-SHA256 over ciphertext
  unsigned char hmacFull[32];
  mbedtls_md_context_t md;
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info == nullptr) {
    Serial.println("ERROR: SHA256 HMAC info unavailable");
    return 0;
  }
  mbedtls_md_init(&md);
  mbedtls_md_setup(&md, info, 1);
  mbedtls_md_hmac_starts(&md, secret, secretLen);
  mbedtls_md_hmac_update(&md, ciphertext, ciphertextLen);
  mbedtls_md_hmac_finish(&md, hmacFull);
  mbedtls_md_free(&md);
  
  // Verify first 2 bytes of HMAC match received MAC
  if (memcmp(receivedMAC, hmacFull, CIPHER_MAC_SIZE) != 0) {
    Serial.printf("MAC verification failed: expected %02X%02X, got %02X%02X\n",
                  hmacFull[0], hmacFull[1], receivedMAC[0], receivedMAC[1]);
    return 0;
  }
  
  Serial.println("MAC verified successfully");
  
  // Decrypt with AES-128 ECB
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, secret, 128);
  
  for (size_t offset = 0; offset < ciphertextLen; offset += CIPHER_BLOCK_SIZE) {
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, ciphertext + offset, output + offset);
  }
  mbedtls_aes_free(&aes);
  
  return ciphertextLen;
}

/**
 * Encrypt plaintext and prepend 2-byte MAC (HMAC-SHA256 over ciphertext)
 * @param secret Channel secret key (used for HMAC and AES-128 key material)
 * @param secretLen Length of secret
 * @param output Buffer for MAC + ciphertext
 * @param maxOutput Size of output buffer
 * @param input Plaintext to encrypt
 * @param inputLen Length of plaintext
 * @return Length of MAC+ciphertext, or 0 on failure
 */
size_t encryptAndSign(const uint8_t* secret, size_t secretLen, uint8_t* output, size_t maxOutput, const uint8_t* input, size_t inputLen) {
  if (secretLen == 0) {
    Serial.println("ERROR: Missing channel secret for encryption");
    return 0;
  }

  size_t paddedLen = ((inputLen + CIPHER_BLOCK_SIZE - 1) / CIPHER_BLOCK_SIZE) * CIPHER_BLOCK_SIZE;
  if (paddedLen + CIPHER_MAC_SIZE > maxOutput) {
    Serial.println("ERROR: Output buffer too small for encrypted payload");
    return 0;
  }

  uint8_t padded[256];
  if (paddedLen > sizeof(padded)) {
    Serial.println("ERROR: Plaintext too large to encrypt");
    return 0;
  }

  memset(padded, 0, paddedLen);
  memcpy(padded, input, inputLen);

  uint8_t* ciphertext = output + CIPHER_MAC_SIZE;

  // Encrypt with AES-128 ECB (first 16 bytes of secret)
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, secret, 128);

  for (size_t offset = 0; offset < paddedLen; offset += CIPHER_BLOCK_SIZE) {
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, padded + offset, ciphertext + offset);
  }
  mbedtls_aes_free(&aes);

  // Compute HMAC-SHA256 over ciphertext
  unsigned char hmacFull[32];
  mbedtls_md_context_t md;
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info == nullptr) {
    Serial.println("ERROR: SHA256 HMAC info unavailable");
    return 0;
  }
  mbedtls_md_init(&md);
  mbedtls_md_setup(&md, info, 1);
  mbedtls_md_hmac_starts(&md, secret, secretLen);
  mbedtls_md_hmac_update(&md, ciphertext, paddedLen);
  mbedtls_md_hmac_finish(&md, hmacFull);
  mbedtls_md_free(&md);

  // Copy first 2 bytes as MAC prefix
  output[0] = hmacFull[0];
  output[1] = hmacFull[1];

  return paddedLen + CIPHER_MAC_SIZE;
}

/**
 * Check if string is valid hex (only 0-9, a-f, A-F)
 */
bool isHexString(const char* str, size_t len) {
  for (size_t i = 0; i < len; i++) {
    char c = str[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
      return false;
    }
  }
  return true;
}

/**
 * Convert hex string to bytes
 */
size_t hexToBytes(const char* hex, uint8_t* bytes, size_t maxBytes) {
  size_t hexLen = strlen(hex);
  if (hexLen % 2 != 0) return 0;
  
  size_t byteLen = hexLen / 2;
  if (byteLen > maxBytes) return 0;
  
  for (size_t i = 0; i < byteLen; i++) {
    char highNibble = hex[i * 2];
    char lowNibble = hex[i * 2 + 1];
    
    uint8_t high = (highNibble >= '0' && highNibble <= '9') ? (highNibble - '0') :
                   (highNibble >= 'a' && highNibble <= 'f') ? (highNibble - 'a' + 10) :
                   (highNibble - 'A' + 10);
    uint8_t low = (lowNibble >= '0' && lowNibble <= '9') ? (lowNibble - '0') :
                  (lowNibble >= 'a' && lowNibble <= 'f') ? (lowNibble - 'a' + 10) :
                  (lowNibble - 'A' + 10);
    
    bytes[i] = (high << 4) | low;
  }
  
  return byteLen;
}

/**
 * Derive channel hash and secret from channel name and passphrase
 * Matches MeshCore's channel derivation (same logic as transmitter):
 * - If secret is 32 or 64 hex chars: use hex bytes directly as PSK, hash = SHA256(PSK)[0]
 * - Otherwise: PSK = SHA256(channelName + ":" + channelSecret), hash = SHA256(PSK)[0]
 */
void deriveChannelKey(const char* channelName, const char* channelSecret, uint8_t* hash, uint8_t* key, size_t* keyLen) {
  unsigned char secret[32];
  size_t secretLen = 0;
  size_t secretStrLen = strlen(channelSecret);
  
  // Check if secret is a valid hex PSK (16 or 32 bytes = 32 or 64 hex chars)
  if ((secretStrLen == 32 || secretStrLen == 64) && isHexString(channelSecret, secretStrLen)) {
    // Use hex bytes directly as PSK
    uint8_t pskBytes[32];
    size_t pskLen = hexToBytes(channelSecret, pskBytes, sizeof(pskBytes));
    
    if (pskLen == 16 || pskLen == 32) {
      Serial.printf("Using hex PSK (%d bytes)\n", (int)pskLen);
      memcpy(secret, pskBytes, pskLen);
      secretLen = pskLen;
    } else {
      Serial.println("ERROR: Invalid hex PSK length");
      secretLen = 0;
    }
  }
  
  // If not hex PSK, derive from channel name + secret
  if (secretLen == 0) {
    String input = String(channelName);
    if (channelSecret != nullptr && strlen(channelSecret) > 0) {
      input += ":";
      input += String(channelSecret);
      Serial.println("Deriving PSK from channel name + secret");
    } else {
      Serial.println("Deriving PSK from channel name only");
    }
    
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, (const unsigned char*)input.c_str(), input.length());
    mbedtls_sha256_finish(&sha, secret);
    mbedtls_sha256_free(&sha);
    secretLen = 32;
  }
  
  // Channel hash: SHA256(secret)[0]
  unsigned char fullHash[32];
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha, secret, secretLen);
  mbedtls_sha256_finish(&sha, fullHash);
  mbedtls_sha256_free(&sha);
  
  *hash = fullHash[0];
  
  // Return the secret as the key
  memcpy(key, secret, secretLen);
  *keyLen = secretLen;
  
  Serial.printf("Channel hash: 0x%02X, Key length: %d\n", *hash, (int)*keyLen);
}

// ============================================
// MeshCore TX Helper
// ============================================
void sendPingPacket() {
  uint8_t channelHash;
  uint8_t channelKey[32];
  size_t channelKeyLen = 0;
  static uint32_t pingCounter = 0;

  deriveChannelKey(settings.channelName.c_str(), settings.channelSecret.c_str(), &channelHash, channelKey, &channelKeyLen);

  // Get MAC address for logging
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char nodeName[18];
  snprintf(nodeName, sizeof(nodeName), "%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  // Build plaintext payload: [timestamp(4)][txt_type(1)][text]
  uint8_t plaintext[256];
  uint32_t timestamp = (uint32_t)time(nullptr);  // Unix epoch time in seconds
  
  // Format message as "nodeName: message" to display sender properly in MeshCore app
  String message = String(TX_PING_TEXT) + " #" + String(pingCounter++);
  String text = String(nodeName) + ": " + message;
  size_t textLen = text.length();
  size_t plainLen = 4 + 1 + textLen;

  if (plainLen > sizeof(plaintext)) {
    Serial.println("ERROR: Ping message too long");
    return;
  }

  size_t idx = 0;
  plaintext[idx++] = (uint8_t)(timestamp & 0xFF);
  plaintext[idx++] = (uint8_t)((timestamp >> 8) & 0xFF);
  plaintext[idx++] = (uint8_t)((timestamp >> 16) & 0xFF);
  plaintext[idx++] = (uint8_t)((timestamp >> 24) & 0xFF);
  plaintext[idx++] = TXT_TYPE_PLAIN;
  memcpy(&plaintext[idx], text.c_str(), textLen);

  uint8_t macAndCipher[256];
  size_t macCipherLen = encryptAndSign(channelKey, channelKeyLen, macAndCipher, sizeof(macAndCipher), plaintext, plainLen);
  if (macCipherLen == 0) {
    Serial.println("ERROR: Failed to encrypt ping payload");
    return;
  }

  uint8_t packet[260];
  size_t pktIdx = 0;
  uint8_t header = (uint8_t)((ROUTE_TYPE_FLOOD & 0x03) | ((PAYLOAD_TYPE_GRP_TXT & 0x0F) << 2));
  packet[pktIdx++] = header;         // header: version=0, payload=GRP_TXT, route=FLOOD
  
  // Add node hash to path (use last 4 bytes of MAC as 32-bit node ID)
  uint32_t nodeId = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
  packet[pktIdx++] = 4;              // path length = 4 bytes (node ID)
  packet[pktIdx++] = (uint8_t)(nodeId & 0xFF);
  packet[pktIdx++] = (uint8_t)((nodeId >> 8) & 0xFF);
  packet[pktIdx++] = (uint8_t)((nodeId >> 16) & 0xFF);
  packet[pktIdx++] = (uint8_t)((nodeId >> 24) & 0xFF);
  
  packet[pktIdx++] = channelHash;    // channel hash byte

  if (pktIdx + macCipherLen > sizeof(packet)) {
    Serial.println("ERROR: Packet buffer too small");
    return;
  }

  memcpy(packet + pktIdx, macAndCipher, macCipherLen);
  pktIdx += macCipherLen;

  Serial.printf("Sending ping on channel %s from %s: '%s' (timestamp=%u, len=%u)\n", 
                settings.channelName.c_str(), nodeName, message.c_str(), timestamp, (unsigned int)pktIdx);

  int state = radio.transmit(packet, pktIdx);
  if (state == RADIOLIB_ERR_NONE) {
    Serial.println("Ping transmitted successfully");
  } else {
    Serial.print("LoRa transmit failed, code: ");
    Serial.println(state);
  }
}

// ============================================
// Setup Function
// ============================================
void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("ESP32 Uptime Receiver Starting...");

  // Rapid LED flicker to indicate boot
  pinMode(LED_PIN, OUTPUT);
  for (int i = 0; i < 16; i++) {
    digitalWrite(LED_PIN, (i % 2) ? HIGH : LOW);
    delay(25);
  }
  digitalWrite(LED_PIN, LOW);

  initBatteryMonitor();
  
  // Power on the LoRa radio (Vext)
  pinMode(LORA_VEXT_PIN, OUTPUT);
  digitalWrite(LORA_VEXT_PIN, LOW);  // LOW = power on
  delay(100);

  // Initialize LittleFS early (settings/services depend on it)
  if (!LittleFS.begin(false)) {
    Serial.println("LittleFS mount failed! Attempting to format...");
    if (LittleFS.begin(true)) {
      Serial.println("LittleFS formatted and mounted successfully.");
    } else {
      Serial.println("LittleFS format failed!");
    }
  } else {
    Serial.println("LittleFS mounted successfully.");
  }

  // Load last-known STA IP for IP-change notifications
  loadLastKnownStaIp();

  // Load runtime settings: build-time defaults (.env) + optional overrides (/settings.json)
  applySettingsDefaults();
  loadSettingsOverrides();
  
  // Setup WiFi (needed for forwarding and NTP sync)
  setupWiFi();
  
  // Initialize node identity for filtering own messages
  initNodeIdentity();
  
  // Sync time via NTP for proper timestamps
  if (wifiConnected) {
    syncNTP();
  }
  
  // Setup LoRa
  if (settings.loraEnabled) {
    setupLoRa();
    loraReady = true;

    if (pendingWifiProvisionNotify && pendingWifiProvisionNotifyMessage.length() > 0) {
      sendLoRaNotification("WiFi", true, pendingWifiProvisionNotifyMessage);
      pendingWifiProvisionNotify = false;
      pendingWifiProvisionNotifyMessage = "";
    }

    if (pendingLoRaNotify && pendingLoRaNotifyMessage.length() > 0) {
      sendLoRaNotification("WiFi", true, pendingLoRaNotifyMessage);
      pendingLoRaNotify = false;
      pendingLoRaNotifyMessage = "";
    }

    // Send boot advert to announce device on the mesh network
    sendBootAdvert();
  } else {
    loraReady = false;
    Serial.println("LoRa disabled by settings; skipping radio init");
  }
  
  Serial.println("System Ready");

  // Load services from LittleFS (or initialize demo services if file doesn't exist)
  loadServices();

  // Authentication endpoints
  server.on("/api/login", HTTP_POST, [](AsyncWebServerRequest *request){}, NULL,
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total){
      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, data, len);
      if (err) {
        request->send(400, "application/json", "{\"error\":\"invalid json\"}");
        return;
      }

      String username = doc["username"].as<String>();
      String password = doc["password"].as<String>();

      if (username == settings.adminUsername && password == settings.adminPassword) {
        sessionToken = generateSessionToken();
        sessionIssuedAt = millis();
        AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", "{\"status\":\"ok\"}");
        resp->addHeader("Set-Cookie", "SESSION=" + sessionToken + "; Path=/; HttpOnly; SameSite=Lax");
        resp->addHeader("Cache-Control", "no-store");
        request->send(resp);
      } else {
        request->send(401, "application/json", "{\"error\":\"invalid credentials\"}");
      }
  });

  server.on("/api/logout", HTTP_POST, [](AsyncWebServerRequest *request){
    sessionToken = "";
    sessionIssuedAt = 0;
    AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", "{\"status\":\"logged out\"}");
    resp->addHeader("Set-Cookie", "SESSION=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax");
    resp->addHeader("Cache-Control", "no-store");
    request->send(resp);
  });

  // Settings API (protected)
  server.on("/api/settings", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    JsonDocument doc;
    doc["WIFI_SSID"] = settings.wifiSsid;
    
    doc["IP_MODE"] = settings.ipMode;
    doc["STATIC_IP"] = settings.staticIp;
    doc["STATIC_GATEWAY"] = settings.staticGateway;
    doc["STATIC_SUBNET"] = settings.staticSubnet;
    
    doc["DNS_MODE"] = settings.dnsMode;
    doc["STATIC_DNS1"] = settings.staticDns1;
    doc["STATIC_DNS2"] = settings.staticDns2;
    
    doc["ADMIN_USERNAME"] = settings.adminUsername;
    doc["CHANNEL_NAME"] = settings.channelName;

    doc["LORA_ENABLED"] = settings.loraEnabled;
    doc["LORA_NODE_NAME"] = settings.loraNodeName;
    doc["LORA_IP_ALERTS"] = settings.loraIpAlerts;
    doc["LORA_FREQ"] = settings.loraFreq;
    doc["LORA_BANDWIDTH"] = settings.loraBandwidth;
    doc["LORA_SPREADING_FACTOR"] = settings.loraSpreadingFactor;
    doc["LORA_CODING_RATE"] = settings.loraCodingRate;

    doc["NTFY_ENABLED"] = settings.ntfyEnabled;
    doc["NTFY_MESH_RELAY"] = settings.ntfyMeshRelay;
    doc["NTFY_IP_ALERTS"] = settings.ntfyIpAlerts;
    doc["NTFY_SERVER"] = settings.ntfyServer;
    doc["NTFY_TOPIC"] = settings.ntfyTopic;
    doc["NTFY_USERNAME"] = settings.ntfyUsername;

    doc["DISCORD_ENABLED"] = settings.discordEnabled;
    doc["DISCORD_MESH_RELAY"] = settings.discordMeshRelay;
    doc["DISCORD_IP_ALERTS"] = settings.discordIpAlerts;

    doc["WEBHOOK_ENABLED"] = settings.webhookEnabled;
    doc["WEBHOOK_MESH_RELAY"] = settings.webhookMeshRelay;
    doc["WEBHOOK_IP_ALERTS"] = settings.webhookIpAlerts;
    doc["WEBHOOK_METHOD"] = settings.webhookMethod;

    doc["EMAIL_ENABLED"] = settings.emailEnabled;
    doc["EMAIL_MESH_RELAY"] = settings.emailMeshRelay;
    doc["EMAIL_IP_ALERTS"] = settings.emailIpAlerts;
    doc["SMTP_HOST"] = settings.smtpHost;
    doc["SMTP_PORT"] = settings.smtpPort;
    doc["EMAIL_RECIPIENT"] = settings.emailRecipient;
    doc["EMAIL_SENDER"] = settings.emailSender;
    doc["SMTP_USER"] = settings.smtpUser;

    doc["MQTT_ENABLED"] = settings.mqttEnabled;
    doc["MQTT_MESH_RELAY"] = settings.mqttMeshRelay;
    doc["MQTT_IP_ALERTS"] = settings.mqttIpAlerts;
    doc["MQTT_BROKER"] = settings.mqttBroker;
    doc["MQTT_PORT"] = settings.mqttPort;
    doc["MQTT_TOPIC"] = settings.mqttTopic;
    doc["MQTT_QOS"] = settings.mqttQos;
    doc["MQTT_USERNAME"] = settings.mqttUsername;

    String json;
    serializeJson(doc, json);
    AsyncWebServerResponse *resp = request->beginResponse(200, "application/json", json);
    resp->addHeader("Cache-Control", "no-store");
    request->send(resp);
  });

  server.on("/api/settings", HTTP_POST, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
  }, nullptr,
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total){
      if (!isAuthenticated(request)) return;
      if (index == 0) {
        String *body = new String();
        body->reserve(total);
        request->_tempObject = body;
      }

      String *body = static_cast<String *>(request->_tempObject);
      if (!body) {
        request->send(500, "application/json", "{\"error\":\"server error\"}");
        return;
      }

      body->concat(reinterpret_cast<const char *>(data), len);
      if (index + len < total) return;

      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, *body);
      delete body;
      request->_tempObject = nullptr;

      if (err) {
        request->send(400, "application/json", "{\"error\":\"invalid json\"}");
        return;
      }

      Settings before = settings;

      // Strings
      if (doc["WIFI_SSID"].is<String>()) settings.wifiSsid = doc["WIFI_SSID"].as<String>();
      if (doc["WIFI_PASSWORD"].is<String>()) {
        String v = doc["WIFI_PASSWORD"].as<String>();
        if (v.length() > 0) settings.wifiPassword = v;
      }
      
      if (doc["IP_MODE"].is<String>()) settings.ipMode = doc["IP_MODE"].as<String>();
      if (doc["STATIC_IP"].is<String>()) settings.staticIp = doc["STATIC_IP"].as<String>();
      if (doc["STATIC_GATEWAY"].is<String>()) settings.staticGateway = doc["STATIC_GATEWAY"].as<String>();
      if (doc["STATIC_SUBNET"].is<String>()) settings.staticSubnet = doc["STATIC_SUBNET"].as<String>();
      
      if (doc["DNS_MODE"].is<String>()) settings.dnsMode = doc["DNS_MODE"].as<String>();
      if (doc["STATIC_DNS1"].is<String>()) settings.staticDns1 = doc["STATIC_DNS1"].as<String>();
      if (doc["STATIC_DNS2"].is<String>()) settings.staticDns2 = doc["STATIC_DNS2"].as<String>();
      
      if (doc["ADMIN_USERNAME"].is<String>()) settings.adminUsername = doc["ADMIN_USERNAME"].as<String>();
      if (doc["ADMIN_PASSWORD"].is<String>()) {
        String v = doc["ADMIN_PASSWORD"].as<String>();
        if (v.length() > 0) settings.adminPassword = v;
      }
      if (doc["CHANNEL_NAME"].is<String>()) settings.channelName = doc["CHANNEL_NAME"].as<String>();
      if (doc["CHANNEL_SECRET"].is<String>()) {
        String v = doc["CHANNEL_SECRET"].as<String>();
        if (v.length() > 0) settings.channelSecret = v;
      }

      if (doc["LORA_ENABLED"].is<bool>()) settings.loraEnabled = doc["LORA_ENABLED"].as<bool>();
      if (doc["LORA_NODE_NAME"].is<String>()) settings.loraNodeName = doc["LORA_NODE_NAME"].as<String>();
      if (doc["LORA_IP_ALERTS"].is<bool>()) settings.loraIpAlerts = doc["LORA_IP_ALERTS"].as<bool>();

      // LoRa radio parameters
      if (doc["LORA_FREQ"].is<float>()) settings.loraFreq = doc["LORA_FREQ"].as<float>();
      if (doc["LORA_FREQ"].is<double>()) settings.loraFreq = (float)doc["LORA_FREQ"].as<double>();
      if (doc["LORA_FREQ"].is<String>()) settings.loraFreq = doc["LORA_FREQ"].as<String>().toFloat();

      if (doc["LORA_BANDWIDTH"].is<float>()) settings.loraBandwidth = doc["LORA_BANDWIDTH"].as<float>();
      if (doc["LORA_BANDWIDTH"].is<double>()) settings.loraBandwidth = (float)doc["LORA_BANDWIDTH"].as<double>();
      if (doc["LORA_BANDWIDTH"].is<String>()) settings.loraBandwidth = doc["LORA_BANDWIDTH"].as<String>().toFloat();

      if (doc["LORA_SPREADING_FACTOR"].is<int>()) settings.loraSpreadingFactor = doc["LORA_SPREADING_FACTOR"].as<int>();
      if (doc["LORA_SPREADING_FACTOR"].is<String>()) settings.loraSpreadingFactor = doc["LORA_SPREADING_FACTOR"].as<String>().toInt();

      if (doc["LORA_CODING_RATE"].is<int>()) settings.loraCodingRate = doc["LORA_CODING_RATE"].as<int>();
      if (doc["LORA_CODING_RATE"].is<String>()) settings.loraCodingRate = doc["LORA_CODING_RATE"].as<String>().toInt();

      if (doc["NTFY_SERVER"].is<String>()) settings.ntfyServer = doc["NTFY_SERVER"].as<String>();
      if (doc["NTFY_TOPIC"].is<String>()) settings.ntfyTopic = doc["NTFY_TOPIC"].as<String>();
      if (doc["NTFY_USERNAME"].is<String>()) settings.ntfyUsername = doc["NTFY_USERNAME"].as<String>();
      if (doc["NTFY_PASSWORD"].is<String>()) {
        String v = doc["NTFY_PASSWORD"].as<String>();
        if (v.length() > 0) settings.ntfyPassword = v;
      }
      if (doc["NTFY_TOKEN"].is<String>()) {
        String v = doc["NTFY_TOKEN"].as<String>();
        if (v.length() > 0) settings.ntfyToken = v;
      }

      if (doc["DISCORD_WEBHOOK_URL"].is<String>()) {
        String v = doc["DISCORD_WEBHOOK_URL"].as<String>();
        if (v.length() > 0) settings.discordWebhookUrl = v;
      }

      if (doc["WEBHOOK_URL"].is<String>()) {
        String v = doc["WEBHOOK_URL"].as<String>();
        if (v.length() > 0) settings.webhookUrl = v;
      }
      if (doc["WEBHOOK_METHOD"].is<String>()) settings.webhookMethod = doc["WEBHOOK_METHOD"].as<String>();

      if (doc["SMTP_HOST"].is<String>()) settings.smtpHost = doc["SMTP_HOST"].as<String>();
      if (doc["SMTP_PORT"].is<int>()) settings.smtpPort = doc["SMTP_PORT"].as<int>();
      if (doc["SMTP_PORT"].is<String>()) settings.smtpPort = doc["SMTP_PORT"].as<String>().toInt();
      if (doc["EMAIL_RECIPIENT"].is<String>()) settings.emailRecipient = doc["EMAIL_RECIPIENT"].as<String>();
      if (doc["EMAIL_SENDER"].is<String>()) settings.emailSender = doc["EMAIL_SENDER"].as<String>();
      if (doc["SMTP_USER"].is<String>()) settings.smtpUser = doc["SMTP_USER"].as<String>();
      if (doc["SMTP_PASSWORD"].is<String>()) {
        String v = doc["SMTP_PASSWORD"].as<String>();
        if (v.length() > 0) settings.smtpPassword = v;
      }

      if (doc["MQTT_BROKER"].is<String>()) settings.mqttBroker = doc["MQTT_BROKER"].as<String>();
      if (doc["MQTT_PORT"].is<int>()) settings.mqttPort = doc["MQTT_PORT"].as<int>();
      if (doc["MQTT_PORT"].is<String>()) settings.mqttPort = doc["MQTT_PORT"].as<String>().toInt();
      if (doc["MQTT_TOPIC"].is<String>()) settings.mqttTopic = doc["MQTT_TOPIC"].as<String>();
      if (doc["MQTT_QOS"].is<int>()) settings.mqttQos = doc["MQTT_QOS"].as<int>();
      if (doc["MQTT_QOS"].is<String>()) settings.mqttQos = doc["MQTT_QOS"].as<String>().toInt();
      if (doc["MQTT_USERNAME"].is<String>()) settings.mqttUsername = doc["MQTT_USERNAME"].as<String>();
      if (doc["MQTT_PASSWORD"].is<String>()) {
        String v = doc["MQTT_PASSWORD"].as<String>();
        if (v.length() > 0) settings.mqttPassword = v;
      }

      // Booleans
      if (doc["NTFY_ENABLED"].is<bool>()) settings.ntfyEnabled = doc["NTFY_ENABLED"].as<bool>();
      if (doc["NTFY_MESH_RELAY"].is<bool>()) settings.ntfyMeshRelay = doc["NTFY_MESH_RELAY"].as<bool>();
      if (doc["NTFY_IP_ALERTS"].is<bool>()) settings.ntfyIpAlerts = doc["NTFY_IP_ALERTS"].as<bool>();
      if (doc["DISCORD_ENABLED"].is<bool>()) settings.discordEnabled = doc["DISCORD_ENABLED"].as<bool>();
      if (doc["DISCORD_MESH_RELAY"].is<bool>()) settings.discordMeshRelay = doc["DISCORD_MESH_RELAY"].as<bool>();
      if (doc["DISCORD_IP_ALERTS"].is<bool>()) settings.discordIpAlerts = doc["DISCORD_IP_ALERTS"].as<bool>();
      if (doc["WEBHOOK_ENABLED"].is<bool>()) settings.webhookEnabled = doc["WEBHOOK_ENABLED"].as<bool>();
      if (doc["WEBHOOK_MESH_RELAY"].is<bool>()) settings.webhookMeshRelay = doc["WEBHOOK_MESH_RELAY"].as<bool>();
      if (doc["WEBHOOK_IP_ALERTS"].is<bool>()) settings.webhookIpAlerts = doc["WEBHOOK_IP_ALERTS"].as<bool>();
      if (doc["EMAIL_ENABLED"].is<bool>()) settings.emailEnabled = doc["EMAIL_ENABLED"].as<bool>();
      if (doc["EMAIL_MESH_RELAY"].is<bool>()) settings.emailMeshRelay = doc["EMAIL_MESH_RELAY"].as<bool>();
      if (doc["EMAIL_IP_ALERTS"].is<bool>()) settings.emailIpAlerts = doc["EMAIL_IP_ALERTS"].as<bool>();

      if (doc["MQTT_ENABLED"].is<bool>()) settings.mqttEnabled = doc["MQTT_ENABLED"].as<bool>();
      if (doc["MQTT_MESH_RELAY"].is<bool>()) settings.mqttMeshRelay = doc["MQTT_MESH_RELAY"].as<bool>();
      if (doc["MQTT_IP_ALERTS"].is<bool>()) settings.mqttIpAlerts = doc["MQTT_IP_ALERTS"].as<bool>();

      // Normalize
      if (settings.webhookMethod.length() == 0) settings.webhookMethod = "POST";

      if (settings.mqttPort <= 0) settings.mqttPort = 1883;
      if (settings.mqttQos < 0) settings.mqttQos = 0;
      if (settings.mqttQos > 2) settings.mqttQos = 2;

      if (settings.loraFreq <= 0.0f) settings.loraFreq = (float)LORA_FREQ;
      if (settings.loraBandwidth <= 0.0f) settings.loraBandwidth = (float)LORA_BANDWIDTH;
      if (settings.loraSpreadingFactor <= 0) settings.loraSpreadingFactor = (int)LORA_SPREADING_FACTOR;
      if (settings.loraCodingRate <= 0) settings.loraCodingRate = (int)LORA_CODING_RATE;

      if (!saveSettingsOverrides()) {
        request->send(500, "application/json", "{\"error\":\"failed to save\"}");
        return;
      }

      // Apply changes that can be applied live (WiFi)
      bool wifiChanged = (before.wifiSsid != settings.wifiSsid) || 
                         (before.wifiPassword != settings.wifiPassword) ||
                         (before.ipMode != settings.ipMode) ||
                         (before.staticIp != settings.staticIp) ||
                         (before.staticGateway != settings.staticGateway) ||
                         (before.staticSubnet != settings.staticSubnet) ||
                         (before.dnsMode != settings.dnsMode) ||
                         (before.staticDns1 != settings.staticDns1) ||
                         (before.staticDns2 != settings.staticDns2);
      if (wifiChanged) {
        Serial.println("Settings updated: WiFi/IP/DNS changed; reconnecting...");
        setupWiFi();
      }

      bool mqttChanged = (before.mqttEnabled != settings.mqttEnabled) ||
                         (before.mqttBroker != settings.mqttBroker) ||
                         (before.mqttPort != settings.mqttPort) ||
                         (before.mqttTopic != settings.mqttTopic) ||
                         (before.mqttQos != settings.mqttQos) ||
                         (before.mqttUsername != settings.mqttUsername) ||
                         (before.mqttPassword != settings.mqttPassword);
      if (mqttChanged) {
        if (mqttClient.connected()) mqttClient.disconnect();
        mqttLastConnectAttemptMs = 0;
        applyMqttConfigFromSettings();
      }

      // LoRa settings require reboot (RadioLib init happens at boot)
      float freqDiff = settings.loraFreq - before.loraFreq;
      if (freqDiff < 0) freqDiff = -freqDiff;
      float bwDiff = settings.loraBandwidth - before.loraBandwidth;
      if (bwDiff < 0) bwDiff = -bwDiff;
      bool loraChanged = (before.loraEnabled != settings.loraEnabled) ||
                        (freqDiff > 0.0001f) ||
                        (bwDiff > 0.0001f) ||
                        (before.loraSpreadingFactor != settings.loraSpreadingFactor) ||
                        (before.loraCodingRate != settings.loraCodingRate);
      if (loraChanged) {
        Serial.println("Settings updated: LoRa settings changed; scheduling reboot...");
        pendingRestart = true;
        restartAtMs = millis() + 1500;
      }

      request->send(200, "application/json", loraChanged ? "{\"status\":\"ok\",\"rebooting\":true}" : "{\"status\":\"ok\"}");
    }
  );

  // Settings page (protected)
  server.on("/settings", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    String page = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    page += "<title>Settings</title><style>";
    page += "*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f7fafc;padding:20px;color:#2d3748}";
    page += ".container{max-width:900px;margin:0 auto}.card{background:#fff;border-radius:14px;padding:22px;box-shadow:0 8px 24px rgba(0,0,0,0.08);margin-bottom:16px}";
    page += "h1{font-size:22px;margin-bottom:10px}h2{font-size:16px;margin:18px 0 10px;color:#4a5568}";
    page += ".row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.fg{margin-bottom:12px}.lbl{display:block;font-weight:600;margin-bottom:6px;font-size:13px;color:#2d3748}";
    page += "input,select{width:100%;padding:10px 12px;border:2px solid #e2e8f0;border-radius:10px;font-size:14px}input:focus,select:focus{outline:none;border-color:#667eea}";
    page += ".btns{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}.btn{padding:10px 14px;border:none;border-radius:10px;cursor:pointer;font-weight:700}";
    page += ".primary{background:#667eea;color:#fff}.secondary{background:#e2e8f0;color:#2d3748}.hint{font-size:12px;color:#718096;margin-top:6px}";
    page += "@media(max-width:700px){.row{grid-template-columns:1fr}}";
    page += "</style></head><body><div class='container'>";
    page += "<div class='card'><h1>Settings</h1><div class='hint'>Saved settings override build-time .env defaults. Passwords/tokens are never displayed; leaving them blank keeps the existing value.</div></div>";

    page += "<div class='card'><h2>WiFi</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>SSID</label><input id='WIFI_SSID' value='" + settings.wifiSsid + "'></div>";
    page += "<div class='fg'><label class='lbl'>Password</label><input id='WIFI_PASSWORD' type='password' value='' placeholder='(unchanged)'></div>";
    page += "</div></div>";

    page += "<div class='card'><h2>IP Configuration</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>IP Mode</label><select id='IP_MODE'><option value='DHCP'" + String(settings.ipMode == "DHCP" ? " selected" : "") + ">DHCP</option><option value='STATIC'" + String(settings.ipMode == "STATIC" ? " selected" : "") + ">Static</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Static IP</label><input id='STATIC_IP' value='" + settings.staticIp + "'></div>";
    page += "<div class='fg'><label class='lbl'>Gateway</label><input id='STATIC_GATEWAY' value='" + settings.staticGateway + "'></div>";
    page += "<div class='fg'><label class='lbl'>Subnet Mask</label><input id='STATIC_SUBNET' value='" + settings.staticSubnet + "'></div>";
    page += "</div></div>";

    page += "<div class='card'><h2>DNS Configuration</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>DNS Mode</label><select id='DNS_MODE'><option value='DHCP'" + String(settings.dnsMode == "DHCP" ? " selected" : "") + ">DHCP</option><option value='STATIC'" + String(settings.dnsMode == "STATIC" ? " selected" : "") + ">Static</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Primary DNS</label><input id='STATIC_DNS1' value='" + settings.staticDns1 + "'></div>";
    page += "<div class='fg'><label class='lbl'>Secondary DNS</label><input id='STATIC_DNS2' value='" + settings.staticDns2 + "'></div>";
    page += "</div></div>";

    page += "<div class='card'><h2>Admin</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>Username</label><input id='ADMIN_USERNAME' value='" + settings.adminUsername + "'></div>";
    page += "<div class='fg'><label class='lbl'>Password</label><input id='ADMIN_PASSWORD' type='password' value='' placeholder='(unchanged)'></div>";
    page += "</div></div>";

    page += "<div class='card'><h2>LoRa / MeshCore</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>Node Name</label><input id='LORA_NODE_NAME' value='" + settings.loraNodeName + "' placeholder='(first 8 chars of public key)'></div>";
    page += "<div class='fg'><label class='lbl'>Channel Name</label><input id='CHANNEL_NAME' value='" + settings.channelName + "'></div>";
    page += "<div class='fg'><label class='lbl'>Channel Secret</label><input id='CHANNEL_SECRET' type='password' value='' placeholder='(unchanged)'></div>";
    page += "<div class='fg'><label class='lbl'>LoRa Enabled</label><select id='LORA_ENABLED'><option value='true'" + String(settings.loraEnabled ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.loraEnabled ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>IP Alerts</label><select id='LORA_IP_ALERTS'><option value='true'" + String(settings.loraIpAlerts ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.loraIpAlerts ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Frequency (MHz)</label><input id='LORA_FREQ' type='number' step='0.001' value='" + String(settings.loraFreq, 3) + "'></div>";
    page += "<div class='fg'><label class='lbl'>Bandwidth (kHz)</label><input id='LORA_BANDWIDTH' type='number' step='0.1' value='" + String(settings.loraBandwidth, 1) + "'></div>";
    page += "<div class='fg'><label class='lbl'>Spreading Factor</label><input id='LORA_SPREADING_FACTOR' type='number' min='6' max='12' step='1' value='" + String(settings.loraSpreadingFactor) + "'></div>";
    page += "<div class='fg'><label class='lbl'>Coding Rate (4/x)</label><input id='LORA_CODING_RATE' type='number' min='5' max='8' step='1' value='" + String(settings.loraCodingRate) + "'></div>";
    page += "</div></div>";

    page += "<div class='card'><h2>Ntfy</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>Enabled</label><select id='NTFY_ENABLED'><option value='true'" + String(settings.ntfyEnabled ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.ntfyEnabled ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Mesh Relay</label><select id='NTFY_MESH_RELAY'><option value='true'" + String(settings.ntfyMeshRelay ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.ntfyMeshRelay ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>IP Alerts</label><select id='NTFY_IP_ALERTS'><option value='true'" + String(settings.ntfyIpAlerts ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.ntfyIpAlerts ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Server</label><input id='NTFY_SERVER' value='" + settings.ntfyServer + "'></div>";
    page += "<div class='fg'><label class='lbl'>Topic</label><input id='NTFY_TOPIC' value='" + settings.ntfyTopic + "'></div>";
    page += "<div class='fg'><label class='lbl'>Username</label><input id='NTFY_USERNAME' value='" + settings.ntfyUsername + "'></div>";
    page += "<div class='fg'><label class='lbl'>Password</label><input id='NTFY_PASSWORD' type='password' value='' placeholder='(unchanged)'></div>";
    page += "<div class='fg'><label class='lbl'>Token</label><input id='NTFY_TOKEN' type='password' value='' placeholder='(unchanged)'></div>";
    page += "</div></div>";

    page += "<div class='card'><h2>Discord</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>Enabled</label><select id='DISCORD_ENABLED'><option value='true'" + String(settings.discordEnabled ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.discordEnabled ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Mesh Relay</label><select id='DISCORD_MESH_RELAY'><option value='true'" + String(settings.discordMeshRelay ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.discordMeshRelay ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>IP Alerts</label><select id='DISCORD_IP_ALERTS'><option value='true'" + String(settings.discordIpAlerts ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.discordIpAlerts ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg' style='grid-column:1/-1'><label class='lbl'>Webhook URL</label><input id='DISCORD_WEBHOOK_URL' value='" + settings.discordWebhookUrl + "'></div>";
    page += "</div></div>";

    page += "<div class='card'><h2>Webhook</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>Enabled</label><select id='WEBHOOK_ENABLED'><option value='true'" + String(settings.webhookEnabled ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.webhookEnabled ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Mesh Relay</label><select id='WEBHOOK_MESH_RELAY'><option value='true'" + String(settings.webhookMeshRelay ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.webhookMeshRelay ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>IP Alerts</label><select id='WEBHOOK_IP_ALERTS'><option value='true'" + String(settings.webhookIpAlerts ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.webhookIpAlerts ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Method</label><select id='WEBHOOK_METHOD'><option value='POST'" + String(settings.webhookMethod == "POST" ? " selected" : "") + ">POST</option><option value='PUT'" + String(settings.webhookMethod == "PUT" ? " selected" : "") + ">PUT</option></select></div>";
    page += "<div class='fg' style='grid-column:1/-1'><label class='lbl'>URL</label><input id='WEBHOOK_URL' value='" + settings.webhookUrl + "'></div>";
    page += "</div></div>";

    page += "<div class='card'><h2>Email</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>Enabled</label><select id='EMAIL_ENABLED'><option value='true'" + String(settings.emailEnabled ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.emailEnabled ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Mesh Relay</label><select id='EMAIL_MESH_RELAY'><option value='true'" + String(settings.emailMeshRelay ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.emailMeshRelay ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>IP Alerts</label><select id='EMAIL_IP_ALERTS'><option value='true'" + String(settings.emailIpAlerts ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.emailIpAlerts ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>SMTP Host</label><input id='SMTP_HOST' value='" + settings.smtpHost + "'></div>";
    page += "<div class='fg'><label class='lbl'>SMTP Port</label><input id='SMTP_PORT' value='" + String(settings.smtpPort) + "'></div>";
    page += "<div class='fg'><label class='lbl'>Recipient</label><input id='EMAIL_RECIPIENT' value='" + settings.emailRecipient + "'></div>";
    page += "<div class='fg'><label class='lbl'>Sender</label><input id='EMAIL_SENDER' value='" + settings.emailSender + "'></div>";
    page += "<div class='fg'><label class='lbl'>SMTP User</label><input id='SMTP_USER' value='" + settings.smtpUser + "'></div>";
    page += "<div class='fg'><label class='lbl'>SMTP Password</label><input id='SMTP_PASSWORD' type='password' value='' placeholder='(unchanged)'></div>";
    page += "</div></div>";

    page += "<div class='card'><h2>MQTT</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>Enabled</label><select id='MQTT_ENABLED'><option value='true'" + String(settings.mqttEnabled ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.mqttEnabled ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Mesh Relay</label><select id='MQTT_MESH_RELAY'><option value='true'" + String(settings.mqttMeshRelay ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.mqttMeshRelay ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>IP Alerts</label><select id='MQTT_IP_ALERTS'><option value='true'" + String(settings.mqttIpAlerts ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.mqttIpAlerts ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Broker</label><input id='MQTT_BROKER' value='" + settings.mqttBroker + "'></div>";
    page += "<div class='fg'><label class='lbl'>Port</label><input id='MQTT_PORT' value='" + String(settings.mqttPort) + "'></div>";
    page += "<div class='fg'><label class='lbl'>QoS</label><select id='MQTT_QOS'><option value='0'" + String(settings.mqttQos == 0 ? " selected" : "") + ">0</option><option value='1'" + String(settings.mqttQos == 1 ? " selected" : "") + ">1</option><option value='2'" + String(settings.mqttQos == 2 ? " selected" : "") + ">2</option></select></div>";
    page += "<div class='fg' style='grid-column:1/-1'><label class='lbl'>Topic</label><input id='MQTT_TOPIC' value='" + settings.mqttTopic + "'></div>";
    page += "<div class='fg'><label class='lbl'>Username</label><input id='MQTT_USERNAME' value='" + settings.mqttUsername + "'></div>";
    page += "<div class='fg'><label class='lbl'>Password</label><input id='MQTT_PASSWORD' type='password' value='' placeholder='(unchanged)'></div>";
    page += "</div></div>";

    page += "<div class='card'><div class='btns'>";
    page += "<button class='btn primary' onclick='save()'>Save</button>";
    page += "<button class='btn secondary' onclick='location.href=\"/\"'>Back</button>";
    page += "</div><div class='hint'>WiFi changes reconnect automatically. LoRa changes reboot the device automatically.</div></div>";

    page += "</div><script>";
    page += "function val(id){return document.getElementById(id).value;}";
    page += "function boolVal(id){return document.getElementById(id).value==='true';}";
    page += "async function save(){const payload={";
    page += "WIFI_SSID:val('WIFI_SSID'),WIFI_PASSWORD:val('WIFI_PASSWORD'),";
    page += "IP_MODE:val('IP_MODE'),STATIC_IP:val('STATIC_IP'),STATIC_GATEWAY:val('STATIC_GATEWAY'),STATIC_SUBNET:val('STATIC_SUBNET'),";
    page += "DNS_MODE:val('DNS_MODE'),STATIC_DNS1:val('STATIC_DNS1'),STATIC_DNS2:val('STATIC_DNS2'),";
    page += "ADMIN_USERNAME:val('ADMIN_USERNAME'),ADMIN_PASSWORD:val('ADMIN_PASSWORD'),";
    page += "CHANNEL_NAME:val('CHANNEL_NAME'),CHANNEL_SECRET:val('CHANNEL_SECRET'),";
    page += "LORA_ENABLED:boolVal('LORA_ENABLED'),LORA_IP_ALERTS:boolVal('LORA_IP_ALERTS'),LORA_FREQ:val('LORA_FREQ'),LORA_BANDWIDTH:val('LORA_BANDWIDTH'),LORA_SPREADING_FACTOR:val('LORA_SPREADING_FACTOR'),LORA_CODING_RATE:val('LORA_CODING_RATE'),";
    page += "NTFY_ENABLED:boolVal('NTFY_ENABLED'),NTFY_MESH_RELAY:boolVal('NTFY_MESH_RELAY'),NTFY_IP_ALERTS:boolVal('NTFY_IP_ALERTS'),";
    page += "NTFY_SERVER:val('NTFY_SERVER'),NTFY_TOPIC:val('NTFY_TOPIC'),NTFY_USERNAME:val('NTFY_USERNAME'),NTFY_PASSWORD:val('NTFY_PASSWORD'),NTFY_TOKEN:val('NTFY_TOKEN'),";
    page += "DISCORD_ENABLED:boolVal('DISCORD_ENABLED'),DISCORD_MESH_RELAY:boolVal('DISCORD_MESH_RELAY'),DISCORD_IP_ALERTS:boolVal('DISCORD_IP_ALERTS'),DISCORD_WEBHOOK_URL:val('DISCORD_WEBHOOK_URL'),";
    page += "WEBHOOK_ENABLED:boolVal('WEBHOOK_ENABLED'),WEBHOOK_MESH_RELAY:boolVal('WEBHOOK_MESH_RELAY'),WEBHOOK_IP_ALERTS:boolVal('WEBHOOK_IP_ALERTS'),WEBHOOK_URL:val('WEBHOOK_URL'),WEBHOOK_METHOD:val('WEBHOOK_METHOD'),";
    page += "EMAIL_ENABLED:boolVal('EMAIL_ENABLED'),EMAIL_MESH_RELAY:boolVal('EMAIL_MESH_RELAY'),EMAIL_IP_ALERTS:boolVal('EMAIL_IP_ALERTS'),SMTP_HOST:val('SMTP_HOST'),SMTP_PORT:val('SMTP_PORT'),EMAIL_RECIPIENT:val('EMAIL_RECIPIENT'),EMAIL_SENDER:val('EMAIL_SENDER'),SMTP_USER:val('SMTP_USER'),SMTP_PASSWORD:val('SMTP_PASSWORD')";
    page += ",MQTT_ENABLED:boolVal('MQTT_ENABLED'),MQTT_MESH_RELAY:boolVal('MQTT_MESH_RELAY'),MQTT_IP_ALERTS:boolVal('MQTT_IP_ALERTS'),MQTT_BROKER:val('MQTT_BROKER'),MQTT_PORT:val('MQTT_PORT'),MQTT_TOPIC:val('MQTT_TOPIC'),MQTT_USERNAME:val('MQTT_USERNAME'),MQTT_PASSWORD:val('MQTT_PASSWORD')";
    page += ",MQTT_QOS:val('MQTT_QOS')";
    page += "};";
    page += "const res=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(payload)});";
    page += "if(res.ok){const j=await res.json().catch(()=>({}));if(j.rebooting){alert('Saved. Rebooting...');}else{alert('Saved');}}else{alert('Save failed');}";
    page += "}";
    page += "</script></body></html>";
    request->send(200, "text/html", page);
  });

  // --- Web Server Endpoints ---
  // ElegantOTA integration
  // ElegantOTA.setAuth(ADMIN_USERNAME, ADMIN_PASSWORD);  // Protect OTA with admin credentials
  // ElegantOTA.begin(&server);  // Temporarily disabled due to header conflicts

  // Status page (modern styled HTML)
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    if (captivePortalActive) {
      request->send(200, "text/html", captivePortalHtml());
      return;
    }
    bool isAuthed = isAuthenticated(request, false);
    String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>ESP32 Uptime Monitor</title>";
    html += "<style>";
    html += "*{margin:0;padding:0;box-sizing:border-box}";
    html += "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;padding:20px}";
    html += ".container{max-width:1200px;margin:0 auto}";
    html += ".header{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:16px;padding:30px;margin-bottom:20px;box-shadow:0 8px 32px rgba(0,0,0,0.1)}";
    html += "h1{color:#2d3748;font-size:28px;margin-bottom:8px}";
    html += ".subtitle{color:#718096;font-size:14px}";
    html += ".card{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:16px;padding:24px;margin-bottom:20px;box-shadow:0 8px 32px rgba(0,0,0,0.1)}";
    html += ".card-title{font-size:18px;font-weight:600;color:#2d3748;margin-bottom:16px;display:flex;align-items:center;gap:8px}";
    html += ".service-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px}";
    html += ".service-actions{display:flex;gap:4px}";
    html += ".icon-btn{background:none;border:none;cursor:pointer;font-size:16px;padding:4px 8px;border-radius:4px;transition:all 0.2s}";
    html += ".icon-btn:hover{background:#f7fafc}";
    html += ".icon-btn.delete:hover{background:#fed7d7}";
    html += ".service-info{color:#718096;font-size:12px;margin-top:8px}";
    html += ".services-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}";
    html += ".service-card{background:#fff;border-radius:12px;padding:20px;border-left:4px solid #cbd5e0;transition:all 0.3s ease;cursor:pointer}";
    html += ".service-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,0.1)}";
    html += ".service-card.up{border-left-color:#48bb78}";
    html += ".service-card.down{border-left-color:#f56565}";
    html += ".service-name{font-size:16px;font-weight:600;color:#2d3748;margin-bottom:8px}";
    html += ".service-status{display:inline-block;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}";
    html += ".status-up{background:#c6f6d5;color:#22543d}";
    html += ".status-down{background:#fed7d7;color:#742a2a}";
    html += ".service-error{color:#718096;font-size:13px;margin-top:8px;font-style:italic}";
    html += ".actions{display:flex;gap:12px;flex-wrap:wrap}";
    html += ".btn{display:inline-flex;align-items:center;gap:8px;padding:12px 24px;border-radius:8px;font-weight:500;text-decoration:none;transition:all 0.3s ease;border:none;cursor:pointer;font-size:14px}";
    html += ".btn-primary{background:#667eea;color:#fff}";
    html += ".btn-primary:hover{background:#5568d3;transform:translateY(-1px)}";
    html += ".btn-secondary{background:#fff;color:#4a5568;border:2px solid #e2e8f0}";
    html += ".btn-secondary:hover{background:#f7fafc;border-color:#cbd5e0}";
    html += ".file-input{display:none}";
    html += ".file-label{display:inline-flex;align-items:center;gap:8px;padding:12px 24px;border-radius:8px;font-weight:500;background:#fff;color:#4a5568;border:2px solid #e2e8f0;cursor:pointer;transition:all 0.3s ease;font-size:14px}";
    html += ".file-label:hover{background:#f7fafc;border-color:#cbd5e0}";
    html += ".stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:20px}";
    html += ".stat-card{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:12px;padding:20px;text-align:center}";
    html += ".stat-value{font-size:32px;font-weight:700;color:#2d3748;margin-bottom:4px}";
    html += ".stat-label{font-size:12px;color:#718096;text-transform:uppercase;letter-spacing:1px}";
    html += ".auth-row{margin-top:16px;display:flex;gap:12px;flex-wrap:wrap;align-items:center}";
    html += ".auth-form{display:flex;gap:8px;flex-wrap:wrap;align-items:center}";
    html += ".auth-form input{padding:8px 10px;border:2px solid #e2e8f0;border-radius:8px;font-size:14px}";
    html += ".auth-form input:focus{outline:none;border-color:#667eea}";
    html += ".auth-hint{color:#4a5568;font-size:14px}";
    html += ".auth-actions{display:flex;gap:10px;align-items:center}";
    html += ".refresh-btn{position:fixed;bottom:24px;right:24px;width:56px;height:56px;border-radius:50%;background:#667eea;color:#fff;border:none;cursor:pointer;box-shadow:0 4px 12px rgba(102,126,234,0.4);transition:all 0.3s ease;display:flex;align-items:center;justify-content:center;font-size:24px}";
    html += ".refresh-btn:hover{transform:scale(1.1);box-shadow:0 6px 20px rgba(102,126,234,0.6)}";
    html += "@keyframes spin{to{transform:rotate(360deg)}}";
    html += ".spinning{animation:spin 1s linear infinite}";
    html += ".modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:1000;align-items:center;justify-content:center}";
    html += ".modal.show{display:flex}";
    html += ".modal-content{background:#fff;border-radius:16px;padding:32px;max-width:600px;width:90%;max-height:90vh;overflow-y:auto}";
    html += ".modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}";
    html += ".modal-title{font-size:24px;font-weight:700;color:#2d3748}";
    html += ".close-btn{background:none;border:none;font-size:28px;cursor:pointer;color:#718096;padding:0;width:32px;height:32px;display:flex;align-items:center;justify-content:center;border-radius:4px}";
    html += ".close-btn:hover{background:#f7fafc}";
    html += ".form-group{margin-bottom:20px}";
    html += ".form-label{display:block;font-weight:600;color:#2d3748;margin-bottom:8px;font-size:14px}";
    html += ".form-input,.form-select{width:100%;padding:10px 12px;border:2px solid #e2e8f0;border-radius:8px;font-size:14px;transition:border-color 0.2s}";
    html += ".form-input:focus,.form-select:focus{outline:none;border-color:#667eea}";
    html += ".form-row{display:grid;grid-template-columns:1fr 1fr;gap:16px}";
    html += ".btn-group{display:flex;gap:12px;margin-top:24px}";
    html += ".btn-cancel{background:#e2e8f0;color:#4a5568}";
    html += ".btn-cancel:hover{background:#cbd5e0}";
    html += "@media(max-width:768px){.services-grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.form-row{grid-template-columns:1fr}.modal-content{padding:24px}}";
    html += "</style></head><body>";
    html += "<div class='container'>";
    html += "<div class='header'><h1>🚀 ESP32 Uptime Monitor</h1><div class='subtitle'>Real-time service monitoring dashboard</div><div class='subtitle' style='font-size:12px;opacity:0.85;margin-top:6px'>Build: " + String(__DATE__) + " " + String(__TIME__) + "</div>";
    html += "<div class='subtitle' style='font-size:12px;opacity:0.85;margin-top:4px'>MAC: " + macWithColons() + "</div></div>";
    
    // Stats cards
    int upCount = 0, downCount = 0;
    for (int i = 0; i < serviceCount; i++) {
      if (services[i].isUp) upCount++; else downCount++;
    }
    BatteryStats battery = getBatteryStats();
    String batteryValue = battery.valid ? String(battery.percent) + "% (" + String(battery.voltage, 2) + "V)" : "N/A";
    String batteryColor = battery.valid ? (battery.percent >= 50 ? "#48bb78" : (battery.percent >= 20 ? "#d69e2e" : "#f56565")) : "#718096";
    html += "<div class='stats'>";
    html += "<div class='stat-card'><div class='stat-value'>" + String(serviceCount) + "</div><div class='stat-label'>Total Services</div></div>";
    html += "<div class='stat-card'><div class='stat-value' style='color:#48bb78'>" + String(upCount) + "</div><div class='stat-label'>Online</div></div>";
    html += "<div class='stat-card'><div class='stat-value' style='color:#f56565'>" + String(downCount) + "</div><div class='stat-label'>Offline</div></div>";
    html += "<div class='stat-card'><div class='stat-value'>" + String(millis() / 1000 / 60) + "m</div><div class='stat-label'>Uptime</div></div>";
    html += "<div class='stat-card'><div class='stat-value' style='color:" + batteryColor + "'>" + batteryValue + "</div><div class='stat-label'>Battery</div></div>";
    html += "</div>";
    
    // Services
    html += "<div class='card'><div class='card-title'>📊 Services";
    if (isAuthed) {
      html += "<button class='btn btn-primary' onclick='showAddModal()' style='margin-left:auto'>+ Add Service</button>";
    }
    html += "</div>";
    html += "<div class='services-grid'>";
    for (int i = 0; i < serviceCount; i++) {
      String statusClass = services[i].isUp ? "up" : "down";
      String statusText = services[i].isUp ? "up" : "down";
      String statusBadgeClass = services[i].isUp ? "status-up" : "status-down";
      html += "<div class='service-card " + statusClass + "'>";
      html += "<div class='service-header'>";
      html += "<div class='service-name'>" + services[i].name + "</div>";
      html += "<div class='service-actions'>";
      html += "<button class='icon-btn' onclick='viewHistory(" + String(i) + ")' title='History'>🕒</button>";
      if (isAuthed) {
        html += "<button class='icon-btn' onclick='editService(" + String(i) + ")' title='Edit'>✏️</button>";
        html += "<button class='icon-btn delete' onclick='deleteService(" + String(i) + ")' title='Delete'>🗑️</button>";
      }
      html += "</div>";
      html += "</div>";
      html += "<span class='service-status " + statusBadgeClass + "'>" + statusText + "</span>";
      html += "<div class='service-info'>Type: " + String(services[i].type) + " | Host: " + services[i].host + "</div>";
      if (services[i].type == TYPE_PUSH) {
        String pushUrl = getPushUrl(services[i]);
        if (pushUrl.length() > 0) {
          html += "<div class='service-info'>Push URL: " + pushUrl + "</div>";
        }
      }
      if (services[i].lastError.length() > 0) {
        html += "<div class='service-error'>" + services[i].lastError + "</div>";
      }
      html += "</div>";
    }
    html += "</div></div>";
    
    // Actions
    html += "<div class='card'><div class='card-title'>⚙️ Actions</div>";
    if (!isAuthed) {
      html += "<div class='auth-row'><form id='loginForm' class='auth-form'><input type='text' name='username' placeholder='Username' autocomplete='username' required><input type='password' name='password' placeholder='Password' autocomplete='current-password' required><button class='btn btn-primary' type='submit'>Login</button></form></div>";
    }
    html += "<div class='actions'>";
    if (isAuthed) {
      html += "<a href='/export' class='btn btn-primary' download='services.json'>📥 Export Config</a>";
      html += "<form action='/import' method='post' enctype='multipart/form-data' style='display:inline'>";
      html += "<input type='file' name='file' id='fileInput' class='file-input' accept='.json' onchange='this.form.submit()'>";
      html += "<label for='fileInput' class='file-label'>📤 Import Config</label>";
      html += "</form>";
      html += "<button class='btn btn-secondary' onclick='testNotifications()'>🔔 Test Notifications</button>";
      html += "<button class='btn btn-secondary' onclick='gotoOta()'>⬆️ OTA Update</button>";
      html += "<button class='btn btn-secondary' onclick='gotoSettings()'>⚙️ Settings</button>";
      html += "<button class='btn btn-secondary' onclick='logout()'>Logout</button>";
    } else {
      html += "<div class='auth-hint'>Login to manage services, import/export configuration, trigger tests, or run OTA updates.</div>";
    }
    html += "</div></div>";
    
    html += "</div>";
    html += "<button class='refresh-btn' onclick='location.reload()' title='Refresh'>↻</button>";
    
    // Modal for add/edit
    html += "<div id='serviceModal' class='modal'><div class='modal-content'>";
    html += "<div class='modal-header'><div class='modal-title' id='modalTitle'>Add Service</div>";
    html += "<button class='close-btn' onclick='closeModal()'>×</button></div>";
    html += "<form id='serviceForm'><input type='hidden' id='serviceIndex' value='-1'><input type='hidden' id='servicePushToken' value=''>";
    html += "<div class='form-group'><label class='form-label'>Service Name</label>";
    html += "<input type='text' id='serviceName' class='form-input' required></div>";
    html += "<div class='form-row'>";
    html += "<div class='form-group'><label class='form-label'>Type</label>";
    html += "<select id='serviceType' class='form-select'>";
    html += "<option value='0'>HTTP GET</option><option value='1'>Ping</option>";
    html += "<option value='2'>SNMP GET</option><option value='3'>Port</option>";
    html += "<option value='4'>Push</option><option value='5'>Uptime</option></select></div>";
    html += "<div class='form-group'><label class='form-label'>Enabled</label>";
    html += "<select id='serviceEnabled' class='form-select'><option value='true'>Yes</option><option value='false'>No</option></select></div></div>";
    html += "<div class='form-row' data-types='1,2,3'>";
    html += "<div class='form-group' style='flex:2'><label class='form-label'>Host/IP</label>";
    html += "<input type='text' id='serviceHost' class='form-input'></div>";
    html += "<div class='form-group' style='flex:1'><label class='form-label'>Port</label>";
    html += "<input type='number' id='servicePort' class='form-input' value='80'></div></div>";
    html += "<div class='form-group' data-types='0'>";
    html += "<label class='form-label'>URL/Path</label>";
    html += "<input type='text' id='serviceUrl' class='form-input' placeholder='/api/health'></div>";
    html += "<div class='form-group' data-types='0'>";
    html += "<label class='form-label'>Expected Response</label>";
    html += "<input type='text' id='serviceExpectedResponse' class='form-input'></div>";
    html += "<div class='form-group' data-types='4'>";
    html += "<label class='form-label'>Push URL (auto-generated)</label>";
    html += "<input type='text' id='servicePushUrl' class='form-input' placeholder='Generated after saving' readonly></div>";
    html += "<div class='form-group' data-types='2'>";
    html += "<label class='form-label'>SNMP OID</label>";
    html += "<input type='text' id='serviceSnmpOid' class='form-input' placeholder='1.3.6.1...'></div>";
    html += "<div class='form-group' data-types='2'>";
    html += "<label class='form-label'>SNMP Community</label>";
    html += "<input type='text' id='serviceSnmpCommunity' class='form-input' value='public'></div>";
    html += "<div class='form-row' data-types='2'>";
    html += "<div class='form-group'><label class='form-label'>SNMP Compare</label>";
    html += "<select id='serviceSnmpCompareOp' class='form-select'><option value='0'>==</option><option value='1'>!=</option><option value='2'>> </option><option value='3'>< </option><option value='4'>>=</option><option value='5'><=</option></select></div>";
    html += "<div class='form-group'><label class='form-label'>Expected Value</label>";
    html += "<input type='text' id='serviceSnmpExpectedValue' class='form-input'></div></div>";
    html += "<div class='form-row' data-types='5'>";
    html += "<div class='form-group'><label class='form-label'>Uptime Threshold (s)</label>";
    html += "<input type='number' id='serviceUptimeThreshold' class='form-input' value='0'></div>";
    html += "<div class='form-group'><label class='form-label'>Compare</label>";
    html += "<select id='serviceUptimeCompareOp' class='form-select'><option value='0'>==</option><option value='1'>!=</option><option value='2'>> </option><option value='3'>< </option><option value='4'>>=</option><option value='5'><=</option></select></div></div>";
    html += "<div class='form-row'>";
    html += "<div class='form-group'><label class='form-label'>Check Interval (seconds)</label>";
    html += "<input type='number' id='serviceCheckInterval' class='form-input' value='60'></div>";
    html += "<div class='form-group'><label class='form-label'>Pass Threshold</label>";
    html += "<input type='number' id='servicePassThreshold' class='form-input' value='1'></div></div>";
    html += "<div class='form-group'><label class='form-label'>Fail Threshold</label>";
    html += "<input type='number' id='serviceFailThreshold' class='form-input' value='2'></div>";
    html += "<div class='btn-group'>";
    html += "<button type='submit' class='btn btn-primary' style='flex:1'>Save Service</button>";
    html += "<button type='button' class='btn btn-cancel' onclick='closeModal()'>Cancel</button></div>";
    html += "</form></div></div>";

    // Modal for history
    html += "<div id='historyModal' class='modal'><div class='modal-content'>";
    html += "<div class='modal-header'><div class='modal-title' id='historyTitle'>History</div>";
    html += "<button class='close-btn' onclick='closeHistoryModal()'>×</button></div>";
    html += "<div id='historyBody' style='white-space:pre-wrap;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:13px;line-height:1.4;color:#2d3748'></div>";
    html += "</div></div>";
    
    // JavaScript
    html += "<script>";
    html += "const services=" + getServicesJson() + ";";
    html += "const isAuthed=" + String(isAuthed ? "true" : "false") + ";";
    html += "let modalOpen=false;";
    html += "function updateFieldVisibility(type){document.querySelectorAll('[data-types]').forEach(el=>{const types=el.getAttribute('data-types').split(',');el.style.display=types.includes(String(type))?'':'none';});}";
    html += "document.getElementById('serviceType').addEventListener('change',e=>updateFieldVisibility(e.target.value));";
    html += "function setPushDetails(token){const hidden=document.getElementById('servicePushToken');const url=document.getElementById('servicePushUrl');hidden.value=token||'';if(token){url.value=location.origin+'/push/'+token;url.placeholder='';}else{url.value='';url.placeholder='Generated after saving';}}";
    html += "function showAddModal(){if(!isAuthed){alert('Login required');return;}document.getElementById('modalTitle').textContent='Add Service';";
    html += "document.getElementById('serviceForm').reset();document.getElementById('serviceIndex').value='-1';setPushDetails('');";
    html += "updateFieldVisibility(document.getElementById('serviceType').value);";
    html += "document.getElementById('serviceModal').classList.add('show');modalOpen=true;}";
    html += "function closeModal(){document.getElementById('serviceModal').classList.remove('show');modalOpen=false;}";

    html += "function closeHistoryModal(){document.getElementById('historyModal').classList.remove('show');modalOpen=false;}";

    html += "async function viewHistory(i){try{";
    html += "const svc=services[i];document.getElementById('historyTitle').textContent='History - '+(svc?.name||'Service');";
    html += "document.getElementById('historyBody').textContent='Loading...';";
    html += "document.getElementById('historyModal').classList.add('show');modalOpen=true;";
    html += "const res=await fetch('/api/service-history/'+i,{credentials:'include'});";
    html += "if(!res.ok){document.getElementById('historyBody').textContent='Failed to load history';return;}";
    html += "const txt=await res.text();";
    html += "const lines=txt.split(/\\r?\\n/).filter(l=>l.trim().length);";
    html += "if(!lines.length){document.getElementById('historyBody').textContent='No history yet';return;}";
    html += "const out=[];for(const line of lines){const parts=line.split(',');if(parts.length<2) continue;";
    html += "const t=parseInt(parts[0],10);const s=(parts[1]||'').trim();if(!t) continue;";
    html += "const when=new Date(t*1000).toLocaleString();out.push(when+' - '+(s==='U'?'UP':(s==='D'?'DOWN':s)));}";
    html += "document.getElementById('historyBody').textContent=out.join('\\n');";
    html += "}catch(e){document.getElementById('historyBody').textContent='Failed to load history';}}";
    html += "function editService(i){if(!isAuthed){alert('Login required');return;}document.getElementById('modalTitle').textContent='Edit Service';";
    html += "const s=services[i];document.getElementById('serviceIndex').value=i;";
    html += "document.getElementById('serviceName').value=s.name;";
    html += "document.getElementById('serviceType').value=s.type;";
    html += "document.getElementById('serviceEnabled').value=s.enabled?'true':'false';";
    html += "document.getElementById('serviceHost').value=s.host||'';";
    html += "document.getElementById('servicePort').value=s.port||0;";
    html += "document.getElementById('serviceUrl').value=s.url||'';";
    html += "document.getElementById('serviceExpectedResponse').value=s.expectedResponse||'';";
    html += "setPushDetails(s.pushToken||'');";
    html += "document.getElementById('serviceSnmpOid').value=s.snmpOid||'';";
    html += "document.getElementById('serviceSnmpCommunity').value=s.snmpCommunity||'';";
    html += "document.getElementById('serviceSnmpCompareOp').value=s.snmpCompareOp||0;";
    html += "document.getElementById('serviceSnmpExpectedValue').value=s.snmpExpectedValue||'';";
    html += "document.getElementById('serviceUptimeThreshold').value=s.uptimeThreshold||0;";
    html += "document.getElementById('serviceUptimeCompareOp').value=s.uptimeCompareOp||0;";
    html += "document.getElementById('serviceCheckInterval').value=s.checkInterval;";
    html += "document.getElementById('servicePassThreshold').value=s.passThreshold;";
    html += "document.getElementById('serviceFailThreshold').value=s.failThreshold;";
    html += "updateFieldVisibility(s.type);";
    html += "document.getElementById('serviceModal').classList.add('show');modalOpen=true;}";
    html += "function deleteService(i){if(!isAuthed){alert('Login required');return;}if(confirm('Delete '+services[i].name+'?')){";
    html += "fetch('/api/service/'+i,{method:'DELETE',credentials:'include'}).then(r=>r.ok?location.reload():alert('Delete failed'))}}";
    html += "document.getElementById('serviceForm').onsubmit=function(e){e.preventDefault();if(!isAuthed){alert('Login required');return;}";
    html += "const data={name:document.getElementById('serviceName').value,";
    html += "type:parseInt(document.getElementById('serviceType').value),";
    html += "enabled:document.getElementById('serviceEnabled').value==='true',";
    html += "host:document.getElementById('serviceHost').value,";
    html += "port:parseInt(document.getElementById('servicePort').value)||0,";
    html += "url:document.getElementById('serviceUrl').value,";
    html += "expectedResponse:document.getElementById('serviceExpectedResponse').value,";
    html += "pushToken:document.getElementById('servicePushToken').value,";
    html += "snmpOid:document.getElementById('serviceSnmpOid').value,";
    html += "snmpCommunity:document.getElementById('serviceSnmpCommunity').value,";
    html += "snmpCompareOp:parseInt(document.getElementById('serviceSnmpCompareOp').value)||0,";
    html += "snmpExpectedValue:document.getElementById('serviceSnmpExpectedValue').value,";
    html += "uptimeThreshold:parseInt(document.getElementById('serviceUptimeThreshold').value)||0,";
    html += "uptimeCompareOp:parseInt(document.getElementById('serviceUptimeCompareOp').value)||0,";
    html += "checkInterval:parseInt(document.getElementById('serviceCheckInterval').value),";
    html += "passThreshold:parseInt(document.getElementById('servicePassThreshold').value),";
    html += "failThreshold:parseInt(document.getElementById('serviceFailThreshold').value)};";
    html += "const idx=document.getElementById('serviceIndex').value;";
    html += "const url=idx==='-1'?'/api/service':'/api/service/'+idx;";
    html += "const method=idx==='-1'?'POST':'PUT';";
    html += "fetch(url,{method:method,headers:{'Content-Type':'application/json'},body:JSON.stringify(data),credentials:'include'})";
    html += ".then(r=>{if(r.ok){location.reload();}else{alert('Save failed');modalOpen=false;}})};";
    html += "function testNotifications(){if(!isAuthed){alert('Login required');return;}if(confirm('Send test notification on all channels?')){";
    html += "fetch('/api/test-notification',{method:'POST',credentials:'include'})";
    html += ".then(r=>r.ok?alert('Test notification sent!'):alert('Failed to send test notification'))}}";
    html += "function gotoOta(){if(!isAuthed){alert('Login required');return;}window.open('/ota','_blank');}";
    html += "function gotoSettings(){if(!isAuthed){alert('Login required');return;}window.open('/settings','_blank');}";
    html += "const loginForm=document.getElementById('loginForm');";
    html += "if(loginForm){loginForm.addEventListener('submit',async e=>{e.preventDefault();const fd=new FormData(loginForm);const res=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({username:fd.get('username'),password:fd.get('password')})});if(res.ok){location.reload();}else{alert('Invalid credentials');}});}";
    html += "function logout(){fetch('/api/logout',{method:'POST',credentials:'include'}).then(()=>location.reload());}";
    html += "setInterval(()=>{if(!modalOpen) location.reload();},30000);";
    html += "updateFieldVisibility(document.getElementById('serviceType').value);";
    html += "</script>";
    html += "</body></html>";
    request->send(200, "text/html", html);
  });

  // Captive portal save (no auth)
  server.on("/captive/save", HTTP_POST, [](AsyncWebServerRequest *request){
    String ssid = "";
    String password = "";
    if (request->hasParam("ssid", true)) ssid = request->getParam("ssid", true)->value();
    if (request->hasParam("password", true)) password = request->getParam("password", true)->value();

    ssid.trim();
    if (ssid.length() == 0) {
      request->send(400, "text/html", "<html><body>SSID is required. <a href='/'>Back</a></body></html>");
      return;
    }

    settings.wifiSsid = ssid;
    settings.wifiPassword = password;
    saveSettingsOverrides();

    // Mark that WiFi was provisioned via captive portal; we will notify after the next successful STA connect.
    writeWifiProvisionFlag(ssid);

    pendingRestart = true;
    restartAtMs = millis() + 1500;

    request->send(200, "text/html",
      "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<title>Saved</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f7fafc;padding:24px;color:#2d3748}"
      ".card{max-width:520px;margin:0 auto;background:#fff;border-radius:14px;padding:22px;box-shadow:0 8px 24px rgba(0,0,0,0.08)}"
      "</style></head><body><div class='card'><h2>Saved</h2><p>Rebooting to connect to WiFi...</p></div></body></html>");
  });

  // Common OS captive portal probe endpoints
  server.on("/generate_204", HTTP_GET, [](AsyncWebServerRequest *request){
    if (captivePortalActive) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(204);
  });
  server.on("/hotspot-detect.html", HTTP_GET, [](AsyncWebServerRequest *request){
    if (captivePortalActive) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(404);
  });
  server.on("/fwlink", HTTP_GET, [](AsyncWebServerRequest *request){
    if (captivePortalActive) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(404);
  });

  // Windows captive portal checks
  server.on("/connecttest.txt", HTTP_GET, [](AsyncWebServerRequest *request){
    if (captivePortalActive) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(404);
  });
  server.on("/ncsi.txt", HTTP_GET, [](AsyncWebServerRequest *request){
    if (captivePortalActive) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(404);
  });

  // Apple/macOS/iOS captive portal checks
  server.on("/library/test/success.html", HTTP_GET, [](AsyncWebServerRequest *request){
    if (captivePortalActive) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(404);
  });

  // Kiosk view: stats + services only, no actions/controls
  server.on("/kiosk", HTTP_GET, [](AsyncWebServerRequest *request) {
    String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>Kiosk</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:20px;}";
    html += ".container{max-width:1100px;margin:0 auto;}";
    html += ".stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px;}";
    html += ".stat{background:#1e293b;border-radius:12px;padding:16px;box-shadow:0 8px 24px rgba(0,0,0,0.2);}";
    html += ".stat .value{font-size:32px;font-weight:700;color:#f8fafc;}";
    html += ".stat .label{color:#cbd5e1;font-size:12px;text-transform:uppercase;letter-spacing:1px;}";
    html += ".services{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px;}";
    html += ".card{background:#1e293b;border-radius:12px;padding:16px;box-shadow:0 8px 24px rgba(0,0,0,0.2);border-left:4px solid #334155;}";
    html += ".card.up{border-left-color:#22c55e;} .card.down{border-left-color:#ef4444;}";
    html += ".name{font-size:16px;font-weight:700;color:#f8fafc;margin-bottom:6px;}";
    html += ".meta{color:#cbd5e1;font-size:13px;} .status-badge{display:inline-block;padding:4px 10px;border-radius:12px;font-weight:700;font-size:12px;margin-top:6px;}";
    html += ".status-up{background:#22c55e33;color:#bbf7d0;} .status-down{background:#ef444433;color:#fecdd3;}";
    html += "</style></head><body><div class='container'>";

    int upCount = 0, downCount = 0;
    for (int i = 0; i < serviceCount; i++) {
      if (services[i].isUp) upCount++; else downCount++;
    }
    BatteryStats battery = getBatteryStats();
    String batteryValue = battery.valid ? String(battery.percent) + "% (" + String(battery.voltage, 2) + "V)" : "N/A";
    String batteryColor = battery.valid ? (battery.percent >= 50 ? "#22c55e" : (battery.percent >= 20 ? "#eab308" : "#ef4444")) : "#cbd5e1";
    html += "<div class='stats'>";
    html += "<div class='stat'><div class='value'>" + String(serviceCount) + "</div><div class='label'>Total</div></div>";
    html += "<div class='stat'><div class='value' style='color:#22c55e'>" + String(upCount) + "</div><div class='label'>Online</div></div>";
    html += "<div class='stat'><div class='value' style='color:#ef4444'>" + String(downCount) + "</div><div class='label'>Offline</div></div>";
    html += "<div class='stat'><div class='value'>" + String(millis() / 1000 / 60) + "m</div><div class='label'>Uptime</div></div>";
    html += "<div class='stat'><div class='value' style='color:" + batteryColor + "'>" + batteryValue + "</div><div class='label'>Battery</div></div>";
    html += "</div>";

    html += "<div class='services'>";
    for (int i = 0; i < serviceCount; i++) {
      String statusClass = services[i].isUp ? "up" : "down";
      String badge = services[i].isUp ? "<span class='status-badge status-up'>UP</span>" : "<span class='status-badge status-down'>DOWN</span>";
      html += "<div class='card " + statusClass + "'>";
      html += "<div class='name'>" + services[i].name + "</div>";
      html += badge;
      html += "<div class='meta'>Type: " + String(services[i].type) + "</div>";
      if (services[i].host.length() > 0) {
        html += "<div class='meta'>Host: " + services[i].host + "</div>";
      }
      if (services[i].type == TYPE_HTTP_GET && services[i].url.length() > 0) {
        html += "<div class='meta'>URL: " + services[i].url + "</div>";
      }
      if (services[i].type == TYPE_PORT && services[i].port > 0) {
        html += "<div class='meta'>Port: " + String(services[i].port) + "</div>";
      }
      if (!services[i].isUp && services[i].lastError.length() > 0) {
        html += "<div class='meta'>" + services[i].lastError + "</div>";
      }
      html += "</div>";
    }
    html += "</div>";
    html += "</div><script>setInterval(()=>location.reload(),20000);</script></body></html>";
    request->send(200, "text/html", html);
  });

  server.on("/push/*", HTTP_ANY, [](AsyncWebServerRequest *request) {
    String token = request->url().substring(request->url().lastIndexOf('/') + 1);
    bool matched = false;
    for (int i = 0; i < serviceCount; i++) {
      Service& svc = services[i];
      if (svc.type == TYPE_PUSH && svc.pushToken == token) {
        matched = true;
        svc.lastPush = millis();
        svc.lastError = "Push received";
        updateServiceStatus(svc, true);
        request->send(200, "text/plain", "Push acknowledged");
        return;
      }
    }

    if (!matched) {
      request->send(404, "text/plain", "Push token not found");
    }
  });

  // Export services as JSON
  server.on("/export", HTTP_GET, [](AsyncWebServerRequest *request) {
    if (!isAuthenticated(request)) return;
    JsonDocument doc;
    JsonArray array = doc["services"].to<JsonArray>();
    for (int i = 0; i < serviceCount; i++) {
      JsonObject obj = array.add<JsonObject>();
      obj["id"] = services[i].id;
      obj["name"] = services[i].name;
      obj["type"] = services[i].type;
      obj["host"] = services[i].host;
      obj["port"] = services[i].port;
      obj["url"] = services[i].url;
      obj["expectedResponse"] = services[i].expectedResponse;
      obj["checkInterval"] = services[i].checkInterval;
      obj["passThreshold"] = services[i].passThreshold;
      obj["failThreshold"] = services[i].failThreshold;
      obj["enabled"] = services[i].enabled;
      obj["snmpOid"] = services[i].snmpOid;
      obj["snmpCommunity"] = services[i].snmpCommunity;
      obj["snmpCompareOp"] = services[i].snmpCompareOp;
      obj["snmpExpectedValue"] = services[i].snmpExpectedValue;
      obj["uptimeThreshold"] = services[i].uptimeThreshold;
      obj["uptimeCompareOp"] = services[i].uptimeCompareOp;
      obj["pushToken"] = services[i].pushToken;
    }
    String json;
    serializeJson(doc, json);
    request->send(200, "application/json", json);
  });

  // Import services from uploaded JSON
  server.on(
    "/import", 
    HTTP_POST, 
    [](AsyncWebServerRequest *request){
      if (!isAuthenticated(request)) return;
      request->send(200, "text/html", "Import complete. <a href='/'>Back</a>");
    },
    [](AsyncWebServerRequest *request, String filename, size_t index, uint8_t *data, size_t len, bool final){
      if (!isAuthenticated(request, false)) return;
      static String jsonData;
      if (index == 0) jsonData = "";
      for (size_t i = 0; i < len; i++) jsonData += (char)data[i];
      if (final) {
        JsonDocument doc;
        DeserializationError err = deserializeJson(doc, jsonData);
        if (!err && doc["services"].is<JsonArray>()) {
          JsonArray array = doc["services"].as<JsonArray>();
          serviceCount = 0;
          for (JsonObject obj : array) {
            if (serviceCount >= MAX_SERVICES) break;
            Service svc;
            svc.id = obj["id"].as<String>();
            svc.name = obj["name"].as<String>();
            svc.type = (ServiceType)obj["type"].as<int>();
            svc.host = obj["host"].as<String>();
            svc.port = obj["port"].as<int>();
            svc.url = obj["url"].as<String>();
            svc.expectedResponse = obj["expectedResponse"].as<String>();
            svc.checkInterval = obj["checkInterval"].as<int>();
            svc.passThreshold = obj["passThreshold"].as<int>();
            svc.failThreshold = obj["failThreshold"].as<int>();
            svc.enabled = obj["enabled"].as<bool>();
            svc.snmpOid = obj["snmpOid"].as<String>();
            svc.snmpCommunity = obj["snmpCommunity"].as<String>();
            svc.snmpCompareOp = (CompareOp)obj["snmpCompareOp"].as<int>();
            svc.snmpExpectedValue = obj["snmpExpectedValue"].as<String>();
            svc.uptimeThreshold = obj["uptimeThreshold"].as<int>();
            svc.uptimeCompareOp = (CompareOp)obj["uptimeCompareOp"].as<int>();
            svc.pushToken = obj["pushToken"].as<String>();
            svc.consecutivePasses = 0;
            svc.consecutiveFails = 0;
            svc.isUp = false;
            svc.hasBeenUp = false;
            svc.lastCheck = 0;
            services[serviceCount++] = svc;
          }
          saveServices();  // Persist to LittleFS
          Serial.printf("Imported %d services from JSON.\n", serviceCount);
        } else {
          Serial.println("Import failed: invalid JSON or missing 'services' array.");
        }
      }
    }
  );

  // API endpoint to add a new service
  server.on("/api/service", HTTP_POST, [](AsyncWebServerRequest *request){ if (!isAuthenticated(request)) return; }, NULL, 
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total){
      if (!isAuthenticated(request)) return;
      if (serviceCount >= MAX_SERVICES) {
        request->send(400, "text/plain", "Maximum services reached");
        return;
      }
      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, data, len);
      if (err) {
        request->send(400, "text/plain", "Invalid JSON");
        return;
      }
      Service svc;
      svc.id = "svc" + String(serviceCount + 1);
      svc.name = doc["name"].as<String>();
      svc.type = (ServiceType)doc["type"].as<int>();
      svc.enabled = doc["enabled"].as<bool>();
      svc.host = doc["host"].as<String>();
      svc.port = doc["port"].as<int>();
      svc.url = doc["url"].as<String>();
      svc.expectedResponse = doc["expectedResponse"].as<String>();
      svc.pushToken = doc["pushToken"].as<String>();
      svc.snmpOid = doc["snmpOid"].as<String>();
      svc.snmpCommunity = doc["snmpCommunity"].as<String>();
      svc.snmpCompareOp = (CompareOp)doc["snmpCompareOp"].as<int>();
      svc.snmpExpectedValue = doc["snmpExpectedValue"].as<String>();
      svc.uptimeThreshold = doc["uptimeThreshold"].as<int>();
      svc.uptimeCompareOp = (CompareOp)doc["uptimeCompareOp"].as<int>();
      svc.checkInterval = doc["checkInterval"].as<int>();
      svc.passThreshold = doc["passThreshold"].as<int>();
      svc.failThreshold = doc["failThreshold"].as<int>();
      if (svc.type == TYPE_PUSH && svc.pushToken.length() == 0) {
        svc.pushToken = generatePushToken();
      }
      svc.consecutivePasses = 0;
      svc.consecutiveFails = 0;
      svc.isUp = false;
      svc.hasBeenUp = false;
      svc.lastCheck = 0;
      svc.lastPush = 0;
      services[serviceCount++] = svc;
      saveServices();  // Persist to LittleFS
      request->send(200, "text/plain", "Service added");
  });

  // API endpoint to update a service
  server.on("/api/service/*", HTTP_PUT, [](AsyncWebServerRequest *request){ if (!isAuthenticated(request)) return; }, NULL,
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total){
      if (!isAuthenticated(request)) return;
      String url = request->url();
      int idx = url.substring(url.lastIndexOf('/') + 1).toInt();
      if (idx < 0 || idx >= serviceCount) {
        request->send(404, "text/plain", "Service not found");
        return;
      }
      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, data, len);
      if (err) {
        request->send(400, "text/plain", "Invalid JSON");
        return;
      }
      services[idx].name = doc["name"].as<String>();
      services[idx].type = (ServiceType)doc["type"].as<int>();
      services[idx].enabled = doc["enabled"].as<bool>();
      services[idx].host = doc["host"].as<String>();
      services[idx].port = doc["port"].as<int>();
      services[idx].url = doc["url"].as<String>();
      services[idx].expectedResponse = doc["expectedResponse"].as<String>();
      services[idx].pushToken = doc["pushToken"].as<String>();
      if (services[idx].type == TYPE_PUSH && services[idx].pushToken.length() == 0) {
        services[idx].pushToken = generatePushToken();
      }
      services[idx].snmpOid = doc["snmpOid"].as<String>();
      services[idx].snmpCommunity = doc["snmpCommunity"].as<String>();
      services[idx].snmpCompareOp = (CompareOp)doc["snmpCompareOp"].as<int>();
      services[idx].snmpExpectedValue = doc["snmpExpectedValue"].as<String>();
      services[idx].uptimeThreshold = doc["uptimeThreshold"].as<int>();
      services[idx].uptimeCompareOp = (CompareOp)doc["uptimeCompareOp"].as<int>();
      services[idx].checkInterval = doc["checkInterval"].as<int>();
      services[idx].passThreshold = doc["passThreshold"].as<int>();
      services[idx].failThreshold = doc["failThreshold"].as<int>();
      saveServices();  // Persist to LittleFS
      request->send(200, "text/plain", "Service updated");
  });

  // API endpoint to delete a service
  server.on("/api/service/*", HTTP_DELETE, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    String url = request->url();
    int idx = url.substring(url.lastIndexOf('/') + 1).toInt();
    if (idx < 0 || idx >= serviceCount) {
      request->send(404, "text/plain", "Service not found");
      return;
    }

    String deletedId = services[idx].id;
    // Shift services array
    for (int i = idx; i < serviceCount - 1; i++) {
      services[i] = services[i + 1];
    }
    serviceCount--;
    deleteServiceHistory(deletedId);
    saveServices();  // Persist to LittleFS
    request->send(200, "text/plain", "Service deleted");
  });

  // API endpoint to fetch a service's up/down history
  server.on("/api/service-history/*", HTTP_GET, [](AsyncWebServerRequest *request){
    String url = request->url();
    int idx = url.substring(url.lastIndexOf('/') + 1).toInt();
    if (idx < 0 || idx >= serviceCount) {
      request->send(404, "text/plain", "Not found");
      return;
    }

    String path = historyFileForServiceId(services[idx].id);
    if (!LittleFS.exists(path)) {
      AsyncWebServerResponse *resp = request->beginResponse(200, "text/plain", "");
      resp->addHeader("Cache-Control", "no-store");
      request->send(resp);
      return;
    }

    File f = LittleFS.open(path, "r");
    if (!f) {
      request->send(500, "text/plain", "Failed to open");
      return;
    }

    AsyncResponseStream *response = request->beginResponseStream("text/plain");
    response->addHeader("Cache-Control", "no-store");
    uint8_t buf[512];
    while (f.available()) {
      size_t n = f.read(buf, sizeof(buf));
      if (n == 0) break;
      response->write(buf, n);
    }
    f.close();
    request->send(response);
  });

  // API endpoint to test notifications
  server.on("/api/test-notification", HTTP_POST, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    const String testMsg = "This is a test notification from ESP32 Monitor";
    sendLoRaNotification("Test", true, testMsg);
    fanOutInternetNotificationsWithId(testMsg);

    request->send(200, "text/plain", "Test notification triggered on enabled channels");
  });

  // OTA update page (protected)
  server.on("/ota", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    String page = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    page += "<title>OTA Update</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f7fafc;padding:24px;color:#2d3748;}";
    page += ".card{max-width:520px;margin:0 auto;background:#fff;border-radius:12px;padding:24px;box-shadow:0 8px 24px rgba(0,0,0,0.08);}";
    page += "h1{margin:0 0 12px;font-size:24px;}p{margin:0 0 16px;color:#4a5568;}.warn{color:#e53e3e;font-size:14px;margin-bottom:16px;}";
    page += "input[type=file]{width:100%;padding:12px;border:2px dashed #cbd5e0;border-radius:10px;background:#f8fafc;cursor:pointer;margin-bottom:16px;}";
    page += "button{padding:12px 18px;border:none;border-radius:8px;background:#667eea;color:#fff;font-weight:600;cursor:pointer;}";
    page += "button:disabled{opacity:0.6;cursor:not-allowed;}";
    page += "#status{margin-top:12px;font-weight:600;}.progress-bar{width:100%;height:8px;background:#e2e8f0;border-radius:4px;margin:12px 0;overflow:hidden;}";
    page += ".progress-fill{height:100%;background:#667eea;width:0;transition:width 0.3s;}";
    page += "</style></head><body><div class='card'><h1>OTA Firmware Update</h1><p>Select a .bin file to upload and flash. Device will reboot after a successful update.</p>";
    page += "<p class='warn'>⚠️ Do not close this page or disconnect power during upload.</p>";
    page += "<input type='file' id='file' accept='.bin,.bin.gz'><div id='fileSize'></div>";
    page += "<button id='uploadBtn'>Upload & Flash</button><div class='progress-bar'><div id='progressFill' class='progress-fill'></div></div><div id='status'></div>";
    page += "<script>const btn=document.getElementById('uploadBtn');const fileInput=document.getElementById('file');const statusEl=document.getElementById('status');const progressFill=document.getElementById('progressFill');const fileSizeEl=document.getElementById('fileSize');";
    page += "fileInput.onchange=()=>{const f=fileInput.files[0];if(f){fileSizeEl.textContent='File: '+f.name+' ('+(f.size/1024).toFixed(1)+' KB)';fileSizeEl.style.color='#4a5568';fileSizeEl.style.fontSize='14px';}};";
    page += "btn.onclick=async()=>{if(!fileInput.files.length){alert('Choose a firmware file');return;}const file=fileInput.files[0];if(file.size>2*1024*1024){if(!confirm('File is larger than 2MB. Upload may take several minutes. Continue?'))return;}";
    page += "btn.disabled=true;statusEl.textContent='Preparing upload...';progressFill.style.width='0%';const fd=new FormData();fd.append('firmware',file);";
    page += "const xhr=new XMLHttpRequest();xhr.upload.onprogress=(e)=>{if(e.lengthComputable){const pct=Math.round(100*e.loaded/e.total);progressFill.style.width=pct+'%';statusEl.textContent='Uploading: '+pct+'%';}};";
    page += "xhr.onload=()=>{if(xhr.status===200){statusEl.textContent='✓ '+xhr.responseText+' Rebooting...';statusEl.style.color='#48bb78';setTimeout(()=>location.href='/',5000);}else{statusEl.textContent='✗ Upload failed: '+xhr.responseText;statusEl.style.color='#e53e3e';btn.disabled=false;progressFill.style.width='0%';}};";
    page += "xhr.onerror=()=>{statusEl.textContent='✗ Connection error during upload';statusEl.style.color='#e53e3e';btn.disabled=false;progressFill.style.width='0%';};";
    page += "xhr.ontimeout=()=>{statusEl.textContent='✗ Upload timeout (file too large or device busy)';statusEl.style.color='#e53e3e';btn.disabled=false;progressFill.style.width='0%';};";
    page += "xhr.open('POST','/ota/upload');xhr.timeout=120000;xhr.send(fd);};";
    page += "</script></div></body></html>";
    request->send(200, "text/html", page);
  });

  // OTA upload handler
  server.on(
    "/ota/upload",
    HTTP_POST,
    [](AsyncWebServerRequest *request){
      if (!isAuthenticated(request)) return;
      bool ok = !Update.hasError();
      if (ok) {
        Serial.println("[OTA] Update successful, rebooting...");
        request->send(200, "text/plain", "Update successful.");
        delay(500);
        ESP.restart();
      } else {
        Serial.println("[OTA] Update failed");
        Update.printError(Serial);
        request->send(500, "text/plain", "Update failed.");
      }
    },
    [](AsyncWebServerRequest *request, String filename, size_t index, uint8_t *data, size_t len, bool final){
      if (!isAuthenticated(request, false)) {
        request->send(401, "text/plain", "Authentication required");
        return;
      }
      
      if (index == 0) {
        Serial.printf("[OTA] Starting update: %s (size unknown)\n", filename.c_str());
        // Calculate maximum available space for OTA
        size_t maxSketchSpace = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
        if (!Update.begin(maxSketchSpace, U_FLASH)) {
          Serial.println("[OTA] Update.begin() failed");
          Update.printError(Serial);
          return;
        }
        Serial.println("[OTA] Update started successfully");
      }
      
      // Feed watchdog during upload
      yield();
      
      // Write firmware data
      if (len > 0) {
        size_t written = Update.write(data, len);
        if (written != len) {
          Serial.printf("[OTA] Write failed: wrote %d of %d bytes\n", written, len);
          Update.printError(Serial);
          return;
        }
        
        // Log progress every 10%
        static size_t lastProgress = 0;
        size_t progress = (index + len) * 100 / Update.size();
        if (Update.size() > 0 && progress >= lastProgress + 10) {
          Serial.printf("[OTA] Progress: %d%% (%d / %d bytes)\n", progress, index + len, Update.size());
          lastProgress = progress;
        }
      }
      
      if (final) {
        if (Update.end(true)) {
          Serial.printf("[OTA] Update complete: %d bytes written\n", index + len);
        } else {
          Serial.println("[OTA] Update.end() failed");
          Update.printError(Serial);
        }
      }
    }
  );

  // API endpoint to receive generic webhook messages and fan out to enabled channels
  server.on("/api/inbound-webhook", HTTP_POST,
    [](AsyncWebServerRequest *request) {
      // Will be handled in body callback; keep handler to satisfy AsyncWebServer signature
    },
    nullptr,
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
      // Accumulate body
      if (index == 0) {
        request->_tempObject = new String();
        static_cast<String*>(request->_tempObject)->reserve(total);
      }
      String *body = static_cast<String*>(request->_tempObject);
      body->concat((const char*)data, len);

      // Final chunk: parse and dispatch
      if (index + len == total) {
        StaticJsonDocument<512> doc;
        DeserializationError err = deserializeJson(doc, *body);
        delete body;
        request->_tempObject = nullptr;

        if (err) {
          request->send(400, "application/json", "{\"error\":\"invalid json\"}");
          return;
        }

        String message = doc["message"] | "";
        String source = doc["source"] | "webhook";
        if (message.length() == 0) {
          request->send(400, "application/json", "{\"error\":\"message required\"}");
          return;
        }

        String combined = source + ": " + message;

        sendLoRaNotification(source, true, message);

      fanOutInternetNotificationsWithId(combined);

        request->send(200, "application/json", "{\"status\":\"ok\"}");
      }
    }
  );

  server.onNotFound([](AsyncWebServerRequest *request){
    if (captivePortalActive) {
      // Redirect any unknown path to the portal page (helps trigger OS captive portal UX)
      request->redirect(String("http://") + captiveApIp.toString() + "/");
      return;
    }
    request->send(404, "text/plain", "Not found");
  });

  server.begin();
}

// ============================================
// Main Loop
// ============================================
void loop() {
  if (captivePortalActive) {
    dnsServer.processNextRequest();
  }

  if (settings.mqttEnabled) {
    ensureMqttConnected();
  }

  if (pendingRestart && millis() >= restartAtMs) {
    Serial.println("Rebooting now...");
    delay(50);
    ESP.restart();
  }

  if (settings.loraEnabled) {
    // Check for LoRa packets (all devices listen)
    String message;
    int state = radio.receive(message);
    
    if (state == RADIOLIB_ERR_NONE) {
      // Packet received successfully
      lastRssi = radio.getRSSI();
      lastSnr = radio.getSNR();
      
      Serial.print("Received packet: '");
      Serial.print(message);
      Serial.print("' RSSI: ");
      Serial.print(lastRssi);
      Serial.print(" dBm, SNR: ");
      Serial.print(lastSnr);
      Serial.println(" dB");
      
      // Handle the message
      handleLoRaMessage(message);
      
      lastMessageTime = millis();
      messageCount++;
      
      // Put radio back in receive mode
      radio.startReceive();
    } else if (state != RADIOLIB_ERR_RX_TIMEOUT) {
      // Some other error occurred
      Serial.print("LoRa receive failed, code: ");
      Serial.println(state);
    }
  }
  
  // Track and heal WiFi connectivity.
  // If the captive portal is active, avoid reconnect loops that would switch WiFi mode back to STA and kill the AP.
  if (!captivePortalActive) {
    static unsigned long lastWifiAttempt = 0;
    static unsigned long lastIpCheck = 0;
    wl_status_t wifiStatus = WiFi.status();
    bool nowConnected = (wifiStatus == WL_CONNECTED);

    if (nowConnected && !wifiConnected) {
      Serial.println("WiFi reconnected");
    } else if (!nowConnected && wifiConnected) {
      Serial.println("WiFi disconnected");
    }

    wifiConnected = nowConnected;

    if (!wifiConnected && millis() - lastWifiAttempt >= 10000) {
      Serial.println("WiFi disconnected, reconnecting...");
      setupWiFi();
      lastWifiAttempt = millis();
      wifiConnected = (WiFi.status() == WL_CONNECTED);
    }

    // Detect DHCP renewals / IP changes while connected
    if (wifiConnected && millis() - lastIpCheck >= 5000) {
      lastIpCheck = millis();
      notifyIpChangeIfNeeded(WiFi.localIP().toString(), "dhcp/renew");
    }
  } else {
    wifiConnected = false;
  }
  
  // Check all services periodically
  checkAllServices();
  
  delay(10);
}

// ============================================
// WiFi Setup
// ============================================
void setupWiFi() {
  if (captivePortalActive) {
    Serial.println("WiFi connect skipped: captive portal active");
    return;
  }

  Serial.print("Connecting to WiFi: ");
  Serial.println(settings.wifiSsid);
  
  WiFi.mode(WIFI_STA);
  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);
  
  // Configure static IP if enabled
  if (settings.ipMode == "STATIC") {
    IPAddress ip, gateway, subnet;
    if (ip.fromString(settings.staticIp) && 
        gateway.fromString(settings.staticGateway) && 
        subnet.fromString(settings.staticSubnet)) {
      Serial.println("Configuring static IP...");
      Serial.print("IP: "); Serial.println(settings.staticIp);
      Serial.print("Gateway: "); Serial.println(settings.staticGateway);
      Serial.print("Subnet: "); Serial.println(settings.staticSubnet);
      
      // Configure DNS if static DNS is enabled
      if (settings.dnsMode == "STATIC") {
        IPAddress dns1, dns2;
        if (dns1.fromString(settings.staticDns1)) {
          if (dns2.fromString(settings.staticDns2)) {
            Serial.print("DNS1: "); Serial.println(settings.staticDns1);
            Serial.print("DNS2: "); Serial.println(settings.staticDns2);
            WiFi.config(ip, gateway, subnet, dns1, dns2);
          } else {
            Serial.print("DNS1: "); Serial.println(settings.staticDns1);
            WiFi.config(ip, gateway, subnet, dns1);
          }
        } else {
          WiFi.config(ip, gateway, subnet);
        }
      } else {
        WiFi.config(ip, gateway, subnet);
      }
    } else {
      Serial.println("Invalid static IP configuration, using DHCP");
    }
  } else if (settings.dnsMode == "STATIC") {
    // DHCP for IP but static DNS
    IPAddress dns1, dns2;
    if (dns1.fromString(settings.staticDns1)) {
      if (dns2.fromString(settings.staticDns2)) {
        Serial.print("Static DNS1: "); Serial.println(settings.staticDns1);
        Serial.print("Static DNS2: "); Serial.println(settings.staticDns2);
        WiFi.config(INADDR_NONE, INADDR_NONE, INADDR_NONE, dns1, dns2);
      } else {
        Serial.print("Static DNS1: "); Serial.println(settings.staticDns1);
        WiFi.config(INADDR_NONE, INADDR_NONE, INADDR_NONE, dns1);
      }
    }
  }
  
  WiFi.begin(settings.wifiSsid.c_str(), settings.wifiPassword.c_str());
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    Serial.println("\nWiFi connected!");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());

    // Notify if the IP differs from the persisted value.
    notifyIpChangeIfNeeded(WiFi.localIP().toString(), "reconnect");

    // If WiFi was provisioned via captive portal, send a one-time notification with device details.
    String provisionedSsid;
    if (consumeWifiProvisionFlag(provisionedSsid)) {
      String mac = macWithColons();
      String ip = WiFi.localIP().toString();
      String msg = "WiFi configured successfully\n";
      if (provisionedSsid.length() > 0) msg += "SSID: " + provisionedSsid + "\n";
      msg += "MAC: " + mac + "\n";
      msg += "IP: " + ip;

      Serial.println("[WiFi] Captive provisioning complete; sending notifications");

      // Internet-based notification providers
      fanOutInternetNotificationsWithId(msg);

      // Defer LoRa notification until after the radio is initialized
      pendingWifiProvisionNotify = true;
      pendingWifiProvisionNotifyMessage = msg;
    }
  } else {
    wifiConnected = false;
    Serial.println("\nWiFi connection failed!");
    startCaptivePortal();
  }
}

// ============================================
// NTP Time Sync
// ============================================
void syncNTP() {
  Serial.println("Syncing time with NTP server...");
  
  // Configure NTP: GMT offset, daylight offset, server
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  
  // Wait for time to be set
  int retries = 0;
  time_t now = time(nullptr);
  while (now < 1000000000 && retries < 20) {
    delay(500);
    now = time(nullptr);
    Serial.print(".");
    retries++;
  }
  
  if (now >= 1000000000) {
    Serial.println("\nNTP sync successful!");
    struct tm timeinfo;
    gmtime_r(&now, &timeinfo);
    Serial.printf("Current time: %04d-%02d-%02d %02d:%02d:%02d UTC\n",
                  timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                  timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
  } else {
    Serial.println("\nNTP sync failed, timestamps may be incorrect");
  }
}

// ============================================
// LoRa Setup
// ============================================
void setupLoRa() {
  // Initialize SPI
  SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_NSS);
  
  Serial.print("Initializing SX1262... ");
  
  // Initialize the radio with basic settings
  // Use default sync word (0x12) and preamble (8) to start
  int state = radio.begin(settings.loraFreq, settings.loraBandwidth, settings.loraSpreadingFactor, settings.loraCodingRate, 
                          0x12, 22, 8, LORA_TCXO_VOLTAGE);
  
  if (state == RADIOLIB_ERR_NONE) {
    Serial.println("success!");
  } else {
    Serial.print("failed, code ");
    Serial.println(state);
    while (true) { delay(10); }
  }
  
  // Try WITHOUT IQ inversion first to see if we receive data
  // (Transmitter might not actually be inverting despite the flag)
  Serial.println("IQ inversion: DISABLED (testing)");
  
  Serial.println("\n=== LoRa Configuration ===");
  Serial.print("Frequency: ");
  Serial.print(settings.loraFreq);
  Serial.println(" MHz");
  Serial.print("Spreading Factor: SF");
  Serial.println(settings.loraSpreadingFactor);
  Serial.print("Bandwidth: ");
  Serial.print(settings.loraBandwidth);
  Serial.println(" kHz");
  Serial.print("Coding Rate: 4/");
  Serial.println(settings.loraCodingRate);
  Serial.print("Channel: ");
  Serial.println(settings.channelName);
  Serial.println("========================\n");
  
  // Start listening for packets (all devices listen and can transmit)
  state = radio.startReceive();
  if (state != RADIOLIB_ERR_NONE) {
    Serial.print("Failed to start receive mode, code ");
    Serial.println(state);
  } else {
    Serial.println("Radio in receive mode, listening for packets...");
    Serial.println("Device can also transmit notifications when services change state");
  }
}

// ============================================
// Handle LoRa Message
// ============================================
void handleLoRaMessage(String message) {
  Serial.println("\n=== Processing MeshCore Packet ===");
  Serial.printf("Packet length: %d bytes\n", message.length());
  
  if (message.length() < 4) {
    Serial.println("Packet too short");
    return;
  }
  
  // Parse MeshCore packet header
  uint8_t header = (uint8_t)message[0];
  uint8_t routeType = header & 0x03;
  uint8_t payloadType = (header >> 2) & 0x0F;
  uint8_t version = (header >> 6) & 0x03;
  uint8_t pathLen = (uint8_t)message[1];
  
  Serial.printf("Header: route=%d, payload=%d, version=%d, pathLen=%d\n", 
                routeType, payloadType, version, pathLen);
  
  // We only handle PAYLOAD_TYPE_GRP_TXT (0x04)
  if (payloadType != PAYLOAD_TYPE_GRP_TXT) {
    Serial.printf("Unsupported payload type: %d\n", payloadType);
    return;
  }
  
  // Skip path (pathLen is in bytes)
  size_t idx = 2 + pathLen;
  if (idx >= message.length()) {
    Serial.println("Packet too short for payload");
    return;
  }
  
  // Get channel hash
  uint8_t receivedHash = (uint8_t)message[idx++];
  Serial.printf("Received channel hash: 0x%02X\n", receivedHash);
  
  // Derive our channel hash and secret
  uint8_t channelHash;
  uint8_t channelKey[32];
  size_t channelKeyLen;
  deriveChannelKey(settings.channelName.c_str(), settings.channelSecret.c_str(), &channelHash, channelKey, &channelKeyLen);
  
  Serial.printf("Expected channel hash: 0x%02X\n", channelHash);
  
  if (receivedHash != channelHash) {
    Serial.println("Channel hash mismatch - wrong channel");
    return;
  }
  
  Serial.println("Channel hash matched!");
  
  // Remaining data is MAC + ciphertext
  size_t encryptedLen = message.length() - idx;
  Serial.printf("Encrypted payload length: %d bytes\n", encryptedLen);
  
  // Minimum: 2 bytes MAC + 16 bytes ciphertext (one AES block)
  if (encryptedLen < CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE) {
    Serial.printf("Packet too short for valid encrypted message (need at least %d bytes, got %d)\n", 
                  CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE, encryptedLen);
    Serial.println("This may be a different packet type or corrupted packet");
    return;
  }
  
  uint8_t* encrypted = (uint8_t*)message.c_str() + idx;
  uint8_t decrypted[256];
  
  // Decrypt and verify MAC
  size_t decryptedLen = verifyAndDecrypt(channelKey, channelKeyLen, decrypted, encrypted, encryptedLen);
  
  if (decryptedLen == 0) {
    Serial.println("Decryption or MAC verification failed");
    Serial.println("This could mean:");
    Serial.println("  - Packet is not from this channel");
    Serial.println("  - Sender is using a different CHANNEL_SECRET");
    Serial.println("  - Packet was corrupted during transmission");
    return;
  }
  
  Serial.printf("Decrypted %d bytes successfully\n", decryptedLen);
  
  // Parse plaintext: [timestamp(4)][txt_type(1)][text]
  if (decryptedLen < 5) {
    Serial.println("Decrypted payload too short");
    return;
  }
  
  uint32_t timestamp = decrypted[0] | (decrypted[1] << 8) | (decrypted[2] << 16) | (decrypted[3] << 24);
  uint8_t txtType = decrypted[4];
  
  Serial.printf("Timestamp: %u, Text type: %d\n", timestamp, txtType);
  
  // Extract text message (remove zero padding)
  size_t textLen = decryptedLen - 5;
  char textMessage[256];
  memcpy(textMessage, &decrypted[5], textLen);
  textMessage[textLen] = '\0';
  
  // Remove trailing zeros (padding)
  for (int i = textLen - 1; i >= 0; i--) {
    if (textMessage[i] == '\0' || textMessage[i] == ' ') {
      textMessage[i] = '\0';
    } else {
      break;
    }
  }
  
  Serial.printf("Decoded message: \"%s\"\n", textMessage);
  
  // Check if this is our own message by checking if the message starts with our node name
  String msgStr = String(textMessage);
  if (msgStr.startsWith(ourNodeName + ":")) {
    Serial.println("This is our own message, not forwarding to notification services");
    Serial.println("=== Packet Processing Complete ===\n");
    return;
  }
  
  // Also check path for our node ID to detect own messages
  if (pathLen >= 4) {
    size_t pathIdx = 2;
    for (size_t i = 0; i < pathLen; i += 4) {
      if (pathIdx + 4 <= 2 + pathLen) {
        uint32_t nodeIdInPath = ((uint8_t)message[pathIdx]) | 
                                ((uint8_t)message[pathIdx+1] << 8) |
                                ((uint8_t)message[pathIdx+2] << 16) |
                                ((uint8_t)message[pathIdx+3] << 24);
        if (nodeIdInPath == ourNodeId) {
          Serial.printf("Found our node ID (0x%08X) in path, not forwarding\n", ourNodeId);
          Serial.println("=== Packet Processing Complete ===\n");
          return;
        }
        pathIdx += 4;
      }
    }
  }
  
  Serial.println("Message from another node, forwarding to notification services");
  Serial.println("=== Packet Processing Complete ===\n");
  
  // Forward the decoded message
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected, cannot forward message");
    return;
  }
  
  String forwardMsg = String(textMessage);

  if (settings.ntfyEnabled && settings.ntfyMeshRelay) {
    forwardToNtfy(forwardMsg);
  } else if (settings.ntfyEnabled && !settings.ntfyMeshRelay) {
    Serial.println("Ntfy mesh relay disabled, skipping");
  }

  if (settings.discordEnabled && settings.discordMeshRelay) {
    forwardToDiscord(forwardMsg);
  } else if (settings.discordEnabled && !settings.discordMeshRelay) {
    Serial.println("Discord mesh relay disabled, skipping");
  }

  if (settings.webhookEnabled && settings.webhookMeshRelay) {
    forwardToWebhook(forwardMsg);
  } else if (settings.webhookEnabled && !settings.webhookMeshRelay) {
    Serial.println("Webhook mesh relay disabled, skipping");
  }

  if (settings.emailEnabled && settings.emailMeshRelay) {
    forwardToEmail(forwardMsg);
  } else if (settings.emailEnabled && !settings.emailMeshRelay) {
    Serial.println("Email mesh relay disabled, skipping");
  }

  if (settings.mqttEnabled && settings.mqttMeshRelay) {
    forwardToMqtt(forwardMsg);
  } else if (settings.mqttEnabled && !settings.mqttMeshRelay) {
    Serial.println("MQTT mesh relay disabled, skipping");
  }
}

// ============================================
// Verify Message Format (NOT USED for MeshCore packets)
// ============================================
bool verifyMessage(String message) {
  // Not used - MeshCore verification done in handleLoRaMessage
  return true;
}

// ============================================
// Forward to Ntfy
// ============================================
void forwardToNtfy(String message) {
  if (!settings.ntfyEnabled) {
    Serial.println("Ntfy disabled, skipping");
    return;
  }
  // Use deterministic MessageID for server-side de-duplication.
  String messageId = messageIdForBody(message);
  HTTPClient http;
  String url = settings.ntfyServer + "/" + settings.ntfyTopic;
  
  Serial.print("Forwarding to Ntfy: ");
  Serial.println(url);
  
  // Determine if we need secure client for HTTPS
  WiFiClientSecure secureClient;
  WiFiClient plainClient;
  bool isSecure = url.startsWith("https://");
  
  if (isSecure) {
    secureClient.setInsecure();  // Skip certificate validation
    http.begin(secureClient, url);
  } else {
    http.begin(plainClient, url);
  }
  
  // Set headers in the exact order from working code
  http.addHeader("Title", "ESP32 Uptime Alert");
  http.addHeader("Tags", "bell");
  http.addHeader("Content-Type", "text/plain");
  if (messageId.length() > 0) {
    http.addHeader("X-Message-ID", messageId);
  } else {
    http.addHeader("X-Message-ID", String(millis()));
  }
  
  // Add authentication - MUST be after begin() and headers
  String ntfyToken = settings.ntfyToken;
  String ntfyUsername = settings.ntfyUsername;
  String ntfyPassword = settings.ntfyPassword;
  
  if (ntfyToken.length() > 0) {
    // Token authentication using Bearer header
    http.addHeader("Authorization", "Bearer " + ntfyToken);
    Serial.println("Using Ntfy Bearer token authentication");
  } else if (ntfyUsername.length() > 0 && ntfyPassword.length() > 0) {
    // Username/password authentication using Basic Auth
    http.setAuthorization(ntfyUsername.c_str(), ntfyPassword.c_str());
    Serial.printf("Using Ntfy Basic Auth: user=%s\n", ntfyUsername.c_str());
  } else {
    Serial.println("WARNING: No Ntfy authentication configured!");
  }
  
  int httpResponseCode = http.POST(message);
  
  if (httpResponseCode >= 200 && httpResponseCode < 300) {
    Serial.printf("Ntfy notification sent: %d\n", httpResponseCode);
  } else {
    Serial.printf("Ntfy error: %d - %s\n", httpResponseCode, http.errorToString(httpResponseCode).c_str());
  }
  
  http.end();
}

// ============================================
// Forward to Email (Placeholder)
// ============================================
void forwardToEmail(String message) {
  // Note: ESP32 SMTP support requires additional library
  // For now, this is a placeholder that would need ESP_Mail_Client library
  Serial.println("Email forwarding not fully implemented");
  Serial.println("Would send: " + addMessageIdPrefix(message, messageIdForBody(message)));
  // TODO: Implement ESP_Mail_Client integration
}

// ============================================
// Forward to Discord
// ============================================
void forwardToDiscord(String message) {
  if (!settings.discordEnabled) {
    Serial.println("Discord disabled, skipping");
    return;
  }
  if (settings.discordWebhookUrl.length() == 0) {
    Serial.println("Discord webhook URL empty, skipping");
    return;
  }
  HTTPClient http;
  
  Serial.print("Forwarding to Discord: ");
  Serial.println(settings.discordWebhookUrl);
  
  // Create JSON payload
  JsonDocument doc;
  doc["content"] = "**ESP32 Uptime Alert**\n" + message;
  doc["username"] = "ESP32 Receiver";
  
  String payload;
  serializeJson(doc, payload);
  
  http.begin(settings.discordWebhookUrl);
  http.addHeader("Content-Type", "application/json");
  
  int httpResponseCode = http.POST(payload);
  
  if (httpResponseCode > 0) {
    Serial.print("Discord response code: ");
    Serial.println(httpResponseCode);
  } else {
    Serial.print("Discord error: ");
    Serial.println(http.errorToString(httpResponseCode));
  }
  
  http.end();
}

// ============================================
// Forward to Generic Webhook
// ============================================
void forwardToWebhook(String message) {
  if (!settings.webhookEnabled) {
    Serial.println("Webhook disabled, skipping");
    return;
  }
  if (settings.webhookUrl.length() == 0) {
    Serial.println("Webhook URL empty, skipping");
    return;
  }
  HTTPClient http;
  
  Serial.print("Forwarding to webhook: ");
  Serial.println(settings.webhookUrl);
  
  // Create JSON payload
  JsonDocument doc;
  doc["messageId"] = messageIdForBody(message);
  doc["message"] = message;
  doc["source"] = "ESP32_Uptime_Receiver";
  doc["timestamp"] = millis();
  doc["rssi"] = lastRssi;
  doc["snr"] = lastSnr;
  
  String payload;
  serializeJson(doc, payload);
  
  http.begin(settings.webhookUrl);
  http.addHeader("Content-Type", "application/json");
  
  int httpResponseCode;
  String method = settings.webhookMethod;
  method.toUpperCase();
  if (method == "POST") {
    httpResponseCode = http.POST(payload);
  } else if (method == "PUT") {
    httpResponseCode = http.PUT(payload);
  } else {
    httpResponseCode = http.POST(payload);
  }
  
  if (httpResponseCode > 0) {
    Serial.print("Webhook response code: ");
    Serial.println(httpResponseCode);
  } else {
    Serial.print("Webhook error: ");
    Serial.println(http.errorToString(httpResponseCode));
  }
  
  http.end();
}
