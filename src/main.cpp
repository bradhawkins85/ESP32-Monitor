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
#include <Curve25519.h>
#include <SHA512.h>
#include <mbedtls/bignum.h>
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
#include <lwip/etharp.h>
#include <lwip/netif.h>
#include <LittleFS.h>
#include <ESPAsyncWebServer.h>
// #include <ElegantOTA.h>  // Temporarily disabled due to header conflicts
#include <cstdlib>
#include <Update.h>
#include <HTTPUpdate.h>
#include <DNSServer.h>
#include <esp_system.h>
#include <AsyncMqttClient.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

// --- MeshCore protocol constants ---
#define CIPHER_BLOCK_SIZE 16
#define CIPHER_MAC_SIZE 2
#define PAYLOAD_TYPE_REQ 0x00
#define PAYLOAD_TYPE_RESPONSE 0x01
#define PAYLOAD_TYPE_TXT 0x02
#define PAYLOAD_TYPE_ACK 0x03
#define PAYLOAD_TYPE_ADVERT 0x04
#define PAYLOAD_TYPE_GRP_TXT 0x05
#define PAYLOAD_TYPE_GRP_DATA 0x06
#define PAYLOAD_TYPE_ANON_REQ 0x07
#define PAYLOAD_TYPE_PATH 0x08
#define TXT_TYPE_PLAIN 0x00
#define TXT_TYPE_CLI_CMD 0x01
#define TXT_TYPE_SIGNED_PLAIN 0x02
#define TXT_TYPE_CLI_DATA 0x03
#define ROUTE_TYPE_TRANSPORT_FLOOD 0x00  // flood mode + transport codes
#define ROUTE_TYPE_FLOOD 0x01            // flood mode, needs 'path' to be built up
#define ROUTE_TYPE_DIRECT 0x02           // direct route, 'path' is supplied (zero hop = direct with no path)
#define ROUTE_TYPE_TRANSPORT_DIRECT 0x03 // direct route + transport codes

// MeshCore public channel PSK (well-known, base64 "izOH6cXN6mrJ5e26oRXNcg==")
static const uint8_t MESHCORE_PUBLIC_PSK[16] = {
  0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a,
  0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72
};

// Multi-channel support: monitor public + user channel(s)
#define MAX_MESH_CHANNELS 8

struct MeshChannel {
  uint8_t hash;         // SHA256(secret)[0]
  uint8_t key[32];      // Channel encryption key
  size_t  keyLen;       // 16 or 32
  char    name[33];     // Channel name for logging
  bool    active;       // Is this channel slot in use?
};

static MeshChannel meshChannels[MAX_MESH_CHANNELS];
static int meshChannelCount = 0;

// --- Uptime Monitoring Types and Struct ---
enum ServiceType {
  TYPE_HTTP_GET,
  TYPE_PING,
  TYPE_SNMP_GET,
  TYPE_PORT,
  TYPE_PUSH,
  TYPE_UPTIME,
  TYPE_MESHCORE_NODE,
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
  // Per-service alert channel overrides (true = use this channel if globally enabled)
  bool alertLora;
  bool alertNtfy;
  bool alertDiscord;
  bool alertWebhook;
  bool alertEmail;
  bool alertMqtt;
  bool alertWol;
  String wolMacAddress;
  // MeshCore Node monitor fields (TYPE_MESHCORE_NODE)
  String meshNodePubkey;       // 64-char hex Ed25519 public key of remote node
  String meshNodePin;          // Remote command PIN for authentication
  bool meshRepeaterControl;    // Enable automated repeater threshold control
  int meshBatteryLowPct;       // Disable repeater when battery drops below this %
  int meshBatteryHighPct;      // Re-enable repeater when battery rises above this %
  // Runtime-only mesh node state (not persisted)
  int meshLastBatteryPct;
  float meshLastBatteryV;
  unsigned long meshLastResponseMs;
  bool meshRepeaterKnownState; // Last commanded repeater state
};

// ============================================
// Direct LoRa Node Configuration
// ============================================
#define MAX_DIRECT_NODES 12

struct DirectNodeConfig {
  String name;
  String pubkeyHex; // 64 hex chars (Ed25519 public key)
};

// --- Service Array and Count ---
#define MAX_SERVICES 16
Service services[MAX_SERVICES];
int serviceCount = 0;

// ============================================
// Pending MeshCore Node Check Tracking
// Correlates outgoing status requests with incoming responses by sender hash.
// ============================================
#define MAX_PENDING_MESH_CHECKS 8

struct PendingMeshNodeCheck {
  bool active;
  uint8_t senderHash;     // First byte of target node's pubkey
  int serviceIdx;         // Index into services[]
  unsigned long sentMs;   // millis() when request was sent
};

static PendingMeshNodeCheck pendingMeshChecks[MAX_PENDING_MESH_CHECKS];

static void initPendingMeshChecks() {
  for (int i = 0; i < MAX_PENDING_MESH_CHECKS; i++) {
    pendingMeshChecks[i].active = false;
  }
}

static void registerPendingMeshCheck(uint8_t senderHash, int serviceIdx) {
  // Reuse an existing slot for the same hash, or find a free one
  for (int i = 0; i < MAX_PENDING_MESH_CHECKS; i++) {
    if (pendingMeshChecks[i].active && pendingMeshChecks[i].senderHash == senderHash) {
      pendingMeshChecks[i].serviceIdx = serviceIdx;
      pendingMeshChecks[i].sentMs = millis();
      return;
    }
  }
  for (int i = 0; i < MAX_PENDING_MESH_CHECKS; i++) {
    if (!pendingMeshChecks[i].active) {
      pendingMeshChecks[i].active = true;
      pendingMeshChecks[i].senderHash = senderHash;
      pendingMeshChecks[i].serviceIdx = serviceIdx;
      pendingMeshChecks[i].sentMs = millis();
      return;
    }
  }
  // All slots full — evict oldest
  unsigned long oldest = 0xFFFFFFFF;
  int oldestIdx = 0;
  for (int i = 0; i < MAX_PENDING_MESH_CHECKS; i++) {
    if (pendingMeshChecks[i].sentMs < oldest) {
      oldest = pendingMeshChecks[i].sentMs;
      oldestIdx = i;
    }
  }
  pendingMeshChecks[oldestIdx].active = true;
  pendingMeshChecks[oldestIdx].senderHash = senderHash;
  pendingMeshChecks[oldestIdx].serviceIdx = serviceIdx;
  pendingMeshChecks[oldestIdx].sentMs = millis();
}

// Returns service index if the given hash matches an active pending check, -1 otherwise.
static int consumePendingMeshCheck(uint8_t senderHash) {
  for (int i = 0; i < MAX_PENDING_MESH_CHECKS; i++) {
    if (pendingMeshChecks[i].active && pendingMeshChecks[i].senderHash == senderHash) {
      int idx = pendingMeshChecks[i].serviceIdx;
      pendingMeshChecks[i].active = false;
      return idx;
    }
  }
  return -1;
}

// ============================================
// Peer Cache for Direct Messages
// Stores peers' Ed25519 public keys indexed by 1-byte node hash (pubkey[0])
// ============================================
struct PeerInfo {
  uint8_t hash;           // First byte of Ed25519 public key
  uint8_t altHash;        // First byte of SHA-256(public key)
  uint8_t ed25519_pub[32];
  String name;            // Optional human-readable name
  uint32_t lastAdvert;    // Unix timestamp of last advert
  uint8_t nodeType;       // MeshCore appFlags lower nibble: 0=Unknown,1=Client,2=Repeater,3=Router
  bool inUse;
};

#define MAX_PEERS 16
PeerInfo peers[MAX_PEERS];

static int upsertPeer(uint8_t hash, const uint8_t *pub, const String &name, uint32_t lastAdvert, uint8_t nodeType = 0);

// ============================================
// Advert Cache (persisted)
// ============================================
#define ADVERT_CACHE_FILE "/adverts.dat"
#define ADVERT_CACHE_MAX 32
#define ADVERT_RETENTION_SECONDS (30UL * 24UL * 60UL * 60UL)

struct AdvertCacheEntry {
  uint8_t pub[32];
  uint32_t lastAdvert;
  char name[32];
  uint8_t nodeType;       // MeshCore appFlags lower nibble
  bool inUse;
};

AdvertCacheEntry advertCache[ADVERT_CACHE_MAX];

static void clearAdvertCache() {
  for (int i = 0; i < ADVERT_CACHE_MAX; i++) {
    advertCache[i].inUse = false;
    advertCache[i].lastAdvert = 0;
    advertCache[i].name[0] = '\0';
    advertCache[i].nodeType = 0;
  }
}

static int findAdvertCacheByPub(const uint8_t* pub) {
  for (int i = 0; i < ADVERT_CACHE_MAX; i++) {
    if (advertCache[i].inUse && memcmp(advertCache[i].pub, pub, 32) == 0) return i;
  }
  return -1;
}

static void saveAdvertCache() {
  File f = LittleFS.open(ADVERT_CACHE_FILE, "w");
  if (!f) {
    Serial.println("[LoRa] Failed to open advert cache for writing");
    return;
  }

  for (int i = 0; i < ADVERT_CACHE_MAX; i++) {
    if (!advertCache[i].inUse) continue;
    f.write(advertCache[i].pub, 32);
    f.write((uint8_t*)&advertCache[i].lastAdvert, sizeof(uint32_t));
    f.write((uint8_t*)advertCache[i].name, sizeof(advertCache[i].name));
    f.write(&advertCache[i].nodeType, 1);
  }
  f.close();
}

static void loadAdvertCache() {
  clearAdvertCache();

  if (!LittleFS.exists(ADVERT_CACHE_FILE)) {
    return;
  }

  File f = LittleFS.open(ADVERT_CACHE_FILE, "r");
  if (!f) {
    Serial.println("[LoRa] Failed to open advert cache for reading");
    return;
  }

  uint32_t now = (uint32_t)time(nullptr);
  bool hasValidTime = (now >= 1000000000UL);
  size_t recordSize = 32 + sizeof(uint32_t) + 32 + 1; // pub + timestamp + name + nodeType
  size_t legacyRecordSize = 32 + sizeof(uint32_t) + 32; // old format without nodeType
  int loaded = 0;

  // Detect format: try new format first, fall back to legacy
  size_t fileSize = f.size();
  bool hasNodeType = (fileSize > 0 && (fileSize % recordSize == 0));
  size_t useRecordSize = hasNodeType ? recordSize : legacyRecordSize;

  while (f.available() >= (int)useRecordSize && loaded < ADVERT_CACHE_MAX) {
    AdvertCacheEntry entry;
    entry.inUse = true;
    entry.nodeType = 0;
    f.read(entry.pub, 32);
    f.read((uint8_t*)&entry.lastAdvert, sizeof(uint32_t));
    f.read((uint8_t*)entry.name, sizeof(entry.name));
    entry.name[sizeof(entry.name) - 1] = '\0';
    if (hasNodeType) {
      f.read(&entry.nodeType, 1);
    }

    if (hasValidTime && entry.lastAdvert > 0 && (now - entry.lastAdvert) > ADVERT_RETENTION_SECONDS) {
      continue;
    }

    advertCache[loaded] = entry;
    uint8_t peerHash = entry.pub[0];
    upsertPeer(peerHash, entry.pub, String(entry.name), entry.lastAdvert, entry.nodeType);
    loaded++;
  }

  f.close();
  Serial.printf("[LoRa] Loaded %d cached adverts\n", loaded);
}

static void updateAdvertCache(const uint8_t* pub, const String& name, uint32_t lastAdvert, uint8_t nodeType = 0) {
  int idx = findAdvertCacheByPub(pub);
  if (idx < 0) {
    for (int i = 0; i < ADVERT_CACHE_MAX; i++) {
      if (!advertCache[i].inUse) { idx = i; break; }
    }
  }
  if (idx < 0) {
    uint32_t oldest = 0xFFFFFFFF;
    int oldestIdx = -1;
    for (int i = 0; i < ADVERT_CACHE_MAX; i++) {
      if (!advertCache[i].inUse) continue;
      if (advertCache[i].lastAdvert < oldest) {
        oldest = advertCache[i].lastAdvert;
        oldestIdx = i;
      }
    }
    idx = (oldestIdx >= 0) ? oldestIdx : 0;
  }

  advertCache[idx].inUse = true;
  memcpy(advertCache[idx].pub, pub, 32);
  advertCache[idx].lastAdvert = lastAdvert;
  advertCache[idx].nodeType = nodeType;
  memset(advertCache[idx].name, 0, sizeof(advertCache[idx].name));
  size_t nameLen = name.length();
  if (nameLen >= sizeof(advertCache[idx].name)) nameLen = sizeof(advertCache[idx].name) - 1;
  memcpy(advertCache[idx].name, name.c_str(), nameLen);

  saveAdvertCache();
}

static void clearPeerCache() {
  for (int i = 0; i < MAX_PEERS; i++) {
    peers[i].inUse = false;
    peers[i].hash = 0;
    peers[i].altHash = 0;
    peers[i].name = "";
    peers[i].lastAdvert = 0;
    peers[i].nodeType = 0;
  }
}

static int findPeerIndexByHash(uint8_t hash) {
  for (int i = 0; i < MAX_PEERS; i++) {
    if (peers[i].inUse && (peers[i].hash == hash || peers[i].altHash == hash)) return i;
  }
  return -1;
}

static uint8_t computeNodeHashSha256(const uint8_t pub[32]) {
  unsigned char fullHash[32];
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha, pub, 32);
  mbedtls_sha256_finish(&sha, fullHash);
  mbedtls_sha256_free(&sha);
  return (uint8_t)fullHash[0];
}

static int upsertPeer(uint8_t hash, const uint8_t *pub, const String &name, uint32_t lastAdvert, uint8_t nodeType) {
  int idx = findPeerIndexByHash(hash);
  if (idx < 0) {
    for (int i = 0; i < MAX_PEERS; i++) {
      if (!peers[i].inUse) { idx = i; break; }
    }
  }
  if (idx < 0) return -1;
  peers[idx].hash = pub[0];
  peers[idx].altHash = computeNodeHashSha256(pub);
  memcpy(peers[idx].ed25519_pub, pub, 32);
  // Sanitize name: keep only printable ASCII (0x20-0x7E) and trim
  String clean;
  clean.reserve(name.length());
  for (unsigned int ci = 0; ci < name.length(); ci++) {
    char ch = name.charAt(ci);
    if (ch >= 0x20 && ch <= 0x7E) clean += ch;
  }
  clean.trim();
  peers[idx].name = clean;
  peers[idx].lastAdvert = lastAdvert;
  peers[idx].nodeType = nodeType;
  peers[idx].inUse = true;
  return idx;
}

static int ensurePeerFromAdvertCache(uint8_t hash) {
  for (int i = 0; i < ADVERT_CACHE_MAX; i++) {
    if (!advertCache[i].inUse) continue;
    uint8_t pubFirst = advertCache[i].pub[0];
    uint8_t pubSha = computeNodeHashSha256(advertCache[i].pub);
    if (hash == pubFirst || hash == pubSha) {
      return upsertPeer(pubFirst, advertCache[i].pub, String(advertCache[i].name), advertCache[i].lastAdvert, advertCache[i].nodeType);
    }
  }
  return -1;
}

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

// ============================================
// LoRa Message Log (LittleFS)
// Stores message events: <unix_epoch>,<dir>,<type>,<peer>,<message_preview>,<status>\n
//   dir: S=sent, R=received
//   type: D=direct, G=group, A=ack, N=notification, V=advert
//   status: ok, fail
// Budget: 10% of total LittleFS space, enforced via trimFileToSize.
// ============================================
static const char* LORA_LOG_FILE = "/lora_log.csv";

static size_t getLoraLogBudget() {
  size_t totalBytes = LittleFS.totalBytes();
  return totalBytes / 10;  // 10% of available storage
}

static const char* nodeTypeName(uint8_t t) {
  switch (t) {
    case 1: return "Client";
    case 2: return "Repeater";
    case 3: return "Router";
    default: return "Unknown";
  }
}

static void appendLoraLog(char dir, char type, const String &peer, const String &preview, bool success) {
  time_t now = time(nullptr);
  if (now < 1000000000) return;  // Time not synced

  // Sanitize preview: replace commas and newlines to keep CSV clean
  String safePreview = preview;
  safePreview.replace(",", ";");
  safePreview.replace("\n", " ");
  safePreview.replace("\r", "");
  if (safePreview.length() > 80) safePreview = safePreview.substring(0, 80);

  String safePeer = peer;
  safePeer.replace(",", ";");
  if (safePeer.length() > 32) safePeer = safePeer.substring(0, 32);

  File f = LittleFS.open(LORA_LOG_FILE, "a");
  if (!f) return;

  char line[192];
  snprintf(line, sizeof(line), "%lu,%c,%c,%s,%s,%s\n",
           (unsigned long)now, dir, type,
           safePeer.c_str(), safePreview.c_str(),
           success ? "ok" : "fail");
  f.print(line);
  f.close();

  trimFileToSize(LORA_LOG_FILE, getLoraLogBudget());
}

// --- Global Variables ---
SX1262 radio = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY);
int lastRssi = 0;
float lastSnr = 0;
bool wifiConnected = false;
static const unsigned long WIFI_CONNECT_TIMEOUT_MS = 10000;
static bool wifiAttemptInProgress = false;
static bool wifiAttemptRestoreCaptive = false;
static unsigned long wifiAttemptStartMs = 0;
unsigned long lastMessageTime = 0;
int messageCount = 0;
unsigned long lastPingTime = 0;

// Ed25519 key pair for node identity
uint8_t ed25519_private_key[32];
uint8_t ed25519_public_key[32];
bool ed25519_keys_loaded = false;
static const char* ED25519_KEY_FILE = "/ed25519_keys.bin";

// Our node hash for direct messaging (primary = pubkey[0], alternate = SHA-256(pubkey)[0])
uint8_t ourNodeHash = 0;
uint8_t ourNodeHashAlt = 0;

// Scheduled reboot (used when settings require restart)
bool pendingRestart = false;
unsigned long restartAtMs = 0;

// Auto OTA globals and forward declaration
static unsigned long autoOtaLastCheckMs = 0;
static String autoOtaLatestVersion = "";
static String autoOtaLatestUrl = "";
static String autoOtaLatestNotes = "";
static String autoOtaLastCheckStatus = "never";
static bool autoOtaUpdateInProgress = false;
static bool autoOtaApplyRequested = false;  // Flag set by web handler, consumed by loop()
static bool checkAutoOtaUpdate(bool applyIfAvailable);

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
  String hotspotPassword;
  bool showBootCredentials;

  // LoRa / MeshCore channel
  String channelName;
  String channelSecret;

  // LoRa radio parameters
  bool loraEnabled;
  bool loraIpAlerts;
  bool loraIgnorePublic;
  String loraNodeName;
  String loraCommandPin;
  float loraFreq;
  float loraBandwidth;
  int loraSpreadingFactor;
  int loraCodingRate;
  int loraAckCount;
  bool loraDirectEnabled;
  DirectNodeConfig loraDirectNodes[MAX_DIRECT_NODES];
  int loraDirectNodeCount;

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

  // Auto OTA (0=off, 1=enabled, 2=enabled-delayed)
  int autoOtaEnabled;
  String autoOtaUrl;
  int autoOtaCheckInterval;  // seconds

  // Repeater mode
  bool repeaterEnabled;
};

Settings settings;

// ============================================
// Runtime Credential Generation
// ============================================
static const char* CREDENTIALS_FILE = "/credentials.json";
static String generatedAdminPassword;
static String generatedHotspotPassword;
static String generatedLoraCommandPin;

static String generateRandomPassword(int length = 12) {
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  String result;
  result.reserve(length);
  for (int i = 0; i < length; i++) {
    uint32_t r = esp_random();
    result += charset[r % (sizeof(charset) - 1)];
  }
  return result;
}

static String generateRandomPin(int length = 4) {
  String result;
  result.reserve(length);
  for (int i = 0; i < length; i++) {
    uint32_t r = esp_random();
    result += String((char)('0' + (r % 10)));
  }
  return result;
}

static void loadOrGenerateCredentials() {
  if (LittleFS.exists(CREDENTIALS_FILE)) {
    File f = LittleFS.open(CREDENTIALS_FILE, "r");
    if (f) {
      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, f);
      f.close();
      if (!err) {
        generatedAdminPassword = doc["admin_password"] | "";
        generatedHotspotPassword = doc["hotspot_password"] | "";
        generatedLoraCommandPin = doc["lora_command_pin"] | "";
      }
    }
  }

  bool needsWrite = false;
  if (generatedAdminPassword.length() == 0) {
    generatedAdminPassword = generateRandomPassword(12);
    needsWrite = true;
    Serial.println("[Credentials] Generated new admin password");
  }
  if (generatedHotspotPassword.length() == 0) {
    generatedHotspotPassword = generateRandomPassword(12);
    needsWrite = true;
    Serial.println("[Credentials] Generated new hotspot password");
  }
  if (generatedLoraCommandPin.length() == 0) {
    generatedLoraCommandPin = generateRandomPin(4);
    needsWrite = true;
    Serial.println("[Credentials] Generated new LoRa command PIN");
  }

  if (needsWrite) {
    File f = LittleFS.open(CREDENTIALS_FILE, "w");
    if (f) {
      JsonDocument doc;
      doc["admin_password"] = generatedAdminPassword;
      doc["hotspot_password"] = generatedHotspotPassword;
      doc["lora_command_pin"] = generatedLoraCommandPin;
      serializeJson(doc, f);
      f.close();
      Serial.println("[Credentials] Saved to filesystem");
    } else {
      Serial.println("[Credentials] ERROR: Failed to write credentials file!");
    }
  } else {
    Serial.println("[Credentials] Loaded from filesystem");
  }
}

static void clearDirectNodeList(Settings &s) {
  s.loraDirectNodeCount = 0;
  for (int i = 0; i < MAX_DIRECT_NODES; i++) {
    s.loraDirectNodes[i].name = "";
    s.loraDirectNodes[i].pubkeyHex = "";
  }
}

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
  s.adminPassword = "";  // Will be set from generated credentials
  s.hotspotPassword = ""; // Will be set from generated credentials
  s.showBootCredentials = (SHOW_BOOT_CREDENTIALS != 0);

  s.channelName = String(CHANNEL_NAME);
  s.channelSecret = String(CHANNEL_SECRET);

  s.loraEnabled = (LORA_ENABLED != 0);
  s.loraIpAlerts = (LORA_IP_ALERTS != 0);
  s.loraIgnorePublic = (LORA_IGNORE_PUBLIC != 0);
  s.loraNodeName = String(LORA_NODE_NAME);
  s.loraCommandPin = "";  // Will be set from generated credentials
  s.loraFreq = (float)LORA_FREQ;
  s.loraBandwidth = (float)LORA_BANDWIDTH;
  s.loraSpreadingFactor = (int)LORA_SPREADING_FACTOR;
  s.loraCodingRate = (int)LORA_CODING_RATE;
  s.loraAckCount = 2;
  s.loraDirectEnabled = false;
  clearDirectNodeList(s);

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

  s.autoOtaEnabled = AUTO_OTA_ENABLED;  // 0=off, 1=on, 2=delayed
  s.autoOtaUrl = String(AUTO_OTA_URL);
  s.autoOtaCheckInterval = (int)AUTO_OTA_CHECK_INTERVAL;
  if (s.autoOtaCheckInterval < 60) s.autoOtaCheckInterval = 3600;

  s.repeaterEnabled = (REPEATER_ENABLED != 0);
  return s;
}

static bool normalizeHexKey(const String &input, String &out);
static bool parseHexKeyToBytes(const String &hex, uint8_t out[32]);

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
  if (doc["HOTSPOT_PASSWORD"].is<String>()) settings.hotspotPassword = doc["HOTSPOT_PASSWORD"].as<String>();
  if (doc["SHOW_BOOT_CREDENTIALS"].is<bool>()) settings.showBootCredentials = doc["SHOW_BOOT_CREDENTIALS"].as<bool>();
  if (doc["CHANNEL_NAME"].is<String>()) settings.channelName = doc["CHANNEL_NAME"].as<String>();
  if (doc["CHANNEL_SECRET"].is<String>()) settings.channelSecret = doc["CHANNEL_SECRET"].as<String>();

  // LoRa radio parameters
  if (doc["LORA_ENABLED"].is<bool>()) settings.loraEnabled = doc["LORA_ENABLED"].as<bool>();
  if (doc["LORA_NODE_NAME"].is<String>()) settings.loraNodeName = doc["LORA_NODE_NAME"].as<String>();
  if (doc["LORA_IP_ALERTS"].is<bool>()) settings.loraIpAlerts = doc["LORA_IP_ALERTS"].as<bool>();
  if (doc["LORA_IGNORE_PUBLIC"].is<bool>()) settings.loraIgnorePublic = doc["LORA_IGNORE_PUBLIC"].as<bool>();
  if (doc["LORA_COMMAND_PIN"].is<String>()) settings.loraCommandPin = doc["LORA_COMMAND_PIN"].as<String>();
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

  if (doc["LORA_ACK_COUNT"].is<int>()) settings.loraAckCount = doc["LORA_ACK_COUNT"].as<int>();
  if (doc["LORA_ACK_COUNT"].is<String>()) settings.loraAckCount = doc["LORA_ACK_COUNT"].as<String>().toInt();

  if (doc["LORA_DIRECT_ENABLED"].is<bool>()) settings.loraDirectEnabled = doc["LORA_DIRECT_ENABLED"].as<bool>();
  if (doc["LORA_DIRECT_NODES"].is<JsonArray>()) {
    JsonArray nodes = doc["LORA_DIRECT_NODES"].as<JsonArray>();
    clearDirectNodeList(settings);
    for (JsonObject obj : nodes) {
      if (settings.loraDirectNodeCount >= MAX_DIRECT_NODES) break;
      String pubkey = obj["pubkey"] | "";
      String name = obj["name"] | "";
      String normalized;
      if (!normalizeHexKey(pubkey, normalized)) {
        continue;
      }
      settings.loraDirectNodes[settings.loraDirectNodeCount].name = name;
      settings.loraDirectNodes[settings.loraDirectNodeCount].pubkeyHex = normalized;
      settings.loraDirectNodeCount++;
    }
  }

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
  if (doc["MQTT_BROKER"].is<String>()) {
    String v = doc["MQTT_BROKER"].as<String>();
    if (v.length() > 0) settings.mqttBroker = v;
  }
  if (doc["MQTT_PORT"].is<int>()) {
    int v = doc["MQTT_PORT"].as<int>();
    if (v > 0) settings.mqttPort = v;
  }
  if (doc["MQTT_PORT"].is<String>()) {
    String v = doc["MQTT_PORT"].as<String>();
    if (v.length() > 0) {
      int p = v.toInt();
      if (p > 0) settings.mqttPort = p;
    }
  }
  if (doc["MQTT_TOPIC"].is<String>()) {
    String v = doc["MQTT_TOPIC"].as<String>();
    if (v.length() > 0) settings.mqttTopic = v;
  }
  if (doc["MQTT_QOS"].is<int>()) {
    int v = doc["MQTT_QOS"].as<int>();
    if (v >= 0 && v <= 2) settings.mqttQos = v;
  }
  if (doc["MQTT_QOS"].is<String>()) {
    String v = doc["MQTT_QOS"].as<String>();
    if (v.length() > 0) {
      int q = v.toInt();
      if (q >= 0 && q <= 2) settings.mqttQos = q;
    }
  }
  if (doc["MQTT_USERNAME"].is<String>()) {
    String v = doc["MQTT_USERNAME"].as<String>();
    if (v.length() > 0) settings.mqttUsername = v;
  }
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

  // Auto OTA
  if (doc["AUTO_OTA_ENABLED"].is<int>()) settings.autoOtaEnabled = doc["AUTO_OTA_ENABLED"].as<int>();
  else if (doc["AUTO_OTA_ENABLED"].is<bool>()) settings.autoOtaEnabled = doc["AUTO_OTA_ENABLED"].as<bool>() ? 1 : 0;
  if (doc["AUTO_OTA_URL"].is<String>()) settings.autoOtaUrl = doc["AUTO_OTA_URL"].as<String>();
  if (doc["AUTO_OTA_CHECK_INTERVAL"].is<int>()) settings.autoOtaCheckInterval = doc["AUTO_OTA_CHECK_INTERVAL"].as<int>();
  if (doc["AUTO_OTA_CHECK_INTERVAL"].is<String>()) settings.autoOtaCheckInterval = doc["AUTO_OTA_CHECK_INTERVAL"].as<String>().toInt();

  // Repeater mode
  if (doc["REPEATER_ENABLED"].is<bool>()) settings.repeaterEnabled = doc["REPEATER_ENABLED"].as<bool>();

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
  doc["HOTSPOT_PASSWORD"] = settings.hotspotPassword;
  doc["SHOW_BOOT_CREDENTIALS"] = settings.showBootCredentials;
  doc["CHANNEL_NAME"] = settings.channelName;
  doc["CHANNEL_SECRET"] = settings.channelSecret;

  doc["LORA_ENABLED"] = settings.loraEnabled;
  doc["LORA_NODE_NAME"] = settings.loraNodeName;
  doc["LORA_IP_ALERTS"] = settings.loraIpAlerts;
  doc["LORA_IGNORE_PUBLIC"] = settings.loraIgnorePublic;
  doc["LORA_COMMAND_PIN"] = settings.loraCommandPin;
  doc["LORA_FREQ"] = settings.loraFreq;
  doc["LORA_BANDWIDTH"] = settings.loraBandwidth;
  doc["LORA_SPREADING_FACTOR"] = settings.loraSpreadingFactor;
  doc["LORA_CODING_RATE"] = settings.loraCodingRate;
  doc["LORA_ACK_COUNT"] = settings.loraAckCount;
  doc["LORA_DIRECT_ENABLED"] = settings.loraDirectEnabled;
  JsonArray directNodes = doc.createNestedArray("LORA_DIRECT_NODES");
  for (int i = 0; i < settings.loraDirectNodeCount; i++) {
    if (settings.loraDirectNodes[i].pubkeyHex.length() == 0) continue;
    JsonObject obj = directNodes.add<JsonObject>();
    obj["name"] = settings.loraDirectNodes[i].name;
    obj["pubkey"] = settings.loraDirectNodes[i].pubkeyHex;
  }

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

  doc["AUTO_OTA_ENABLED"] = settings.autoOtaEnabled;
  doc["AUTO_OTA_URL"] = settings.autoOtaUrl;
  doc["AUTO_OTA_CHECK_INTERVAL"] = settings.autoOtaCheckInterval;

  doc["REPEATER_ENABLED"] = settings.repeaterEnabled;

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

// --- MQTT pending message queue (survives async connect delay) ---
static const size_t MQTT_QUEUE_SIZE = 16;
static String mqttPendingQueue[MQTT_QUEUE_SIZE];
static size_t mqttQueueHead = 0;  // next write slot
static size_t mqttQueueCount = 0; // number of queued items
static SemaphoreHandle_t mqttStateMutex = nullptr;

static void ensureMqttStateMutex() {
  if (mqttStateMutex != nullptr) return;
  mqttStateMutex = xSemaphoreCreateMutex();
}

static size_t mqttQueuePush(const String &msg) {
  ensureMqttStateMutex();
  if (mqttStateMutex == nullptr) {
    Serial.println("[MQTT] Failed to allocate queue mutex");
    return mqttQueueCount;
  }
  xSemaphoreTake(mqttStateMutex, portMAX_DELAY);
  if (mqttQueueCount >= MQTT_QUEUE_SIZE) {
    // Drop oldest to make room
    mqttQueueHead = (mqttQueueHead + 1) % MQTT_QUEUE_SIZE;
    mqttQueueCount--;
    Serial.println("[MQTT] Queue full, dropped oldest message");
  }
  size_t writeSlot = (mqttQueueHead + mqttQueueCount) % MQTT_QUEUE_SIZE;
  mqttPendingQueue[writeSlot] = msg;
  mqttQueueCount++;
  size_t pending = mqttQueueCount;
  xSemaphoreGive(mqttStateMutex);
  return pending;
}

static bool mqttQueuePop(String &out) {
  ensureMqttStateMutex();
  if (mqttStateMutex == nullptr) return false;
  xSemaphoreTake(mqttStateMutex, portMAX_DELAY);
  if (mqttQueueCount == 0) {
    xSemaphoreGive(mqttStateMutex);
    return false;
  }
  out = mqttPendingQueue[mqttQueueHead];
  mqttPendingQueue[mqttQueueHead] = String(); // free memory
  mqttQueueHead = (mqttQueueHead + 1) % MQTT_QUEUE_SIZE;
  mqttQueueCount--;
  xSemaphoreGive(mqttStateMutex);
  return true;
}

static size_t mqttQueueSize() {
  ensureMqttStateMutex();
  if (mqttStateMutex == nullptr) return 0;
  xSemaphoreTake(mqttStateMutex, portMAX_DELAY);
  size_t pending = mqttQueueCount;
  xSemaphoreGive(mqttStateMutex);
  return pending;
}

static bool mqttRecentlyPublished(const String &messageId) {
  if (messageId.length() == 0) return false;
  ensureMqttStateMutex();
  if (mqttStateMutex == nullptr) return false;
  xSemaphoreTake(mqttStateMutex, portMAX_DELAY);
  for (size_t i = 0; i < MQTT_DEDUP_SIZE; i++) {
    if (mqttRecentMessageIds[i] == messageId) {
      xSemaphoreGive(mqttStateMutex);
      return true;
    }
  }
  xSemaphoreGive(mqttStateMutex);
  return false;
}

static void mqttRememberPublished(const String &messageId) {
  if (messageId.length() == 0) return;
  ensureMqttStateMutex();
  if (mqttStateMutex == nullptr) return;
  xSemaphoreTake(mqttStateMutex, portMAX_DELAY);
  mqttRecentMessageIds[mqttRecentMessageIdsHead] = messageId;
  mqttRecentMessageIdsHead = (uint8_t)((mqttRecentMessageIdsHead + 1) % MQTT_DEDUP_SIZE);
  xSemaphoreGive(mqttStateMutex);
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

// Forward declaration (defined after sha256/messageId helpers below)
static void mqttFlushQueue();

static void mqttOnConnect(bool sessionPresent) {
  (void)sessionPresent;
  mqttConnecting = false;
  Serial.println("[MQTT] Connected");
  // Flush any messages that were queued while waiting for the connection
  mqttFlushQueue();
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

// Publish a single message immediately (must already be connected)
static bool mqttPublishNow(const String &message) {
  String messageId = messageIdForBody(message);
  if (mqttRecentlyPublished(messageId)) {
    Serial.println("[MQTT] Duplicate MessageID; skipping publish");
    return true; // already sent
  }
  String payload = addMessageIdPrefix(message, messageId);
  uint16_t pid = mqttClient.publish(settings.mqttTopic.c_str(), (uint8_t)settings.mqttQos, false, payload.c_str(), payload.length());
  if (pid > 0 || settings.mqttQos == 0) {
    mqttRememberPublished(messageId);
    Serial.printf("[MQTT] Published to %s (qos=%d)\n", settings.mqttTopic.c_str(), settings.mqttQos);
    return true;
  }
  Serial.println("[MQTT] Publish failed");
  return false;
}

// Flush any queued messages (called when connection is available)
static void mqttFlushQueue() {
  if (!mqttClient.connected()) return;
  if (settings.mqttTopic.length() == 0) return;
  size_t flushed = 0;
  String msg;
  while (mqttQueuePop(msg)) {
    if (mqttPublishNow(msg)) {
      flushed++;
    }
  }
  if (flushed > 0) {
    Serial.printf("[MQTT] Flushed %zu queued message(s)\n", flushed);
  }
}

void forwardToMqtt(String message) {
  initMqttClientOnce();

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

  String messageId = messageIdForBody(message);
  if (mqttRecentlyPublished(messageId)) {
    Serial.println("[MQTT] Duplicate MessageID; skipping publish");
    return;
  }

  // Kick off a connection if needed
  ensureMqttConnected();

  if (mqttClient.connected()) {
    // Connected right now — publish immediately
    mqttPublishNow(message);
  } else {
    // Connection is pending — queue the message for delivery once connected
    size_t pending = mqttQueuePush(message);
    Serial.printf("[MQTT] Not connected yet, queued message (%zu pending)\n", pending);
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
static const unsigned long CAPTIVE_RETRY_INTERVAL_MS = 60UL * 60UL * 1000UL;
static unsigned long lastCaptiveRetryMs = 0;

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

// ============================================
// Wake-on-LAN Helpers
// ============================================

// Extract the bare IP address from a URL or host string.
// Handles "https://192.168.1.1/health", "http://10.0.0.1:8080/api", "192.168.1.1", etc.
static String extractIpFromUrl(const String &input) {
  String s = input;
  // Strip scheme
  int schemeEnd = s.indexOf("://");
  if (schemeEnd >= 0) s = s.substring(schemeEnd + 3);
  // Strip path (after host)
  int slashPos = s.indexOf('/');
  if (slashPos >= 0) s = s.substring(0, slashPos);
  // Strip port
  int colonPos = s.indexOf(':');
  if (colonPos >= 0) s = s.substring(0, colonPos);
  // Strip userinfo (user@host)
  int atPos = s.indexOf('@');
  if (atPos >= 0) s = s.substring(atPos + 1);
  s.trim();
  return s;
}

// Parse "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF" into 6-byte array.
// Returns true on success.
static bool parseMacAddress(const String &macStr, uint8_t mac[6]) {
  if (macStr.length() < 17) return false;
  char sep = macStr.charAt(2);
  if (sep != ':' && sep != '-') return false;
  for (int i = 0; i < 6; i++) {
    String octet = macStr.substring(i * 3, i * 3 + 2);
    mac[i] = (uint8_t)strtoul(octet.c_str(), NULL, 16);
  }
  return true;
}

// Format a 6-byte MAC into "AA:BB:CC:DD:EE:FF".
static String formatMacAddress(const uint8_t mac[6]) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

// Attempt to discover the MAC address for an IP via ARP.
// Sends a ping first to populate the ARP table, then queries it.
static String discoverMacFromIp(const String &ipStr) {
  IPAddress ip;
  if (!ip.fromString(ipStr)) {
    Serial.printf("[WoL] Invalid IP for MAC discovery: %s\n", ipStr.c_str());
    return "";
  }

  // Send a quick ICMP ping to populate ARP table
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock >= 0) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = (uint32_t)ip;

    uint8_t icmpPkt[8];
    memset(icmpPkt, 0, sizeof(icmpPkt));
    icmpPkt[0] = 8; // ICMP Echo Request
    icmpPkt[4] = 0x12; icmpPkt[5] = 0x34; // id
    // Checksum
    uint32_t sum = 0;
    for (int i = 0; i < 8; i += 2) sum += (icmpPkt[i] << 8) | icmpPkt[i + 1];
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    uint16_t cksum = ~sum;
    icmpPkt[2] = cksum >> 8;
    icmpPkt[3] = cksum & 0xFF;

    struct timeval tv = {1, 0}; // 1 second timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sendto(sock, icmpPkt, sizeof(icmpPkt), 0, (struct sockaddr *)&dest, sizeof(dest));

    // Wait briefly for reply (to let ARP resolve)
    uint8_t recvBuf[64];
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    recvfrom(sock, recvBuf, sizeof(recvBuf), 0, (struct sockaddr *)&from, &fromLen);
    close(sock);
  }
  delay(100); // Give ARP table time to update

  // Query the ARP table via ESP-IDF/lwIP
  ip4_addr_t lwip_ip;
  IP4_ADDR(&lwip_ip, ip[0], ip[1], ip[2], ip[3]);
  struct eth_addr *eth_ret = NULL;
  const ip4_addr_t *ip_ret = NULL;

  // Check ARP table
  if (etharp_find_addr(netif_default, &lwip_ip, &eth_ret, &ip_ret) >= 0 && eth_ret != NULL) {
    String mac = formatMacAddress(eth_ret->addr);
    Serial.printf("[WoL] Discovered MAC for %s: %s\n", ipStr.c_str(), mac.c_str());
    return mac;
  }

  Serial.printf("[WoL] Could not discover MAC for %s\n", ipStr.c_str());
  return "";
}

// Send a Wake-on-LAN magic packet to the given MAC address.
// The magic packet is 6x 0xFF followed by 16x the 6-byte MAC, sent as UDP broadcast on port 9.
static void sendWolPacket(const String &macStr) {
  uint8_t mac[6];
  if (!parseMacAddress(macStr, mac)) {
    Serial.printf("[WoL] Invalid MAC address: %s\n", macStr.c_str());
    return;
  }

  uint8_t magicPacket[102];
  // 6 bytes of 0xFF
  memset(magicPacket, 0xFF, 6);
  // 16 repetitions of the MAC address
  for (int i = 0; i < 16; i++) {
    memcpy(magicPacket + 6 + i * 6, mac, 6);
  }

  WiFiUDP udp;
  udp.begin(0);
  udp.beginPacket(IPAddress(255, 255, 255, 255), 9);
  udp.write(magicPacket, sizeof(magicPacket));
  udp.endPacket();
  udp.stop();

  Serial.printf("[WoL] Magic packet sent to %s\n", macStr.c_str());
}

// Get the best IP string for a service (used for MAC auto-discovery).
static String getServiceIp(const Service &svc) {
  // Prefer host field (Ping, SNMP, Port types)
  if (svc.host.length() > 0) {
    return extractIpFromUrl(svc.host);
  }
  // Fall back to URL field (HTTP GET type)
  if (svc.url.length() > 0) {
    return extractIpFromUrl(svc.url);
  }
  return "";
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

static void stopCaptivePortal() {
  if (!captivePortalActive) return;
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
  captivePortalActive = false;
  Serial.println("[CaptivePortal] Stopped");
}

// Returns true when WiFi SSID has been configured (not the default "Unset")
static bool isWifiConfigured() {
  return settings.wifiSsid.length() > 0 && settings.wifiSsid != "Unset";
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

  String apPass = settings.hotspotPassword;
  bool ok;
  if (apPass.length() >= 8) {
    ok = WiFi.softAP(captiveApSsid.c_str(), apPass.c_str());
  } else {
    Serial.println("[CaptivePortal] Hotspot password too short (<8). Starting open AP.");
    ok = WiFi.softAP(captiveApSsid.c_str());
  }

  if (!ok) {
    Serial.println("[CaptivePortal] Failed to start SoftAP");
    return;
  }

  dnsServer.start(53, "*", captiveApIp);
  captivePortalActive = true;
  lastCaptiveRetryMs = millis();
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
bool checkMeshNode(Service& service);
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
    // Per-service alert channel overrides
    svc["alertLora"] = services[i].alertLora;
    svc["alertNtfy"] = services[i].alertNtfy;
    svc["alertDiscord"] = services[i].alertDiscord;
    svc["alertWebhook"] = services[i].alertWebhook;
    svc["alertEmail"] = services[i].alertEmail;
    svc["alertMqtt"] = services[i].alertMqtt;
    svc["alertWol"] = services[i].alertWol;
    svc["wolMacAddress"] = services[i].wolMacAddress;
    // MeshCore Node fields
    svc["meshNodePubkey"] = services[i].meshNodePubkey;
    svc["meshNodePin"] = services[i].meshNodePin;
    svc["meshRepeaterControl"] = services[i].meshRepeaterControl;
    svc["meshBatteryLowPct"] = services[i].meshBatteryLowPct;
    svc["meshBatteryHighPct"] = services[i].meshBatteryHighPct;
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
    // Per-service alert channel overrides (default true for backward compatibility)
    services[serviceCount].alertLora = svc["alertLora"].isNull() ? true : svc["alertLora"].as<bool>();
    services[serviceCount].alertNtfy = svc["alertNtfy"].isNull() ? true : svc["alertNtfy"].as<bool>();
    services[serviceCount].alertDiscord = svc["alertDiscord"].isNull() ? true : svc["alertDiscord"].as<bool>();
    services[serviceCount].alertWebhook = svc["alertWebhook"].isNull() ? true : svc["alertWebhook"].as<bool>();
    services[serviceCount].alertEmail = svc["alertEmail"].isNull() ? true : svc["alertEmail"].as<bool>();
    services[serviceCount].alertMqtt = svc["alertMqtt"].isNull() ? true : svc["alertMqtt"].as<bool>();
    services[serviceCount].alertWol = svc["alertWol"].isNull() ? false : svc["alertWol"].as<bool>();
    services[serviceCount].wolMacAddress = svc["wolMacAddress"].isNull() ? "" : svc["wolMacAddress"].as<String>();
    // MeshCore Node fields
    services[serviceCount].meshNodePubkey = svc["meshNodePubkey"].isNull() ? "" : svc["meshNodePubkey"].as<String>();
    services[serviceCount].meshNodePin = svc["meshNodePin"].isNull() ? "" : svc["meshNodePin"].as<String>();
    services[serviceCount].meshRepeaterControl = svc["meshRepeaterControl"].isNull() ? false : svc["meshRepeaterControl"].as<bool>();
    services[serviceCount].meshBatteryLowPct = svc["meshBatteryLowPct"].isNull() ? 20 : svc["meshBatteryLowPct"].as<int>();
    services[serviceCount].meshBatteryHighPct = svc["meshBatteryHighPct"].isNull() ? 50 : svc["meshBatteryHighPct"].as<int>();
    // Runtime-only mesh node state
    services[serviceCount].meshLastBatteryPct = 0;
    services[serviceCount].meshLastBatteryV = 0.0f;
    services[serviceCount].meshLastResponseMs = 0;
    services[serviceCount].meshRepeaterKnownState = true;  // Assume repeater on until told otherwise

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
  httpSvc.alertLora = true;
  httpSvc.alertNtfy = true;
  httpSvc.alertDiscord = true;
  httpSvc.alertWebhook = true;
  httpSvc.alertEmail = true;
  httpSvc.alertMqtt = true;
  httpSvc.alertWol = false;
  httpSvc.wolMacAddress = "";
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
  pingSvc.alertLora = true;
  pingSvc.alertNtfy = true;
  pingSvc.alertDiscord = true;
  pingSvc.alertWebhook = true;
  pingSvc.alertEmail = true;
  pingSvc.alertMqtt = true;
  pingSvc.alertWol = false;
  pingSvc.wolMacAddress = "";
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
  snmpSvc.alertLora = true;
  snmpSvc.alertNtfy = true;
  snmpSvc.alertDiscord = true;
  snmpSvc.alertWebhook = true;
  snmpSvc.alertEmail = true;
  snmpSvc.alertMqtt = true;
  snmpSvc.alertWol = false;
  snmpSvc.wolMacAddress = "";
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
        case TYPE_MESHCORE_NODE:
          result = checkMeshNode(svc);
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
void setupWiFi(bool waitForConnect = true);
void setupLoRa();
void syncNTP();
void handleLoRaMessage(const uint8_t* message, size_t messageLen);
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
void initMeshChannels();
static bool deriveSharedSecretWithPeer(const uint8_t peerEd25519Pub[32], uint8_t shared[32]);
static void deriveDirectKeyFromShared(const uint8_t shared[32], uint8_t outKey[32]);
static bool normalizeHexKey(const String &input, String &out);
static bool parseHexKeyToBytes(const String &hex, uint8_t out[32]);

// Helper function to get services as JSON string
String getServicesJson() {
  DynamicJsonDocument doc(16384);
  JsonArray arr = doc.to<JsonArray>();
  for (int i = 0; i < serviceCount; i++) {
    JsonObject obj = arr.createNestedObject();
    obj["name"] = services[i].name;
    obj["type"] = services[i].type;
    obj["enabled"] = services[i].enabled;
    obj["host"] = services[i].host;
    obj["port"] = services[i].port;
    obj["url"] = services[i].url;
    obj["expectedResponse"] = services[i].expectedResponse;
    obj["pushToken"] = services[i].pushToken;
    obj["snmpOid"] = services[i].snmpOid;
    obj["snmpCommunity"] = services[i].snmpCommunity;
    obj["snmpCompareOp"] = (int)services[i].snmpCompareOp;
    obj["snmpExpectedValue"] = services[i].snmpExpectedValue;
    obj["uptimeThreshold"] = services[i].uptimeThreshold;
    obj["uptimeCompareOp"] = (int)services[i].uptimeCompareOp;
    obj["checkInterval"] = services[i].checkInterval;
    obj["passThreshold"] = services[i].passThreshold;
    obj["failThreshold"] = services[i].failThreshold;
    obj["alertLora"] = services[i].alertLora;
    obj["alertNtfy"] = services[i].alertNtfy;
    obj["alertDiscord"] = services[i].alertDiscord;
    obj["alertWebhook"] = services[i].alertWebhook;
    obj["alertEmail"] = services[i].alertEmail;
    obj["alertMqtt"] = services[i].alertMqtt;
    obj["alertWol"] = services[i].alertWol;
    obj["wolMacAddress"] = services[i].wolMacAddress;
    obj["meshNodePubkey"] = services[i].meshNodePubkey;
    obj["meshNodePin"] = services[i].meshNodePin;
    obj["meshRepeaterControl"] = services[i].meshRepeaterControl;
    obj["meshBatteryLowPct"] = services[i].meshBatteryLowPct;
    obj["meshBatteryHighPct"] = services[i].meshBatteryHighPct;
    obj["meshLastBatteryPct"] = services[i].meshLastBatteryPct;
    obj["meshLastBatteryV"] = services[i].meshLastBatteryV;
    obj["meshRepeaterKnownState"] = services[i].meshRepeaterKnownState;
  }
  String json;
  serializeJson(doc, json);
  return json;
}

// Helper: which alert channels are globally enabled (for UI)
String getGlobalAlertChannelsJson() {
  DynamicJsonDocument doc(256);
  JsonObject obj = doc.to<JsonObject>();
  obj["lora"] = settings.loraEnabled;
  obj["ntfy"] = settings.ntfyEnabled;
  obj["discord"] = settings.discordEnabled;
  obj["webhook"] = settings.webhookEnabled;
  obj["email"] = settings.emailEnabled;
  obj["mqtt"] = settings.mqttEnabled;
  String json;
  serializeJson(doc, json);
  return json;
}

String getDirectNodesJson() {
  DynamicJsonDocument doc(4096);
  JsonArray arr = doc.to<JsonArray>();
  for (int i = 0; i < settings.loraDirectNodeCount; i++) {
    if (settings.loraDirectNodes[i].pubkeyHex.length() == 0) continue;
    JsonObject obj = arr.createNestedObject();
    obj["name"] = settings.loraDirectNodes[i].name;
    obj["pubkey"] = settings.loraDirectNodes[i].pubkeyHex;
  }
  String json;
  serializeJson(doc, json);
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
  
  // Load or generate Ed25519 keys for signing adverts
  loadOrGenerateEd25519Keys();

  // Node name: use configured name, or default to first 8 hex chars of public key
  if (settings.loraNodeName.length() > 0) {
    ourNodeName = settings.loraNodeName;
  } else {
    char hexBuf[9];
    for (int i = 0; i < 4; i++) {
      snprintf(hexBuf + (i * 2), 3, "%02X", ed25519_public_key[i]);
    }
    hexBuf[8] = '\0';
    ourNodeName = String(hexBuf);
  }
  Serial.printf("Node identity: %s (ID: 0x%08X)\n", ourNodeName.c_str(), ourNodeId);

  // Compute our node hashes (primary = pubkey[0], alternate = SHA-256(pubkey)[0])
  ourNodeHash = ed25519_public_key[0];
  ourNodeHashAlt = computeNodeHashSha256(ed25519_public_key);
  Serial.printf("Node hash (pubkey[0]): 0x%02X, alt (sha256[0]): 0x%02X\n", ourNodeHash, ourNodeHashAlt);

  clearPeerCache();
  initPendingMeshChecks();
}

// Send direct LoRa text message (for commands like ping/status)
// Returns true if the radio transmission succeeded.
bool sendLoRaDirectMessage(const String& message, const uint8_t* destPubKey, uint8_t destHash, const uint8_t* replyPath, size_t replyPathLen) {
  if (!settings.loraEnabled) return false;

  // Send message without node name prefix (direct response style)
  size_t textLen = message.length();
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
  memcpy(&plaintext[idx], message.c_str(), textLen);
  idx += textLen;
  
  if (destPubKey == nullptr) {
    Serial.println("[LoRa] ERROR: Missing destination public key for direct message");
    return false;
  }

  // For direct messages, derive ECDH shared secret with peer
  // MeshCore uses the raw shared secret directly (not SHA-256 derived)
  uint8_t channelKey[32];
  size_t channelKeyLen = 32;
  if (!deriveSharedSecretWithPeer(destPubKey, channelKey)) {
    Serial.println("[LoRa] ERROR: Failed to derive shared secret for direct message");
    return false;
  }
  
  // Encrypt and compute MAC using raw shared secret
  uint8_t macAndCipher[256];
  size_t macCipherLen = encryptAndSign(channelKey, channelKeyLen, macAndCipher, sizeof(macAndCipher), plaintext, idx);
  if (macCipherLen == 0) {
    Serial.println("[LoRa] ERROR: Failed to encrypt message");
    return false;
  }
  
  // Build complete packet: [header][path_len][path][destHash][srcHash][MAC+ciphertext]
  uint8_t packet[260];
  size_t pktIdx = 0;
  
  // Get MAC address for our node ID
  uint8_t mac[6];
  WiFi.macAddress(mac);
  
  // Determine routing: DIRECT if we have sender path, otherwise FLOOD
  bool useDirect = (replyPath != nullptr && replyPathLen > 0);
  uint8_t routeType = useDirect ? ROUTE_TYPE_DIRECT : ROUTE_TYPE_FLOOD;
  
  // Header: version(0) + payload_type(TXT=2) + route_type
  uint8_t header = (uint8_t)((routeType & 0x03) | ((PAYLOAD_TYPE_TXT & 0x0F) << 2));
  packet[pktIdx++] = header;
  
  // Path: use sender's path for direct routing, or our node ID for flood
  if (useDirect) {
    // Direct routing: use sender's path as destination
    packet[pktIdx++] = replyPathLen;
    memcpy(&packet[pktIdx], replyPath, replyPathLen);
    pktIdx += replyPathLen;
    Serial.printf("[LoRa] Using DIRECT routing with path_len=%d\n", replyPathLen);
  } else {
    // Flood routing: start with empty path
    packet[pktIdx++] = 0;  // path_len
    Serial.println("[LoRa] Using FLOOD routing");
  }
  
  // Direct addressing hashes
  // destHash: first byte of destination public key
  packet[pktIdx++] = destHash;
  // srcHash: our node hash
  packet[pktIdx++] = ourNodeHash;
  
  // MAC + ciphertext
  if (pktIdx + macCipherLen > sizeof(packet)) {
    Serial.println("[LoRa] ERROR: Packet buffer too small");
    return false;
  }
  memcpy(packet + pktIdx, macAndCipher, macCipherLen);
  pktIdx += macCipherLen;
  
  // Transmit
  int state = radio.transmit(packet, pktIdx);
  bool success = (state == RADIOLIB_ERR_NONE);
  if (success) {
    Serial.printf("[LoRa] Sent direct message: %s (len=%u)\n", 
                  message.c_str(), (unsigned int)pktIdx);
  } else {
    Serial.printf("[LoRa] Failed to send message, code: %d\n", state);
  }
  
  // Log to LoRa message history
  {
    String peerName = "";
    int pi = findPeerIndexByHash(destHash);
    if (pi >= 0) peerName = peers[pi].name;
    if (peerName.length() == 0) { char hx[8]; snprintf(hx, sizeof(hx), "0x%02X", destHash); peerName = hx; }
    appendLoraLog('S', 'D', peerName, message, success);
  }
  
  // Return to RX mode
  radio.startReceive();
  return success;
}

static uint32_t computeAckHash(const uint8_t* data, size_t dataLen, const uint8_t senderPubKey[32]) {
  unsigned char fullHash[32];
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha, data, dataLen);
  mbedtls_sha256_update(&sha, senderPubKey, 32);
  mbedtls_sha256_finish(&sha, fullHash);
  mbedtls_sha256_free(&sha);
  return (uint32_t)fullHash[0] | ((uint32_t)fullHash[1] << 8) | ((uint32_t)fullHash[2] << 16) | ((uint32_t)fullHash[3] << 24);
}

// Returns true if at least one ACK was transmitted successfully.
static bool sendLoRaAck(uint32_t ackHash, const uint8_t* replyPath, size_t replyPathLen) {
  if (!settings.loraEnabled) return false;

  uint8_t packet[64];
  constexpr size_t kAckOverheadBytes = 1 /* header */ + 1 /* path_len */ + 4 /* ack hash */;
  constexpr size_t kMaxDirectAckPathLen = sizeof(packet) - kAckOverheadBytes;
  size_t pktIdx = 0;

  bool useDirect = (replyPath != nullptr && replyPathLen > 0);
  if (useDirect && replyPathLen > kMaxDirectAckPathLen) {
    Serial.printf("[LoRa] ACK reply path too long for packet buffer (%u > %u), using flood ACK\n",
                  (unsigned int)replyPathLen, (unsigned int)kMaxDirectAckPathLen);
    useDirect = false;
  }
  uint8_t routeType = useDirect ? ROUTE_TYPE_DIRECT : ROUTE_TYPE_FLOOD;
  uint8_t header = (uint8_t)((routeType & 0x03) | ((PAYLOAD_TYPE_ACK & 0x0F) << 2));
  packet[pktIdx++] = header;

  if (useDirect) {
    packet[pktIdx++] = replyPathLen;
    memcpy(&packet[pktIdx], replyPath, replyPathLen);
    pktIdx += replyPathLen;
  } else {
    packet[pktIdx++] = 0; // no path for flood
  }

  packet[pktIdx++] = (uint8_t)(ackHash & 0xFF);
  packet[pktIdx++] = (uint8_t)((ackHash >> 8) & 0xFF);
  packet[pktIdx++] = (uint8_t)((ackHash >> 16) & 0xFF);
  packet[pktIdx++] = (uint8_t)((ackHash >> 24) & 0xFF);

  int ackCount = settings.loraAckCount;
  if (ackCount < 1) ackCount = 1;
  if (ackCount > 5) ackCount = 5;

  bool anySuccess = false;
  for (int ackIdx = 0; ackIdx < ackCount; ackIdx++) {
    if (ackIdx > 0) delay(150);
    int state = radio.transmit(packet, pktIdx);
    if (state == RADIOLIB_ERR_NONE) {
      Serial.printf("[LoRa] Sent ACK %d/%d (hash=0x%08X, len=%u)\n", ackIdx + 1, ackCount, ackHash, (unsigned int)pktIdx);
      anySuccess = true;
    } else {
      Serial.printf("[LoRa] Failed to send ACK %d/%d, code: %d\n", ackIdx + 1, ackCount, state);
    }
  }

  // Log ACK to LoRa message history
  {
    char hashStr[16];
    snprintf(hashStr, sizeof(hashStr), "0x%08X", ackHash);
    appendLoraLog('S', 'A', String(hashStr), "ACK", anySuccess);
  }

  radio.startReceive();
  return anySuccess;
}

static void sendLoRaDirectNotifications(const String &notification) {
  if (!settings.loraEnabled) return;
  if (!settings.loraDirectEnabled) return;
  if (settings.loraDirectNodeCount <= 0) return;

  for (int i = 0; i < settings.loraDirectNodeCount; i++) {
    const String &pubHex = settings.loraDirectNodes[i].pubkeyHex;
    if (pubHex.length() == 0) continue;

    uint8_t pubkey[32];
    if (!parseHexKeyToBytes(pubHex, pubkey)) {
      Serial.printf("[LoRa] Skipping direct node %d: invalid pubkey\n", i);
      continue;
    }

    if (memcmp(pubkey, ed25519_public_key, 32) == 0) {
      Serial.println("[LoRa] Skipping direct message to self");
      continue;
    }

    String label = settings.loraDirectNodes[i].name;
    if (label.length() == 0) label = String("node-") + String(i + 1);
    Serial.printf("[LoRa] Direct notify -> %s\n", label.c_str());
    bool notifyOk = sendLoRaDirectMessage(notification, pubkey, pubkey[0], nullptr, 0);
    appendLoraLog('S', 'N', label, notification, notifyOk);
  }
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
  
  // Format message as "nodeName: text" to match MeshCore group message format.
  // Use ourNodeName so self-message suppression remains consistent with initNodeIdentity().
  String formattedMsg = ourNodeName + ": " + notification;
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
  uint8_t mac[6];
  WiFi.macAddress(mac);
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
  appendLoraLog('S', 'G', settings.channelName, notification, state == RADIOLIB_ERR_NONE);

  // Optional direct notifications to configured nodes
  sendLoRaDirectNotifications(notification);
  
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
  
  // App flags (1 byte) - bit 0-3: role (1=Chat Node/Client, 2=Repeater), bit 4: location (0=No), bit 7: name (1=Yes)
  // 0x81 = binary 10000001 = Chat Node with name
  // 0x82 = binary 10000010 = Repeater with name
  app_data[app_data_len++] = settings.repeaterEnabled ? 0x82 : 0x81;
  
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

// Forward declarations for MeshCore node check functions
static void sendMeshRepeaterCommand(Service& svc, bool enable);
static void processMeshNodeResponse(int serviceIdx, const String& text);

// ============================================
// MeshCore Node Monitor Functions
// ============================================

// Send "repeater on" or "repeater off" to a remote MeshCore node.
static void sendMeshRepeaterCommand(Service& svc, bool enable) {
  if (!settings.loraEnabled) return;
  uint8_t pubkeyBytes[32];
  if (!parseHexKeyToBytes(svc.meshNodePubkey, pubkeyBytes)) {
    Serial.printf("[MeshNode] Invalid pubkey for service '%s'\n", svc.name.c_str());
    return;
  }
  String cmd = svc.meshNodePin + ":repeater " + (enable ? "on" : "off");
  bool ok = sendLoRaDirectMessage(cmd, pubkeyBytes, pubkeyBytes[0], nullptr, 0);
  if (ok) {
    svc.meshRepeaterKnownState = enable;
    Serial.printf("[MeshNode] Sent 'repeater %s' to %s\n", enable ? "on" : "off", svc.name.c_str());
  } else {
    Serial.printf("[MeshNode] Failed to send 'repeater %s' to %s\n", enable ? "on" : "off", svc.name.c_str());
  }
}

// Parse a status reply from a remote MeshCore node and update service state.
// Expected format: "Status: IP=x.x.x.x, Battery=X.XXV (YY%), ..."
static void processMeshNodeResponse(int serviceIdx, const String& text) {
  if (serviceIdx < 0 || serviceIdx >= serviceCount) return;
  Service& svc = services[serviceIdx];

  Serial.printf("[MeshNode] Response for '%s': %s\n", svc.name.c_str(), text.c_str());

  // Parse battery voltage and percent from "Battery=X.XXV (YY%)"
  int battIdx = text.indexOf("Battery=");
  if (battIdx >= 0) {
    String battStr = text.substring(battIdx + 8);
    // Extract voltage
    int vIdx = battStr.indexOf('V');
    if (vIdx > 0) {
      svc.meshLastBatteryV = battStr.substring(0, vIdx).toFloat();
    }
    // Extract percent from "(YY%)"
    int pOpen = battStr.indexOf('(');
    int pClose = battStr.indexOf('%');
    if (pOpen >= 0 && pClose > pOpen) {
      svc.meshLastBatteryPct = battStr.substring(pOpen + 1, pClose).toInt();
    }
    svc.meshLastResponseMs = millis();
    svc.lastError = "Battery: " + String(svc.meshLastBatteryPct) + "% (" + String(svc.meshLastBatteryV, 2) + "V)";
    Serial.printf("[MeshNode] '%s' battery: %d%% (%.2fV)\n",
                  svc.name.c_str(), svc.meshLastBatteryPct, svc.meshLastBatteryV);

    // Automated repeater control
    if (svc.meshRepeaterControl) {
      if (svc.meshRepeaterKnownState && svc.meshLastBatteryPct < svc.meshBatteryLowPct) {
        Serial.printf("[MeshNode] Battery %d%% below low threshold %d%% — disabling repeater\n",
                      svc.meshLastBatteryPct, svc.meshBatteryLowPct);
        sendMeshRepeaterCommand(svc, false);
      } else if (!svc.meshRepeaterKnownState && svc.meshLastBatteryPct >= svc.meshBatteryHighPct) {
        Serial.printf("[MeshNode] Battery %d%% above high threshold %d%% — enabling repeater\n",
                      svc.meshLastBatteryPct, svc.meshBatteryHighPct);
        sendMeshRepeaterCommand(svc, true);
      }
    }
  } else {
    // Response received but no battery info — still counts as reachable
    svc.meshLastResponseMs = millis();
    svc.lastError = "Reached (no battery data)";
  }
}

// Send a PIN-authenticated status request to a remote MeshCore node.
// Returns true if a previous response arrived within the allowable window
// (checkInterval * 2.5 s), false otherwise.
bool checkMeshNode(Service& svc) {
  if (!settings.loraEnabled) {
    svc.lastError = "LoRa disabled";
    return false;
  }
  if (svc.meshNodePubkey.length() != 64) {
    svc.lastError = "Invalid pubkey (need 64 hex chars)";
    return false;
  }
  if (svc.meshNodePin.length() == 0) {
    svc.lastError = "No PIN configured";
    return false;
  }

  // Determine service index
  int svcIdx = -1;
  for (int i = 0; i < serviceCount; i++) {
    if (&services[i] == &svc) { svcIdx = i; break; }
  }

  uint8_t pubkeyBytes[32];
  if (!parseHexKeyToBytes(svc.meshNodePubkey, pubkeyBytes)) {
    svc.lastError = "Malformed pubkey hex";
    return false;
  }

  // Send status request
  String cmd = svc.meshNodePin + ":status";
  bool sent = sendLoRaDirectMessage(cmd, pubkeyBytes, pubkeyBytes[0], nullptr, 0);
  if (sent && svcIdx >= 0) {
    registerPendingMeshCheck(pubkeyBytes[0], svcIdx);
    Serial.printf("[MeshNode] Sent status request to '%s' (hash=0x%02X)\n",
                  svc.name.c_str(), pubkeyBytes[0]);
  }

  // Determine result based on whether we've received a fresh response recently
  if (svc.meshLastResponseMs == 0) {
    // Never received a response yet
    svc.lastError = sent ? "Waiting for first response" : "LoRa send failed";
    return false;
  }

  unsigned long windowMs = (unsigned long)(svc.checkInterval) * 2500UL;  // 2.5× interval
  unsigned long age = millis() - svc.meshLastResponseMs;
  if (age <= windowMs) {
    // Fresh enough response — node is reachable
    return true;
  }

  svc.lastError = "No response for " + String(age / 1000) + "s (timeout " + String(windowMs / 1000) + "s)";
  return false;
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
  
  // Send notifications on status change (but not for initial pending -> up/down transition)
  if (wasUp != service.isUp && !wasPending) {
    appendServiceStatusEvent(service, service.isUp);
    String statusStr = service.isUp ? "UP" : "DOWN";
    Serial.printf("[Status] %s is now %s\n", service.name.c_str(), statusStr.c_str());
    String alertMsg = "[Monitor] " + service.name + ": " + statusStr;
    if (service.lastError.length() > 0) {
      alertMsg += " - " + service.lastError;
    }

    // LoRa channel notification
    if (service.alertLora) {
      sendLoRaNotification(service.name, service.isUp, service.lastError);
    }

    // Internet channel notifications (per-service overrides)
    String messageId = messageIdForBody(alertMsg);
    String bodyWithId = addMessageIdPrefix(alertMsg, messageId);
    if (service.alertNtfy && settings.ntfyEnabled) forwardToNtfy(bodyWithId);
    if (service.alertDiscord && settings.discordEnabled) forwardToDiscord(bodyWithId);
    if (service.alertWebhook && settings.webhookEnabled) forwardToWebhook(bodyWithId);
    if (service.alertEmail && settings.emailEnabled) forwardToEmail(bodyWithId);
    if (service.alertMqtt && settings.mqttEnabled) forwardToMqtt(alertMsg);

    // Wake-on-LAN: send magic packet when service goes DOWN
    if (service.alertWol && !service.isUp && service.wolMacAddress.length() > 0) {
      sendWolPacket(service.wolMacAddress);
    }
  } else if (wasPending && !service.isPending) {
    Serial.printf("[Status] %s initial state: %s\n", service.name.c_str(), service.isUp ? "UP" : "DOWN");
  }
  
  service.lastCheck = millis();
}

// ============================================
// MeshCore Crypto Functions
// ============================================

static void deriveDirectKeyFromShared(const uint8_t shared[32], uint8_t outKey[32]) {
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha, shared, 32);
  mbedtls_sha256_finish(&sha, outKey);
  mbedtls_sha256_free(&sha);
}

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
  
  // Decrypt with AES-128 ECB (key is first 16 bytes of shared secret)
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

// ============================================
// X25519 (Curve25519) Helpers for Direct Messages
// ============================================

// Derive an X25519 private key from our Ed25519 private seed using SHA-512 and clamping
static void ed25519SeedToX25519Private(const uint8_t edSeed[32], uint8_t xPriv[32]) {
  uint8_t digest[64];
  SHA512 sha;
  sha.reset();
  sha.update(edSeed, 32);
  sha.finalize(digest, sizeof(digest));
  memcpy(xPriv, digest, 32);
  // Clamp per RFC 7748
  xPriv[0] &= 248;
  xPriv[31] &= 127;
  xPriv[31] |= 64;
}

// Convert Ed25519 public key to Curve25519 (Montgomery) public key
// Formula: u = (1 + y) / (1 - y) mod p
static bool ed25519PubToCurve25519Pub(const uint8_t edPub[32], uint8_t curvePub[32]) {
  uint8_t yLe[32];
  memcpy(yLe, edPub, 32);
  yLe[31] &= 0x7F; // Clear sign bit

  uint8_t yBe[32];
  for (int i = 0; i < 32; i++) {
    yBe[i] = yLe[31 - i];
  }

  mbedtls_mpi y, one, p, num, den, inv, u;
  mbedtls_mpi_init(&y);
  mbedtls_mpi_init(&one);
  mbedtls_mpi_init(&p);
  mbedtls_mpi_init(&num);
  mbedtls_mpi_init(&den);
  mbedtls_mpi_init(&inv);
  mbedtls_mpi_init(&u);

  int ret = 0;
  if ((ret = mbedtls_mpi_read_binary(&y, yBe, sizeof(yBe))) != 0) {
    Serial.printf("[X25519] Failed to read Ed25519 pubkey: -0x%04X\n", -ret);
    goto cleanup;
  }
  if ((ret = mbedtls_mpi_lset(&one, 1)) != 0) {
    Serial.printf("[X25519] Failed to set one: -0x%04X\n", -ret);
    goto cleanup;
  }
  // p = 2^255 - 19
  if ((ret = mbedtls_mpi_lset(&p, 1)) != 0) goto cleanup;
  if ((ret = mbedtls_mpi_shift_l(&p, 255)) != 0) goto cleanup;
  if ((ret = mbedtls_mpi_sub_int(&p, &p, 19)) != 0) goto cleanup;

  // num = (1 + y) mod p
  if ((ret = mbedtls_mpi_add_mpi(&num, &one, &y)) != 0) goto cleanup;
  if ((ret = mbedtls_mpi_mod_mpi(&num, &num, &p)) != 0) goto cleanup;

  // den = (1 - y) mod p
  if ((ret = mbedtls_mpi_sub_mpi(&den, &one, &y)) != 0) goto cleanup;
  if ((ret = mbedtls_mpi_mod_mpi(&den, &den, &p)) != 0) goto cleanup;

  // inv = den^{-1} mod p
  if ((ret = mbedtls_mpi_inv_mod(&inv, &den, &p)) != 0) {
    Serial.printf("[X25519] Failed to invert denominator: -0x%04X\n", -ret);
    goto cleanup;
  }

  // u = num * inv mod p
  if ((ret = mbedtls_mpi_mul_mpi(&u, &num, &inv)) != 0) goto cleanup;
  if ((ret = mbedtls_mpi_mod_mpi(&u, &u, &p)) != 0) goto cleanup;

  uint8_t uBe[32];
  memset(uBe, 0, sizeof(uBe));
  if ((ret = mbedtls_mpi_write_binary(&u, uBe, sizeof(uBe))) != 0) {
    Serial.printf("[X25519] Failed to write montgomery u: -0x%04X\n", -ret);
    goto cleanup;
  }

  for (int i = 0; i < 32; i++) {
    curvePub[i] = uBe[31 - i];
  }

  mbedtls_mpi_free(&y);
  mbedtls_mpi_free(&one);
  mbedtls_mpi_free(&p);
  mbedtls_mpi_free(&num);
  mbedtls_mpi_free(&den);
  mbedtls_mpi_free(&inv);
  mbedtls_mpi_free(&u);
  return true;

cleanup:
  mbedtls_mpi_free(&y);
  mbedtls_mpi_free(&one);
  mbedtls_mpi_free(&p);
  mbedtls_mpi_free(&num);
  mbedtls_mpi_free(&den);
  mbedtls_mpi_free(&inv);
  mbedtls_mpi_free(&u);
  return false;
}

// Compute shared secret with a peer's Ed25519 public key (converted to X25519)
static bool deriveSharedSecretWithPeer(const uint8_t peerEd25519Pub[32], uint8_t shared[32]) {
  uint8_t xPriv[32];
  ed25519SeedToX25519Private(ed25519_private_key, xPriv);

  uint8_t xPeerPub[32];
  if (!ed25519PubToCurve25519Pub(peerEd25519Pub, xPeerPub)) {
    Serial.println("[X25519] Failed to convert Ed25519 public key to Curve25519");
    return false;
  }

  // Perform X25519 ECDH using Curve25519::eval
  if (!Curve25519::eval(shared, xPriv, xPeerPub)) {
    Serial.println("[X25519] ECDH failed");
    return false;
  }

  return true;
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

static bool normalizeHexKey(const String &input, String &out) {
  out = input;
  out.trim();
  if (out.startsWith("0x") || out.startsWith("0X")) {
    out = out.substring(2);
  }
  out.toLowerCase();
  if (out.length() != 64) return false;
  if (!isHexString(out.c_str(), out.length())) return false;
  return true;
}

static bool parseHexKeyToBytes(const String &hex, uint8_t out[32]) {
  String normalized;
  if (!normalizeHexKey(hex, normalized)) return false;
  return hexToBytes(normalized.c_str(), out, 32) == 32;
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

/**
 * Initialize mesh channels: public channel + user's configured channel.
 * Called at startup and whenever channel settings change.
 */
void initMeshChannels() {
  meshChannelCount = 0;
  memset(meshChannels, 0, sizeof(meshChannels));

  // Channel 0: MeshCore public channel (always present, like MeshCore firmware)
  {
    MeshChannel& ch = meshChannels[meshChannelCount];
    ch.active = true;
    memcpy(ch.key, MESHCORE_PUBLIC_PSK, 16);
    ch.keyLen = 16;
    strncpy(ch.name, "Public", sizeof(ch.name) - 1);
    // hash = SHA256(PSK)[0]
    unsigned char h[32];
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, MESHCORE_PUBLIC_PSK, 16);
    mbedtls_sha256_finish(&sha, h);
    mbedtls_sha256_free(&sha);
    ch.hash = h[0];
    Serial.printf("[Channels] #%d '%s' hash=0x%02X keyLen=%d\n", meshChannelCount, ch.name, ch.hash, (int)ch.keyLen);
    meshChannelCount++;
  }

  // Channel 1+: User's configured channel (if secret is set)
  if (settings.channelSecret.length() > 0) {
    MeshChannel& ch = meshChannels[meshChannelCount];
    ch.active = true;
    deriveChannelKey(settings.channelName.c_str(), settings.channelSecret.c_str(), &ch.hash, ch.key, &ch.keyLen);
    strncpy(ch.name, settings.channelName.c_str(), sizeof(ch.name) - 1);
    Serial.printf("[Channels] #%d '%s' hash=0x%02X keyLen=%d\n", meshChannelCount, ch.name, ch.hash, (int)ch.keyLen);
    meshChannelCount++;
  }

  Serial.printf("[Channels] %d channel(s) initialized\n", meshChannelCount);
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
  
  // Wait for USB CDC serial to be ready (ESP32-S3)
  // This allows the serial monitor to connect and see boot messages
  unsigned long serialStart = millis();
  while (!Serial && (millis() - serialStart < 3000)) {
    delay(10);
  }
  delay(500);  // Extra delay to ensure monitor is ready
  
  Serial.println("\n\n===========================================");
  Serial.println("ESP32 Uptime Receiver Starting...");
  Serial.println("===========================================\n");

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

  // Generate or load credentials (admin password, hotspot password)
  loadOrGenerateCredentials();
  settings.adminPassword = generatedAdminPassword;
  settings.hotspotPassword = generatedHotspotPassword;
  settings.loraCommandPin = generatedLoraCommandPin;

  // Apply user overrides from settings.json (may override generated admin password)
  loadSettingsOverrides();

  // Output credentials to serial monitor on boot (if enabled)
  if (settings.showBootCredentials) {
    String hotspotSsid = String("ESP32NM-") + macNoColons();
    Serial.println("-------------------------------------------");
    Serial.println("  DEVICE CREDENTIALS");
    Serial.println("-------------------------------------------");
    Serial.printf("  Hotspot SSID:     %s\n", hotspotSsid.c_str());
    Serial.printf("  Hotspot Password: %s\n", settings.hotspotPassword.c_str());
    Serial.printf("  Hotspot IP:       %s\n", HOTSPOT_IP);
    Serial.printf("  Admin Password:   %s\n", settings.adminPassword.c_str());
    Serial.printf("  LoRa Command PIN: %s\n", settings.loraCommandPin.c_str());
    Serial.println("-------------------------------------------\n");

    // Auto-disable after showing once; admin must re-enable to see again
    settings.showBootCredentials = false;
    saveSettingsOverrides();
    Serial.println("[Credentials] Boot credential display auto-disabled.");
  }

  // Setup WiFi (needed for forwarding and NTP sync)
  setupWiFi();
  
  // Initialize node identity for filtering own messages
  initNodeIdentity();

  // Sync time via NTP for proper timestamps
  if (wifiConnected) {
    syncNTP();
  }

  // Load cached adverts after NTP sync so stale entries can be expired
  loadAdvertCache();

  // Pre-populate peer cache with configured direct nodes
  for (int i = 0; i < settings.loraDirectNodeCount; i++) {
    const String &pubHex = settings.loraDirectNodes[i].pubkeyHex;
    if (pubHex.length() == 0) continue;
    uint8_t pubkey[32];
    if (!parseHexKeyToBytes(pubHex, pubkey)) continue;
    String label = settings.loraDirectNodes[i].name;
    if (label.length() == 0) label = String("node-") + String(i + 1);
    upsertPeer(pubkey[0], pubkey, label, 0);
    Serial.printf("[LoRa] Pre-loaded direct node '%s' into peer cache\n", label.c_str());
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
    doc["SHOW_BOOT_CREDENTIALS"] = settings.showBootCredentials;
    doc["CHANNEL_NAME"] = settings.channelName;

    doc["LORA_ENABLED"] = settings.loraEnabled;
    doc["LORA_NODE_NAME"] = settings.loraNodeName;
    doc["LORA_IP_ALERTS"] = settings.loraIpAlerts;
    doc["LORA_IGNORE_PUBLIC"] = settings.loraIgnorePublic;
    doc["LORA_FREQ"] = settings.loraFreq;
    doc["LORA_BANDWIDTH"] = settings.loraBandwidth;
    doc["LORA_SPREADING_FACTOR"] = settings.loraSpreadingFactor;
    doc["LORA_CODING_RATE"] = settings.loraCodingRate;
    doc["LORA_ACK_COUNT"] = settings.loraAckCount;
    doc["LORA_DIRECT_ENABLED"] = settings.loraDirectEnabled;
    JsonArray directNodes = doc.createNestedArray("LORA_DIRECT_NODES");
    for (int i = 0; i < settings.loraDirectNodeCount; i++) {
      if (settings.loraDirectNodes[i].pubkeyHex.length() == 0) continue;
      JsonObject obj = directNodes.add<JsonObject>();
      obj["name"] = settings.loraDirectNodes[i].name;
      obj["pubkey"] = settings.loraDirectNodes[i].pubkeyHex;
    }

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

    doc["AUTO_OTA_ENABLED"] = settings.autoOtaEnabled;
    doc["AUTO_OTA_URL"] = settings.autoOtaUrl;
    doc["AUTO_OTA_CHECK_INTERVAL"] = settings.autoOtaCheckInterval;
    doc["FIRMWARE_VERSION"] = String(FIRMWARE_VERSION);

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
      if (doc["SHOW_BOOT_CREDENTIALS"].is<bool>()) settings.showBootCredentials = doc["SHOW_BOOT_CREDENTIALS"].as<bool>();
      if (doc["CHANNEL_NAME"].is<String>()) settings.channelName = doc["CHANNEL_NAME"].as<String>();
      if (doc["CHANNEL_SECRET"].is<String>()) {
        String v = doc["CHANNEL_SECRET"].as<String>();
        if (v.length() > 0) settings.channelSecret = v;
      }

      if (doc["LORA_ENABLED"].is<bool>()) settings.loraEnabled = doc["LORA_ENABLED"].as<bool>();
      if (doc["LORA_NODE_NAME"].is<String>()) settings.loraNodeName = doc["LORA_NODE_NAME"].as<String>();
      if (doc["LORA_IP_ALERTS"].is<bool>()) settings.loraIpAlerts = doc["LORA_IP_ALERTS"].as<bool>();
      if (doc["LORA_IGNORE_PUBLIC"].is<bool>()) settings.loraIgnorePublic = doc["LORA_IGNORE_PUBLIC"].as<bool>();
      if (doc["LORA_COMMAND_PIN"].is<String>()) {
        String v = doc["LORA_COMMAND_PIN"].as<String>();
        if (v.length() > 0) settings.loraCommandPin = v;
      }

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

      if (doc["LORA_ACK_COUNT"].is<int>()) settings.loraAckCount = doc["LORA_ACK_COUNT"].as<int>();
      if (doc["LORA_ACK_COUNT"].is<String>()) settings.loraAckCount = doc["LORA_ACK_COUNT"].as<String>().toInt();

      if (doc["LORA_DIRECT_ENABLED"].is<bool>()) settings.loraDirectEnabled = doc["LORA_DIRECT_ENABLED"].as<bool>();
      if (doc["LORA_DIRECT_NODES"].is<JsonArray>()) {
        JsonArray nodes = doc["LORA_DIRECT_NODES"].as<JsonArray>();
        clearDirectNodeList(settings);
        for (JsonObject obj : nodes) {
          if (settings.loraDirectNodeCount >= MAX_DIRECT_NODES) break;
          String pubkey = obj["pubkey"] | "";
          String name = obj["name"] | "";
          String normalized;
          if (!normalizeHexKey(pubkey, normalized)) {
            continue;
          }
          settings.loraDirectNodes[settings.loraDirectNodeCount].name = name;
          settings.loraDirectNodes[settings.loraDirectNodeCount].pubkeyHex = normalized;
          settings.loraDirectNodeCount++;
        }
      }

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

      // Auto OTA
      if (doc["AUTO_OTA_ENABLED"].is<int>()) settings.autoOtaEnabled = doc["AUTO_OTA_ENABLED"].as<int>();
      else if (doc["AUTO_OTA_ENABLED"].is<bool>()) settings.autoOtaEnabled = doc["AUTO_OTA_ENABLED"].as<bool>() ? 1 : 0;
      if (doc["AUTO_OTA_URL"].is<String>()) settings.autoOtaUrl = doc["AUTO_OTA_URL"].as<String>();
      if (doc["AUTO_OTA_CHECK_INTERVAL"].is<int>()) settings.autoOtaCheckInterval = doc["AUTO_OTA_CHECK_INTERVAL"].as<int>();
      if (doc["AUTO_OTA_CHECK_INTERVAL"].is<String>()) settings.autoOtaCheckInterval = doc["AUTO_OTA_CHECK_INTERVAL"].as<String>().toInt();

      // Repeater mode
      if (doc["REPEATER_ENABLED"].is<bool>()) settings.repeaterEnabled = doc["REPEATER_ENABLED"].as<bool>();

      // Normalize
      if (settings.webhookMethod.length() == 0) settings.webhookMethod = "POST";

      if (settings.mqttPort <= 0) settings.mqttPort = 1883;
      if (settings.mqttQos < 0) settings.mqttQos = 0;
      if (settings.mqttQos > 2) settings.mqttQos = 2;

      if (settings.loraFreq <= 0.0f) settings.loraFreq = (float)LORA_FREQ;
      if (settings.loraBandwidth <= 0.0f) settings.loraBandwidth = (float)LORA_BANDWIDTH;
      if (settings.loraSpreadingFactor <= 0) settings.loraSpreadingFactor = (int)LORA_SPREADING_FACTOR;
      if (settings.loraCodingRate <= 0) settings.loraCodingRate = (int)LORA_CODING_RATE;
      if (settings.loraAckCount < 1) settings.loraAckCount = 1;
      if (settings.loraAckCount > 5) settings.loraAckCount = 5;

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
    page += "*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#000;min-height:100vh;padding:20px;color:#2d3748;overflow-x:hidden}";
    page += "#meshBg{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0}";
    page += ".container{max-width:900px;margin:0 auto;position:relative;z-index:1}.card{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:16px;padding:22px;box-shadow:0 8px 32px rgba(0,0,0,0.1);margin-bottom:16px}";
    page += "h1{font-size:22px;margin-bottom:10px}h2{font-size:16px;margin:18px 0 10px;color:#4a5568}";
    page += ".row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.fg{margin-bottom:12px}.lbl{display:block;font-weight:600;margin-bottom:6px;font-size:13px;color:#2d3748}";
    page += "input,select{width:100%;padding:10px 12px;border:2px solid #e2e8f0;border-radius:10px;font-size:14px}input:focus,select:focus{outline:none;border-color:#667eea}";
    page += ".btns{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}.btn{padding:10px 14px;border:none;border-radius:10px;cursor:pointer;font-weight:700}";
    page += ".primary{background:#667eea;color:#fff}.secondary{background:#e2e8f0;color:#2d3748}.hint{font-size:12px;color:#718096;margin-top:6px}";
    page += ".node-row{display:grid;grid-template-columns:1fr 2fr auto;gap:10px;align-items:center;margin-bottom:10px}.node-actions{display:flex;gap:6px;align-items:center}.btn-small{padding:8px 10px;border-radius:8px;font-size:12px;font-weight:700}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px}";
    page += "@media(max-width:700px){.row{grid-template-columns:1fr}}";
    page += "</style></head><body><canvas id='meshBg'></canvas><div class='container'>";
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
    page += "<div class='fg'><label class='lbl'>Show Boot Credentials</label><select id='SHOW_BOOT_CREDENTIALS'><option value='true'" + String(settings.showBootCredentials ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.showBootCredentials ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='hint'>When enabled, Hotspot Name, Password, IP, Admin Password and LoRa Command PIN are printed to the serial monitor on each boot.</div>";
    page += "</div></div>";

    page += "<div class='card'><h2>LoRa / MeshCore</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>Node Name</label><input id='LORA_NODE_NAME' value='" + settings.loraNodeName + "' placeholder='(first 8 chars of public key)'></div>";
    page += "<div class='fg'><label class='lbl'>Channel Name</label><input id='CHANNEL_NAME' value='" + settings.channelName + "'></div>";
    page += "<div class='fg'><label class='lbl'>Channel Secret</label><input id='CHANNEL_SECRET' type='password' value='' placeholder='(unchanged)'></div>";
    page += "<div class='fg'><label class='lbl'>Command PIN</label><input id='LORA_COMMAND_PIN' type='password' value='' placeholder='(unchanged)'></div>";
    page += "<div class='fg'><label class='lbl'>LoRa Enabled</label><select id='LORA_ENABLED'><option value='true'" + String(settings.loraEnabled ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.loraEnabled ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>IP Alerts</label><select id='LORA_IP_ALERTS'><option value='true'" + String(settings.loraIpAlerts ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.loraIpAlerts ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Ignore Public Channel</label><select id='LORA_IGNORE_PUBLIC'><option value='true'" + String(settings.loraIgnorePublic ? " selected" : "") + ">Yes</option><option value='false'" + String(!settings.loraIgnorePublic ? " selected" : "") + ">No</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Frequency (MHz)</label><input id='LORA_FREQ' type='number' step='0.001' value='" + String(settings.loraFreq, 3) + "'></div>";
    page += "<div class='fg'><label class='lbl'>Bandwidth (kHz)</label><input id='LORA_BANDWIDTH' type='number' step='0.1' value='" + String(settings.loraBandwidth, 1) + "'></div>";
    page += "<div class='fg'><label class='lbl'>Spreading Factor</label><input id='LORA_SPREADING_FACTOR' type='number' min='6' max='12' step='1' value='" + String(settings.loraSpreadingFactor) + "'></div>";
    page += "<div class='fg'><label class='lbl'>Coding Rate (4/x)</label><input id='LORA_CODING_RATE' type='number' min='5' max='8' step='1' value='" + String(settings.loraCodingRate) + "'></div>";
    page += "<div class='fg'><label class='lbl'>ACK Repeat Count</label><input id='LORA_ACK_COUNT' type='number' min='1' max='5' step='1' value='" + String(settings.loraAckCount) + "'></div>";
    page += "</div></div>";

    page += "<div class='card'><h2>LoRa Direct Messaging</h2>";
    page += "<div class='row'>";
    page += "<div class='fg'><label class='lbl'>Direct Messages</label><select id='LORA_DIRECT_ENABLED'><option value='true'" + String(settings.loraDirectEnabled ? " selected" : "") + ">Enabled</option><option value='false'" + String(!settings.loraDirectEnabled ? " selected" : "") + ">Disabled</option></select></div>";
    page += "</div>";
    page += "<div class='hint'>Add recipient nodes by Ed25519 public key (64 hex chars). These will receive direct LoRa alerts in addition to channel alerts.</div>";
    page += "<div id='directNodes'></div>";
    page += "<div class='btns'><button class='btn secondary' type='button' onclick='addDirectNode()'>+ Add Node</button></div>";
    page += "</div>";

    page += "<div class='card'><h2>Repeater Mode</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>Repeater Enabled</label><select id='REPEATER_ENABLED'><option value='true'" + String(settings.repeaterEnabled ? " selected" : "") + ">Yes — Advertise as Repeater</option><option value='false'" + String(!settings.repeaterEnabled ? " selected" : "") + ">No — Advertise as Client</option></select></div>";
    page += "</div>";
    page += "<div class='hint'>When enabled, this node advertises itself as a MeshCore repeater (role=2) to the mesh network. Can also be toggled remotely via LoRa command: &lt;pin&gt;:repeater on/off</div>";
    page += "</div>";

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

    page += "<div class='card'><h2>Auto OTA Updates</h2><div class='row'>";
    page += "<div class='fg'><label class='lbl'>Enabled</label><select id='AUTO_OTA_ENABLED'><option value='0'" + String(settings.autoOtaEnabled == 0 ? " selected" : "") + ">No</option><option value='1'" + String(settings.autoOtaEnabled == 1 ? " selected" : "") + ">Yes</option><option value='2'" + String(settings.autoOtaEnabled == 2 ? " selected" : "") + ">Yes - Delayed</option></select></div>";
    page += "<div class='fg'><label class='lbl'>Check Interval (sec)</label><input id='AUTO_OTA_CHECK_INTERVAL' value='" + String(settings.autoOtaCheckInterval) + "'></div>";
    page += "<div class='fg' style='grid-column:1/-1'><label class='lbl'>Firmware URL</label><input id='AUTO_OTA_URL' value='" + settings.autoOtaUrl + "' placeholder='https://example.com/firmware'></div>";
    page += "<div class='fg' style='grid-column:1/-1'><label class='lbl' style='font-size:12px;color:#718096'>Current version: " + String(FIRMWARE_VERSION) + " &mdash; The server should host a version.json with {version, url, notes} and the .bin file</label></div>";
    page += "<div class='fg' style='grid-column:1/-1'><button id='otaBtn' class='btn secondary' type='button' onclick='checkOta()'>Check Now</button> <span id='otaStatus' style='font-size:13px;color:#718096'></span></div>";
    page += "</div></div>";

    page += "<div class='card'><div class='btns'>";
    page += "<button class='btn primary' onclick='save()'>Save</button>";
    page += "<button class='btn secondary' onclick='location.href=\"/\"'>Back</button>";
    page += "</div><div class='hint'>WiFi changes reconnect automatically. LoRa changes reboot the device automatically.</div></div>";

    page += "</div><script>";
    page += "const directNodes=" + getDirectNodesJson() + ";";
    page += "function renderDirectNodes(){const c=document.getElementById('directNodes');if(!c) return;c.innerHTML='';if(!directNodes.length){c.innerHTML=\"<div class='hint'>No direct nodes configured.</div>\";return;}directNodes.forEach((n,i)=>{const row=document.createElement('div');row.className='node-row';row.innerHTML=\"<input class='node-name' placeholder='Name (optional)'>\"+\"<input class='node-pubkey mono' placeholder='Ed25519 public key (64 hex)'>\"+\"<div class='node-actions'><button class='btn btn-small secondary' type='button' onclick='removeDirectNode(\"+i+\")'>Remove</button></div>\";c.appendChild(row);row.querySelector('.node-name').value=n.name||'';row.querySelector('.node-pubkey').value=n.pubkey||'';});};";
    page += "function addDirectNode(name,pubkey){directNodes.push({name:name||'',pubkey:pubkey||''});renderDirectNodes();}";
    page += "function removeDirectNode(i){directNodes.splice(i,1);renderDirectNodes();}";
    page += "function collectDirectNodes(){const list=[];document.querySelectorAll('.node-row').forEach(row=>{const name=row.querySelector('.node-name')?.value.trim()||'';const pubkey=row.querySelector('.node-pubkey')?.value.trim()||'';if(pubkey.length>0){list.push({name:name,pubkey:pubkey});}});return list;};";
    page += "function val(id){return document.getElementById(id).value;}";
    page += "function boolVal(id){return document.getElementById(id).value==='true';}";
    page += "async function save(){const payload={";
    page += "WIFI_SSID:val('WIFI_SSID'),WIFI_PASSWORD:val('WIFI_PASSWORD'),";
    page += "IP_MODE:val('IP_MODE'),STATIC_IP:val('STATIC_IP'),STATIC_GATEWAY:val('STATIC_GATEWAY'),STATIC_SUBNET:val('STATIC_SUBNET'),";
    page += "DNS_MODE:val('DNS_MODE'),STATIC_DNS1:val('STATIC_DNS1'),STATIC_DNS2:val('STATIC_DNS2'),";
    page += "ADMIN_USERNAME:val('ADMIN_USERNAME'),ADMIN_PASSWORD:val('ADMIN_PASSWORD'),SHOW_BOOT_CREDENTIALS:boolVal('SHOW_BOOT_CREDENTIALS'),";
    page += "CHANNEL_NAME:val('CHANNEL_NAME'),CHANNEL_SECRET:val('CHANNEL_SECRET'),";
    page += "LORA_ENABLED:boolVal('LORA_ENABLED'),LORA_NODE_NAME:val('LORA_NODE_NAME'),LORA_IP_ALERTS:boolVal('LORA_IP_ALERTS'),LORA_IGNORE_PUBLIC:boolVal('LORA_IGNORE_PUBLIC'),LORA_COMMAND_PIN:val('LORA_COMMAND_PIN'),LORA_FREQ:val('LORA_FREQ'),LORA_BANDWIDTH:val('LORA_BANDWIDTH'),LORA_SPREADING_FACTOR:val('LORA_SPREADING_FACTOR'),LORA_CODING_RATE:val('LORA_CODING_RATE'),LORA_ACK_COUNT:val('LORA_ACK_COUNT'),LORA_DIRECT_ENABLED:boolVal('LORA_DIRECT_ENABLED'),LORA_DIRECT_NODES:collectDirectNodes(),";
    page += "NTFY_ENABLED:boolVal('NTFY_ENABLED'),NTFY_MESH_RELAY:boolVal('NTFY_MESH_RELAY'),NTFY_IP_ALERTS:boolVal('NTFY_IP_ALERTS'),";
    page += "NTFY_SERVER:val('NTFY_SERVER'),NTFY_TOPIC:val('NTFY_TOPIC'),NTFY_USERNAME:val('NTFY_USERNAME'),NTFY_PASSWORD:val('NTFY_PASSWORD'),NTFY_TOKEN:val('NTFY_TOKEN'),";
    page += "DISCORD_ENABLED:boolVal('DISCORD_ENABLED'),DISCORD_MESH_RELAY:boolVal('DISCORD_MESH_RELAY'),DISCORD_IP_ALERTS:boolVal('DISCORD_IP_ALERTS'),DISCORD_WEBHOOK_URL:val('DISCORD_WEBHOOK_URL'),";
    page += "WEBHOOK_ENABLED:boolVal('WEBHOOK_ENABLED'),WEBHOOK_MESH_RELAY:boolVal('WEBHOOK_MESH_RELAY'),WEBHOOK_IP_ALERTS:boolVal('WEBHOOK_IP_ALERTS'),WEBHOOK_URL:val('WEBHOOK_URL'),WEBHOOK_METHOD:val('WEBHOOK_METHOD'),";
    page += "EMAIL_ENABLED:boolVal('EMAIL_ENABLED'),EMAIL_MESH_RELAY:boolVal('EMAIL_MESH_RELAY'),EMAIL_IP_ALERTS:boolVal('EMAIL_IP_ALERTS'),SMTP_HOST:val('SMTP_HOST'),SMTP_PORT:val('SMTP_PORT'),EMAIL_RECIPIENT:val('EMAIL_RECIPIENT'),EMAIL_SENDER:val('EMAIL_SENDER'),SMTP_USER:val('SMTP_USER'),SMTP_PASSWORD:val('SMTP_PASSWORD')";
    page += ",MQTT_ENABLED:boolVal('MQTT_ENABLED'),MQTT_MESH_RELAY:boolVal('MQTT_MESH_RELAY'),MQTT_IP_ALERTS:boolVal('MQTT_IP_ALERTS'),MQTT_BROKER:val('MQTT_BROKER'),MQTT_PORT:val('MQTT_PORT'),MQTT_TOPIC:val('MQTT_TOPIC'),MQTT_USERNAME:val('MQTT_USERNAME'),MQTT_PASSWORD:val('MQTT_PASSWORD')";
    page += ",MQTT_QOS:val('MQTT_QOS')";
    page += ",AUTO_OTA_ENABLED:parseInt(val('AUTO_OTA_ENABLED'))||0,AUTO_OTA_URL:val('AUTO_OTA_URL'),AUTO_OTA_CHECK_INTERVAL:parseInt(val('AUTO_OTA_CHECK_INTERVAL'))||3600";
    page += ",REPEATER_ENABLED:boolVal('REPEATER_ENABLED')";
    page += "};";
    page += "const res=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(payload)});";
    page += "if(res.ok){const j=await res.json().catch(()=>({}));if(j.rebooting){alert('Saved. Rebooting...');}else{alert('Saved');}}else{alert('Save failed');}";
    page += "}";
    page += "async function checkOta(){const btn=document.getElementById('otaBtn');const st=document.getElementById('otaStatus');btn.disabled=true;st.textContent='Checking...';try{const r=await fetch('/api/auto-ota/check',{method:'POST',credentials:'include'});const d=await r.json();if(d.updateAvailable){st.textContent='Update available: v'+d.latestVersion+(d.latestNotes?' - '+d.latestNotes:'');st.style.color='#48bb78';btn.textContent='Install Now';btn.className='btn primary';btn.onclick=installOta;btn.disabled=false;}else{st.textContent='Up to date (v'+d.currentVersion+')';st.style.color='#718096';btn.disabled=false;}}catch(e){st.textContent='Check failed: '+e.message;st.style.color='#e53e3e';btn.disabled=false;}}";
    page += "async function installOta(){const btn=document.getElementById('otaBtn');const st=document.getElementById('otaStatus');if(!confirm('Install firmware update now? The device will reboot.'))return;btn.disabled=true;btn.textContent='Installing...';st.textContent='Downloading and flashing firmware...';st.style.color='#ecc94b';try{const r=await fetch('/api/auto-ota/apply',{method:'POST',credentials:'include'});const d=await r.json();if(d.error){st.textContent='Install failed: '+d.error;st.style.color='#e53e3e';btn.textContent='Install Now';btn.disabled=false;}else{st.textContent='Update started. Device will reboot shortly...';st.style.color='#48bb78';}}catch(e){st.textContent='Install failed: '+e.message;st.style.color='#e53e3e';btn.textContent='Install Now';btn.disabled=false;}}";
    page += "renderDirectNodes();";
    page += "</script><script>";
    page += "(function(){";
    page += "var c=document.getElementById('meshBg'),ctx=c.getContext('2d');";
    page += "var dots=[],MAX=60,DIST=120;";
    page += "function resize(){c.width=window.innerWidth;c.height=window.innerHeight;}";
    page += "window.addEventListener('resize',resize);resize();";
    page += "for(var i=0;i<MAX;i++){dots.push({x:Math.random()*c.width,y:Math.random()*c.height,vx:(Math.random()-0.5)*0.6,vy:(Math.random()-0.5)*0.6,r:Math.random()*1.5+1});}";
    page += "function draw(){ctx.clearRect(0,0,c.width,c.height);";
    page += "for(var i=0;i<dots.length;i++){var d=dots[i];d.x+=d.vx;d.y+=d.vy;";
    page += "if(d.x<0||d.x>c.width)d.vx*=-1;if(d.y<0||d.y>c.height)d.vy*=-1;";
    page += "ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fillStyle='rgba(72,187,120,0.8)';ctx.fill();";
    page += "for(var j=i+1;j<dots.length;j++){var e=dots[j],dx=d.x-e.x,dy=d.y-e.y,dist=Math.sqrt(dx*dx+dy*dy);";
    page += "if(dist<DIST){ctx.beginPath();ctx.moveTo(d.x,d.y);ctx.lineTo(e.x,e.y);";
    page += "ctx.strokeStyle='rgba(72,187,120,'+(1-dist/DIST)*0.4+')';ctx.lineWidth=0.8;ctx.stroke();}}}";
    page += "requestAnimationFrame(draw);}draw();})();";
    page += "</script></body></html>";
    request->send(200, "text/html", page);
  });

  // --- Web Server Endpoints ---
  // ElegantOTA integration
  // ElegantOTA.setAuth(ADMIN_USERNAME, ADMIN_PASSWORD);  // Protect OTA with admin credentials
  // ElegantOTA.begin(&server);  // Temporarily disabled due to header conflicts

  // Status page (modern styled HTML)
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    if (captivePortalActive && !isWifiConfigured()) {
      request->send(200, "text/html", captivePortalHtml());
      return;
    }
    bool isAuthed = isAuthenticated(request, false);
    String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>ESP32 Uptime Monitor</title>";
    html += "<style>";
    html += "*{margin:0;padding:0;box-sizing:border-box}";
    html += "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;background:#000;min-height:100vh;padding:20px;overflow-x:hidden}";
    html += "#meshBg{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0}";
    html += ".container{max-width:1200px;margin:0 auto;position:relative;z-index:1}";
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
    html += "<canvas id='meshBg'></canvas>";
    html += "<div class='container'>";
    html += "<div class='header'><h1>🚀 ESP32 Uptime Monitor</h1><div class='subtitle'>Real-time service monitoring dashboard</div><div class='subtitle' style='font-size:13px;opacity:0.9;margin-top:6px'>Firmware v" + String(FIRMWARE_VERSION) + "</div><div class='subtitle' style='font-size:12px;opacity:0.85;margin-top:4px'>Build: " + String(__DATE__) + " " + String(__TIME__) + "</div>";
    if (isAuthed) {
      html += "<div class='subtitle' style='font-size:12px;opacity:0.85;margin-top:4px'>MAC: " + macWithColons() + "</div>";
    }
    html += "<div class='subtitle' style='font-size:12px;opacity:0.85;margin-top:4px'>LoRa Node: " + (ourNodeName.length() > 0 ? ourNodeName : String("(not set)")) + "</div></div>";
    
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
      html += "<button class='icon-btn' onclick='checkServiceNow(" + String(i) + ")' title='Check Now'>▶️</button>";
      html += "<button class='icon-btn' onclick='viewHistory(" + String(i) + ")' title='History'>🕒</button>";
      if (isAuthed) {
        html += "<button class='icon-btn' onclick='editService(" + String(i) + ")' title='Edit'>✏️</button>";
        html += "<button class='icon-btn delete' onclick='deleteService(" + String(i) + ")' title='Delete'>🗑️</button>";
      }
      html += "</div>";
      html += "</div>";
      html += "<span class='service-status " + statusBadgeClass + "'>" + statusText + "</span>";
      const char* svcTypeName[] = {"HTTP GET","Ping","SNMP GET","Port","Push","Uptime","MeshCore Node","Unknown"};
      int svcTypeId = (int)services[i].type;
      if (svcTypeId < 0 || svcTypeId > 7) svcTypeId = 7;
      String typeLabel = svcTypeName[svcTypeId];
      String infoStr = "Type: " + typeLabel;
      if (services[i].type != TYPE_MESHCORE_NODE) infoStr += " | Host: " + services[i].host;
      html += "<div class='service-info'>" + infoStr + "</div>";
      if (services[i].type == TYPE_PUSH) {
        String pushUrl = getPushUrl(services[i]);
        if (pushUrl.length() > 0) {
          html += "<div class='service-info'>Push URL: " + pushUrl + "</div>";
        }
      }
      if (services[i].type == TYPE_MESHCORE_NODE && services[i].meshLastResponseMs > 0) {
        String battColor = services[i].meshLastBatteryPct >= 50 ? "#48bb78" : (services[i].meshLastBatteryPct >= 20 ? "#d69e2e" : "#f56565");
        html += "<div class='service-info'>Battery: <span style='color:" + battColor + ";font-weight:600'>" +
                String(services[i].meshLastBatteryPct) + "% (" + String(services[i].meshLastBatteryV, 2) + "V)</span>";
        if (services[i].meshRepeaterControl) {
          html += " | Repeater: " + String(services[i].meshRepeaterKnownState ? "on" : "off");
        }
        html += "</div>";
      }
      if (services[i].lastError.length() > 0) {
        html += "<div class='service-error'>" + services[i].lastError + "</div>";
      }
      // Show enabled alert channels (only show those that are globally enabled)
      String channels = "";
      if (settings.loraEnabled && services[i].alertLora) channels += "📡";
      if (settings.ntfyEnabled && services[i].alertNtfy) channels += "🔔";
      if (settings.discordEnabled && services[i].alertDiscord) channels += "💬";
      if (settings.webhookEnabled && services[i].alertWebhook) channels += "🌐";
      if (settings.emailEnabled && services[i].alertEmail) channels += "📧";
      if (settings.mqttEnabled && services[i].alertMqtt) channels += "📨";
      if (services[i].alertWol) channels += "⏰";
      if (channels.length() > 0) {
        html += "<div class='service-info' style='margin-top:4px;font-size:12px;opacity:0.85'>Alerts: " + channels + "</div>";
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
      html += "<button class='btn btn-secondary' onclick='gotoLora()'>📡 LoRa Stats</button>";
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
    html += "<option value='4'>Push</option><option value='5'>Uptime</option>";
    html += "<option value='6'>MeshCore Node</option></select></div>";
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
    // WoL MAC Address field
    html += "<div class='form-group'><label class='form-label'>WoL MAC Address</label>";
    html += "<input type='text' id='serviceWolMac' class='form-input' placeholder='AA:BB:CC:DD:EE:FF (auto-discovered if empty)'></div>";
    // MeshCore Node fields (shown only for type 6)
    html += "<div class='form-group' data-types='6'><label class='form-label'>Node Public Key (64 hex chars)</label>";
    html += "<input type='text' id='serviceMeshPubkey' class='form-input' placeholder='e.g. 01ab23cd...' maxlength='64'></div>";
    html += "<div class='form-group' data-types='6'><label class='form-label'>Remote Command PIN</label>";
    html += "<input type='text' id='serviceMeshPin' class='form-input' placeholder='PIN used to authenticate commands'></div>";
    html += "<div class='form-group' data-types='6'><label class='form-label' style='display:flex;align-items:center;gap:8px'>";
    html += "<input type='checkbox' id='serviceMeshRepeaterControl'>Enable Automated Repeater Control</label></div>";
    html += "<div class='form-row' data-types='6'>";
    html += "<div class='form-group'><label class='form-label'>Disable Repeater Below (%)</label>";
    html += "<input type='number' id='serviceMeshBattLow' class='form-input' value='20' min='0' max='100'></div>";
    html += "<div class='form-group'><label class='form-label'>Re-enable Repeater Above (%)</label>";
    html += "<input type='number' id='serviceMeshBattHigh' class='form-input' value='50' min='0' max='100'></div></div>";
    // Alert channel toggles (only globally-enabled channels shown via JS)
    html += "<div class='form-group' id='alertChannelsGroup'><label class='form-label'>Alert Channels</label>";
    html += "<div id='alertChannelsContainer' style='display:flex;flex-wrap:wrap;gap:12px;margin-top:4px'></div></div>";
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
    html += "const globalChannels=" + getGlobalAlertChannelsJson() + ";";
    html += "const isAuthed=" + String(isAuthed ? "true" : "false") + ";";
    html += "let modalOpen=false;";
    // Alert channel rendering helper
    html += "const channelDefs=[{key:'lora',label:'📡 LoRa',field:'alertLora'},{key:'ntfy',label:'🔔 Ntfy',field:'alertNtfy'},{key:'discord',label:'💬 Discord',field:'alertDiscord'},{key:'webhook',label:'🌐 Webhook',field:'alertWebhook'},{key:'email',label:'📧 Email',field:'alertEmail'},{key:'mqtt',label:'📨 MQTT',field:'alertMqtt'},{key:'wol',label:'⏰ WoL',field:'alertWol',alwaysShow:true}];";;
    html += "function renderAlertChannels(vals){const c=document.getElementById('alertChannelsContainer');c.innerHTML='';let any=false;channelDefs.forEach(ch=>{if(!ch.alwaysShow&&!globalChannels[ch.key])return;any=true;const lbl=document.createElement('label');lbl.style.cssText='display:flex;align-items:center;gap:4px;font-size:14px;cursor:pointer';const cb=document.createElement('input');cb.type='checkbox';cb.id='alert_'+ch.field;cb.checked=vals[ch.field]===true;lbl.appendChild(cb);lbl.appendChild(document.createTextNode(ch.label));c.appendChild(lbl);});document.getElementById('alertChannelsGroup').style.display=any?'':'none';}";
    html += "function getAlertChannelValues(){const v={};channelDefs.forEach(ch=>{const el=document.getElementById('alert_'+ch.field);v[ch.field]=el?el.checked:true;});return v;}";
    html += "function updateFieldVisibility(type){document.querySelectorAll('[data-types]').forEach(el=>{const types=el.getAttribute('data-types').split(',');el.style.display=types.includes(String(type))?'':'none';});}";
    html += "document.getElementById('serviceType').addEventListener('change',e=>updateFieldVisibility(e.target.value));";
    html += "function setPushDetails(token){const hidden=document.getElementById('servicePushToken');const url=document.getElementById('servicePushUrl');hidden.value=token||'';if(token){url.value=location.origin+'/push/'+token;url.placeholder='';}else{url.value='';url.placeholder='Generated after saving';}}";
    html += "function showAddModal(){if(!isAuthed){alert('Login required');return;}document.getElementById('modalTitle').textContent='Add Service';";
    html += "document.getElementById('serviceForm').reset();document.getElementById('serviceIndex').value='-1';setPushDetails('');";
    html += "updateFieldVisibility(document.getElementById('serviceType').value);";
    html += "renderAlertChannels({});";
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
    html += "document.getElementById('serviceWolMac').value=s.wolMacAddress||'';";
    html += "document.getElementById('serviceMeshPubkey').value=s.meshNodePubkey||'';";
    html += "document.getElementById('serviceMeshPin').value=s.meshNodePin||'';";
    html += "document.getElementById('serviceMeshRepeaterControl').checked=s.meshRepeaterControl===true;";
    html += "document.getElementById('serviceMeshBattLow').value=s.meshBatteryLowPct!=null?s.meshBatteryLowPct:20;";
    html += "document.getElementById('serviceMeshBattHigh').value=s.meshBatteryHighPct!=null?s.meshBatteryHighPct:50;";
    html += "updateFieldVisibility(s.type);";
    html += "renderAlertChannels(s);";
    html += "document.getElementById('serviceModal').classList.add('show');modalOpen=true;}";
    html += "function deleteService(i){if(!isAuthed){alert('Login required');return;}if(confirm('Delete '+services[i].name+'?')){";
    html += "fetch('/api/service/'+i,{method:'DELETE',credentials:'include'}).then(r=>r.ok?location.reload():alert('Delete failed'))}}";
    html += "async function checkServiceNow(i){try{";
    html += "const res=await fetch('/api/service/check/'+i,{credentials:'include',method:'POST'});";
    html += "const d=await res.json();";
    html += "let msg='Check Results for \"'+services[i].name+'\"\\n\\n';";
    html += "msg+='Result: '+(d.checkPassed?'✅ PASS':'❌ FAIL')+'\\n';";
    html += "msg+='Service: '+d.serviceName+' (Type: '+['HTTP GET','Ping','SNMP GET','Port','Push','Uptime','MeshCore Node'][d.serviceType||0]+')'+(d.target?' @ '+d.target:'')+'\\n';";
    html += "msg+='Detail: '+(d.checkError||'(none)')+'\\n';";
    html += "if(d.serviceType===6){msg+='Battery: '+(d.meshLastBatteryPct||0)+'% ('+(d.meshLastBatteryV||0).toFixed(2)+'V)\\n';msg+='Repeater: '+(d.meshRepeaterKnownState?'on':'off')+'\\n';}";
    html += "msg+='Timestamp: '+new Date((d.timestamp||Math.floor(Date.now()/1000))*1000).toLocaleString()+'\\n';";
    html += "msg+='\\nService will continue its normal check schedule regardless of this result.';";
    html += "alert(msg);";
    html += "}catch(e){alert('Check failed: '+e.message);}}";
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
    html += "failThreshold:parseInt(document.getElementById('serviceFailThreshold').value),";
    html += "wolMacAddress:document.getElementById('serviceWolMac').value,";
    html += "meshNodePubkey:document.getElementById('serviceMeshPubkey').value,";
    html += "meshNodePin:document.getElementById('serviceMeshPin').value,";
    html += "meshRepeaterControl:document.getElementById('serviceMeshRepeaterControl').checked,";
    html += "meshBatteryLowPct:parseInt(document.getElementById('serviceMeshBattLow').value)||20,";
    html += "meshBatteryHighPct:parseInt(document.getElementById('serviceMeshBattHigh').value)||50};";
    html += "Object.assign(data,getAlertChannelValues());";
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
    html += "function gotoLora(){if(!isAuthed){alert('Login required');return;}window.open('/lora','_blank');}";
    html += "const loginForm=document.getElementById('loginForm');";
    html += "if(loginForm){loginForm.addEventListener('submit',async e=>{e.preventDefault();const fd=new FormData(loginForm);const res=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({username:fd.get('username'),password:fd.get('password')})});if(res.ok){location.reload();}else{alert('Invalid credentials');}});}";
    html += "function logout(){fetch('/api/logout',{method:'POST',credentials:'include'}).then(()=>location.reload());}";
    html += "setInterval(()=>{if(!modalOpen) location.reload();},30000);";
    html += "updateFieldVisibility(document.getElementById('serviceType').value);";
    html += "</script>";
    html += "<script>";
    html += "(function(){";
    html += "var c=document.getElementById('meshBg'),ctx=c.getContext('2d');";
    html += "var dots=[],MAX=60,DIST=120;";
    html += "function resize(){c.width=window.innerWidth;c.height=window.innerHeight;}";
    html += "window.addEventListener('resize',resize);resize();";
    html += "for(var i=0;i<MAX;i++){dots.push({x:Math.random()*c.width,y:Math.random()*c.height,vx:(Math.random()-0.5)*0.6,vy:(Math.random()-0.5)*0.6,r:Math.random()*1.5+1});}";
    html += "function draw(){ctx.clearRect(0,0,c.width,c.height);";
    html += "for(var i=0;i<dots.length;i++){var d=dots[i];d.x+=d.vx;d.y+=d.vy;";
    html += "if(d.x<0||d.x>c.width)d.vx*=-1;if(d.y<0||d.y>c.height)d.vy*=-1;";
    html += "ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fillStyle='rgba(72,187,120,0.8)';ctx.fill();";
    html += "for(var j=i+1;j<dots.length;j++){var e=dots[j],dx=d.x-e.x,dy=d.y-e.y,dist=Math.sqrt(dx*dx+dy*dy);";
    html += "if(dist<DIST){ctx.beginPath();ctx.moveTo(d.x,d.y);ctx.lineTo(e.x,e.y);";
    html += "ctx.strokeStyle='rgba(72,187,120,'+(1-dist/DIST)*0.4+')';ctx.lineWidth=0.8;ctx.stroke();}}}";
    html += "requestAnimationFrame(draw);}draw();})();";
    html += "</script>";
    html += "</body></html>";
    request->send(200, "text/html", html);
  });

  // Captive portal save (allowed only while captive portal provisioning is active)
  server.on("/captive/save", HTTP_POST, [](AsyncWebServerRequest *request){
    if (!captivePortalActive || isWifiConfigured()) {
      request->send(403, "text/html", "<html><body>Captive portal is not active. <a href='/'>Back</a></body></html>");
      return;
    }

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
    if (captivePortalActive && !isWifiConfigured()) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(204);
  });
  server.on("/hotspot-detect.html", HTTP_GET, [](AsyncWebServerRequest *request){
    if (captivePortalActive && !isWifiConfigured()) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(404);
  });
  server.on("/fwlink", HTTP_GET, [](AsyncWebServerRequest *request){
    if (captivePortalActive && !isWifiConfigured()) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(404);
  });

  // Windows captive portal checks
  server.on("/connecttest.txt", HTTP_GET, [](AsyncWebServerRequest *request){
    if (captivePortalActive && !isWifiConfigured()) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(404);
  });
  server.on("/ncsi.txt", HTTP_GET, [](AsyncWebServerRequest *request){
    if (captivePortalActive && !isWifiConfigured()) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(404);
  });

  // Apple/macOS/iOS captive portal checks
  server.on("/library/test/success.html", HTTP_GET, [](AsyncWebServerRequest *request){
    if (captivePortalActive && !isWifiConfigured()) request->redirect(String("http://") + captiveApIp.toString() + "/");
    else request->send(404);
  });

  // Kiosk view: stats + services only, no actions/controls
  server.on("/kiosk", HTTP_GET, [](AsyncWebServerRequest *request) {
    String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>Kiosk</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#000;color:#e2e8f0;margin:0;padding:20px;overflow-x:hidden;}";
    html += "#meshBg{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0}";
    html += ".container{max-width:1100px;margin:0 auto;position:relative;z-index:1;}";
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
    html += "</style></head><body><canvas id='meshBg'></canvas><div class='container'>";

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
    html += "</div><script>setInterval(()=>location.reload(),20000);";
    html += "(function(){";
    html += "var c=document.getElementById('meshBg'),ctx=c.getContext('2d');";
    html += "var dots=[],MAX=60,DIST=120;";
    html += "function resize(){c.width=window.innerWidth;c.height=window.innerHeight;}";
    html += "window.addEventListener('resize',resize);resize();";
    html += "for(var i=0;i<MAX;i++){dots.push({x:Math.random()*c.width,y:Math.random()*c.height,vx:(Math.random()-0.5)*0.6,vy:(Math.random()-0.5)*0.6,r:Math.random()*1.5+1});}";
    html += "function draw(){ctx.clearRect(0,0,c.width,c.height);";
    html += "for(var i=0;i<dots.length;i++){var d=dots[i];d.x+=d.vx;d.y+=d.vy;";
    html += "if(d.x<0||d.x>c.width)d.vx*=-1;if(d.y<0||d.y>c.height)d.vy*=-1;";
    html += "ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fillStyle='rgba(72,187,120,0.8)';ctx.fill();";
    html += "for(var j=i+1;j<dots.length;j++){var e=dots[j],dx=d.x-e.x,dy=d.y-e.y,dist=Math.sqrt(dx*dx+dy*dy);";
    html += "if(dist<DIST){ctx.beginPath();ctx.moveTo(d.x,d.y);ctx.lineTo(e.x,e.y);";
    html += "ctx.strokeStyle='rgba(72,187,120,'+(1-dist/DIST)*0.4+')';ctx.lineWidth=0.8;ctx.stroke();}}}";
    html += "requestAnimationFrame(draw);}draw();})();";
    html += "</script></body></html>";
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
      obj["alertLora"] = services[i].alertLora;
      obj["alertNtfy"] = services[i].alertNtfy;
      obj["alertDiscord"] = services[i].alertDiscord;
      obj["alertWebhook"] = services[i].alertWebhook;
      obj["alertEmail"] = services[i].alertEmail;
      obj["alertMqtt"] = services[i].alertMqtt;
      obj["alertWol"] = services[i].alertWol;
      obj["wolMacAddress"] = services[i].wolMacAddress;
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
            svc.alertLora = obj["alertLora"].isNull() ? true : obj["alertLora"].as<bool>();
            svc.alertNtfy = obj["alertNtfy"].isNull() ? true : obj["alertNtfy"].as<bool>();
            svc.alertDiscord = obj["alertDiscord"].isNull() ? true : obj["alertDiscord"].as<bool>();
            svc.alertWebhook = obj["alertWebhook"].isNull() ? true : obj["alertWebhook"].as<bool>();
            svc.alertEmail = obj["alertEmail"].isNull() ? true : obj["alertEmail"].as<bool>();
            svc.alertMqtt = obj["alertMqtt"].isNull() ? true : obj["alertMqtt"].as<bool>();
            svc.alertWol = obj["alertWol"].isNull() ? false : obj["alertWol"].as<bool>();
            svc.wolMacAddress = obj["wolMacAddress"].isNull() ? "" : obj["wolMacAddress"].as<String>();
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
      svc.alertLora = doc["alertLora"].isNull() ? true : doc["alertLora"].as<bool>();
      svc.alertNtfy = doc["alertNtfy"].isNull() ? true : doc["alertNtfy"].as<bool>();
      svc.alertDiscord = doc["alertDiscord"].isNull() ? true : doc["alertDiscord"].as<bool>();
      svc.alertWebhook = doc["alertWebhook"].isNull() ? true : doc["alertWebhook"].as<bool>();
      svc.alertEmail = doc["alertEmail"].isNull() ? true : doc["alertEmail"].as<bool>();
      svc.alertMqtt = doc["alertMqtt"].isNull() ? true : doc["alertMqtt"].as<bool>();
      svc.alertWol = doc["alertWol"].isNull() ? false : doc["alertWol"].as<bool>();
      svc.wolMacAddress = doc["wolMacAddress"].isNull() ? "" : doc["wolMacAddress"].as<String>();
      // MeshCore Node fields
      svc.meshNodePubkey = doc["meshNodePubkey"].isNull() ? "" : doc["meshNodePubkey"].as<String>();
      svc.meshNodePin = doc["meshNodePin"].isNull() ? "" : doc["meshNodePin"].as<String>();
      svc.meshRepeaterControl = doc["meshRepeaterControl"].isNull() ? false : doc["meshRepeaterControl"].as<bool>();
      svc.meshBatteryLowPct = doc["meshBatteryLowPct"].isNull() ? 20 : doc["meshBatteryLowPct"].as<int>();
      svc.meshBatteryHighPct = doc["meshBatteryHighPct"].isNull() ? 50 : doc["meshBatteryHighPct"].as<int>();
      svc.meshLastBatteryPct = 0;
      svc.meshLastBatteryV = 0.0f;
      svc.meshLastResponseMs = 0;
      svc.meshRepeaterKnownState = true;
      // Auto-discover MAC address if WoL enabled but no MAC specified
      if (svc.alertWol && svc.wolMacAddress.length() == 0) {
        String ip = getServiceIp(svc);
        if (ip.length() > 0) {
          svc.wolMacAddress = discoverMacFromIp(ip);
        }
      }
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
      services[idx].alertLora = doc["alertLora"].isNull() ? true : doc["alertLora"].as<bool>();
      services[idx].alertNtfy = doc["alertNtfy"].isNull() ? true : doc["alertNtfy"].as<bool>();
      services[idx].alertDiscord = doc["alertDiscord"].isNull() ? true : doc["alertDiscord"].as<bool>();
      services[idx].alertWebhook = doc["alertWebhook"].isNull() ? true : doc["alertWebhook"].as<bool>();
      services[idx].alertEmail = doc["alertEmail"].isNull() ? true : doc["alertEmail"].as<bool>();
      services[idx].alertMqtt = doc["alertMqtt"].isNull() ? true : doc["alertMqtt"].as<bool>();
      services[idx].alertWol = doc["alertWol"].isNull() ? false : doc["alertWol"].as<bool>();
      services[idx].wolMacAddress = doc["wolMacAddress"].isNull() ? "" : doc["wolMacAddress"].as<String>();
      // MeshCore Node fields
      services[idx].meshNodePubkey = doc["meshNodePubkey"].isNull() ? "" : doc["meshNodePubkey"].as<String>();
      services[idx].meshNodePin = doc["meshNodePin"].isNull() ? "" : doc["meshNodePin"].as<String>();
      services[idx].meshRepeaterControl = doc["meshRepeaterControl"].isNull() ? false : doc["meshRepeaterControl"].as<bool>();
      services[idx].meshBatteryLowPct = doc["meshBatteryLowPct"].isNull() ? 20 : doc["meshBatteryLowPct"].as<int>();
      services[idx].meshBatteryHighPct = doc["meshBatteryHighPct"].isNull() ? 50 : doc["meshBatteryHighPct"].as<int>();
      // Auto-discover MAC address if WoL enabled but no MAC specified
      if (services[idx].alertWol && services[idx].wolMacAddress.length() == 0) {
        String ip = getServiceIp(services[idx]);
        if (ip.length() > 0) {
          services[idx].wolMacAddress = discoverMacFromIp(ip);
        }
      }
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

  // API endpoint to immediately run a service check (Check Now)
  server.on("^/api/service/check/([0-9]+)$", HTTP_POST, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    int idx = request->pathArg(0).toInt();
    if (idx < 0 || idx >= serviceCount) {
      request->send(404, "application/json", "{\"error\":\"Service not found\"}");
      return;
    }

    Service& svc = services[idx];
    bool result = false;

    // Save state before check
    int prevPasses = svc.consecutivePasses;
    int prevFails = svc.consecutiveFails;
    bool prevIsUp = svc.isUp;
    bool prevPending = svc.isPending;
    String prevError = svc.lastError;

    switch (svc.type) {
      case TYPE_HTTP_GET:   result = checkHttpGet(svc); break;
      case TYPE_PING:       result = checkPing(svc); break;
      case TYPE_PORT:       result = checkPort(svc); break;
      case TYPE_SNMP_GET:   result = checkSnmpGet(svc); break;
      case TYPE_PUSH:       result = checkPush(svc); break;
      case TYPE_UPTIME:     result = checkUptime(svc); break;
      case TYPE_MESHCORE_NODE: result = checkMeshNode(svc); break;
      default:
        svc.lastError = "Unknown service type";
        result = false;
    }

    // Restore state (don't affect thresholds/notifications from a manual check)
    svc.consecutivePasses = prevPasses;
    svc.consecutiveFails = prevFails;
    svc.isUp = prevIsUp;
    svc.isPending = prevPending;

    JsonDocument doc;
    doc["checkPassed"] = result;
    doc["error"] = svc.lastError;
    doc["serviceName"] = svc.name;
    doc["serviceType"] = (int)svc.type;
    doc["host"] = svc.host;
    doc["port"] = svc.port;
    doc["url"] = svc.url;

    // Capture the check result before restoring the previous error
    String checkError = svc.lastError;
    svc.lastError = prevError;

    doc["checkError"] = checkError;

    // Add type-specific details
    if (svc.type == TYPE_PING || svc.type == TYPE_PORT) {
      doc["target"] = svc.host;
      if (svc.port > 0) doc["port"] = svc.port;
    } else if (svc.type == TYPE_HTTP_GET) {
      doc["url"] = svc.url;
      doc["expectedResponse"] = svc.expectedResponse;
    } else if (svc.type == TYPE_SNMP_GET) {
      doc["snmpOid"] = svc.snmpOid;
      doc["snmpExpectedValue"] = svc.snmpExpectedValue;
    } else if (svc.type == TYPE_MESHCORE_NODE) {
      doc["meshNodePubkey"] = svc.meshNodePubkey;
      doc["meshLastBatteryPct"] = svc.meshLastBatteryPct;
      doc["meshLastBatteryV"] = svc.meshLastBatteryV;
      doc["meshRepeaterKnownState"] = svc.meshRepeaterKnownState;
    }

    doc["timestamp"] = (unsigned long)time(nullptr);

    String json;
    serializeJson(doc, json);
    request->send(200, "application/json", json);
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
    page += "<title>OTA Update</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#000;min-height:100vh;padding:24px;color:#2d3748;overflow-x:hidden;}";
    page += "#meshBg{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0}";
    page += ".card{max-width:520px;margin:0 auto;background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:16px;padding:24px;box-shadow:0 8px 32px rgba(0,0,0,0.1);position:relative;z-index:1;}";
    page += "h1{margin:0 0 12px;font-size:24px;}p{margin:0 0 16px;color:#4a5568;}.warn{color:#e53e3e;font-size:14px;margin-bottom:16px;}";
    page += "input[type=file]{width:100%;padding:12px;border:2px dashed #cbd5e0;border-radius:10px;background:#f8fafc;cursor:pointer;margin-bottom:16px;}";
    page += "button{padding:12px 18px;border:none;border-radius:8px;background:#667eea;color:#fff;font-weight:600;cursor:pointer;}";
    page += "button:disabled{opacity:0.6;cursor:not-allowed;}";
    page += "#status{margin-top:12px;font-weight:600;}.progress-bar{width:100%;height:8px;background:#e2e8f0;border-radius:4px;margin:12px 0;overflow:hidden;}";
    page += ".progress-fill{height:100%;background:#667eea;width:0;transition:width 0.3s;}";
    page += "</style></head><body><canvas id='meshBg'></canvas><div class='card'><h1>OTA Firmware Update</h1><p>Select a .bin file to upload and flash. Device will reboot after a successful update.</p>";
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
    page += "</script></div>";
    page += "<script>";
    page += "(function(){";
    page += "var c=document.getElementById('meshBg'),ctx=c.getContext('2d');";
    page += "var dots=[],MAX=60,DIST=120;";
    page += "function resize(){c.width=window.innerWidth;c.height=window.innerHeight;}";
    page += "window.addEventListener('resize',resize);resize();";
    page += "for(var i=0;i<MAX;i++){dots.push({x:Math.random()*c.width,y:Math.random()*c.height,vx:(Math.random()-0.5)*0.6,vy:(Math.random()-0.5)*0.6,r:Math.random()*1.5+1});}";
    page += "function draw(){ctx.clearRect(0,0,c.width,c.height);";
    page += "for(var i=0;i<dots.length;i++){var d=dots[i];d.x+=d.vx;d.y+=d.vy;";
    page += "if(d.x<0||d.x>c.width)d.vx*=-1;if(d.y<0||d.y>c.height)d.vy*=-1;";
    page += "ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fillStyle='rgba(72,187,120,0.8)';ctx.fill();";
    page += "for(var j=i+1;j<dots.length;j++){var e=dots[j],dx=d.x-e.x,dy=d.y-e.y,dist=Math.sqrt(dx*dx+dy*dy);";
    page += "if(dist<DIST){ctx.beginPath();ctx.moveTo(d.x,d.y);ctx.lineTo(e.x,e.y);";
    page += "ctx.strokeStyle='rgba(72,187,120,'+(1-dist/DIST)*0.4+')';ctx.lineWidth=0.8;ctx.stroke();}}}";
    page += "requestAnimationFrame(draw);}draw();})();";
    page += "</script></body></html>";
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
      // Require shared secret to prevent unauthenticated message injection
      if (settings.channelSecret.length() == 0) {
        request->send(503, "application/json", "{\"error\":\"inbound webhook secret not configured\"}");
        return;
      }
      if (!request->hasHeader("X-Webhook-Secret") || request->header("X-Webhook-Secret") != settings.channelSecret) {
        request->send(401, "application/json", "{\"error\":\"unauthorized\"}");
        return;
      }

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
    if (captivePortalActive && !isWifiConfigured()) {
      // Redirect any unknown path to the portal page (helps trigger OS captive portal UX)
      request->redirect(String("http://") + captiveApIp.toString() + "/");
      return;
    }
    request->send(404, "text/plain", "Not found");
  });

  // Auto OTA status endpoint
  server.on("/api/auto-ota/status", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    JsonDocument doc;
    doc["enabled"] = settings.autoOtaEnabled;  // 0=off, 1=on, 2=delayed
    doc["currentVersion"] = String(FIRMWARE_VERSION);
    doc["latestVersion"] = autoOtaLatestVersion;
    doc["latestUrl"] = autoOtaLatestUrl;
    doc["latestNotes"] = autoOtaLatestNotes;
    doc["lastCheckStatus"] = autoOtaLastCheckStatus;
    doc["checkIntervalSec"] = settings.autoOtaCheckInterval;
    doc["updateInProgress"] = autoOtaUpdateInProgress;
    doc["otaUrl"] = settings.autoOtaUrl;
    String json;
    serializeJson(doc, json);
    request->send(200, "application/json", json);
  });

  // Auto OTA check-now endpoint (check only, don't apply)
  server.on("/api/auto-ota/check", HTTP_POST, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    if (autoOtaUpdateInProgress) {
      request->send(409, "application/json", "{\"error\":\"update already in progress\"}");
      return;
    }
    bool found = checkAutoOtaUpdate(false);
    JsonDocument doc;
    doc["updateAvailable"] = found;
    doc["currentVersion"] = String(FIRMWARE_VERSION);
    doc["latestVersion"] = autoOtaLatestVersion;
    doc["latestNotes"] = autoOtaLatestNotes;
    doc["status"] = autoOtaLastCheckStatus;
    String json;
    serializeJson(doc, json);
    request->send(200, "application/json", json);
  });

  // Auto OTA apply-now endpoint (download and flash)
  server.on("/api/auto-ota/apply", HTTP_POST, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    if (autoOtaUpdateInProgress) {
      request->send(409, "application/json", "{\"error\":\"update already in progress\"}");
      return;
    }
    request->send(200, "application/json", "{\"status\":\"starting update\"}");
    // Defer the actual update to loop() — httpUpdate.update() is a long blocking
    // call that cannot run inside an AsyncWebServer handler without corrupting
    // the WiFi/TCP stack.
    autoOtaApplyRequested = true;
  });

  // LoRa Stats JSON API
  server.on("/api/lora-stats", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;

    JsonDocument doc;

    // Radio info
    doc["enabled"] = settings.loraEnabled;
    doc["lastRssi"] = lastRssi;
    doc["lastSnr"] = lastSnr;
    doc["messageCount"] = messageCount;
    doc["lastMessageTime"] = (unsigned long)lastMessageTime;

    // Peers
    JsonArray peersArr = doc["peers"].to<JsonArray>();
    for (int i = 0; i < MAX_PEERS; i++) {
      if (!peers[i].inUse) continue;
      JsonObject p = peersArr.add<JsonObject>();
      // Sanitize peer name: strip control characters that break JSON
      String safeName;
      safeName.reserve(peers[i].name.length());
      for (unsigned int c = 0; c < peers[i].name.length(); c++) {
        char ch = peers[i].name[c];
        if (ch >= 0x20 && ch != 0x7F) safeName += ch;  // printable ASCII only
      }
      p["name"] = safeName;
      p["hash"] = peers[i].hash;
      p["type"] = nodeTypeName(peers[i].nodeType);
      p["typeId"] = peers[i].nodeType;
      p["lastAdvert"] = peers[i].lastAdvert;
      // Pubkey as hex
      char hexPub[65];
      for (int b = 0; b < 32; b++) snprintf(hexPub + b * 2, 3, "%02x", peers[i].ed25519_pub[b]);
      p["pubkey"] = String(hexPub);
    }

    // Storage info
    doc["logBudget"] = (unsigned long)getLoraLogBudget();
    doc["totalBytes"] = (unsigned long)LittleFS.totalBytes();
    doc["usedBytes"] = (unsigned long)LittleFS.usedBytes();

    String json;
    json.reserve(measureJson(doc) + 1);
    serializeJson(doc, json);
    request->send(200, "application/json", json);
  });

  // LoRa message log (raw CSV)
  server.on("/api/lora-log", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    if (!LittleFS.exists(LORA_LOG_FILE)) {
      request->send(200, "text/plain", "");
      return;
    }
    request->send(LittleFS, LORA_LOG_FILE, "text/plain");
  });

  // Clear LoRa log
  server.on("/api/lora-log", HTTP_DELETE, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    if (LittleFS.exists(LORA_LOG_FILE)) LittleFS.remove(LORA_LOG_FILE);
    request->send(200, "application/json", "{\"status\":\"ok\"}");
  });

  // LoRa Stats HTML page
  server.on("/lora", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;

    AsyncResponseStream *response = request->beginResponseStream("text/html");

    // Head + CSS
    response->print("<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>LoRa Stats</title>");
    response->print("<style>");
    response->print("*{margin:0;padding:0;box-sizing:border-box}");
    response->print("body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#000;min-height:100vh;padding:20px;color:#2d3748;overflow-x:hidden}");
    response->print("#meshBg{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0}");
    response->print(".container{max-width:1000px;margin:0 auto;position:relative;z-index:1}");
    response->print(".card{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:16px;padding:24px;margin-bottom:20px;box-shadow:0 8px 32px rgba(0,0,0,0.1)}");
    response->print("h1{font-size:22px;margin-bottom:6px;color:#2d3748}");
    response->print("h2{font-size:16px;margin:0 0 12px;color:#4a5568}");
    response->print(".stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:16px}");
    response->print(".stat-card{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:12px;padding:18px;text-align:center;box-shadow:0 4px 16px rgba(0,0,0,0.06)}");
    response->print(".stat-value{font-size:28px;font-weight:700;color:#2d3748;margin-bottom:2px}");
    response->print(".stat-label{font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:1px}");
    response->print("table{width:100%;border-collapse:collapse;font-size:13px}");
    response->print("th{text-align:left;padding:10px 8px;border-bottom:2px solid #e2e8f0;font-weight:600;color:#4a5568;font-size:12px;text-transform:uppercase;letter-spacing:0.5px}");
    response->print("td{padding:8px;border-bottom:1px solid #edf2f7;color:#2d3748}");
    response->print("tr:hover{background:#f7fafc}");
    response->print(".badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:600}");
    response->print(".badge-client{background:#ebf4ff;color:#3182ce}");
    response->print(".badge-repeater{background:#fefcbf;color:#b7791f}");
    response->print(".badge-router{background:#c6f6d5;color:#276749}");
    response->print(".badge-unknown{background:#edf2f7;color:#718096}");
    response->print(".badge-ok{background:#c6f6d5;color:#276749}");
    response->print(".badge-fail{background:#fed7d7;color:#c53030}");
    response->print(".badge-sent{background:#e9d8fd;color:#6b46c1}");
    response->print(".badge-recv{background:#bee3f8;color:#2b6cb0}");
    response->print(".mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:11px}");
    response->print(".btns{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}");
    response->print(".btn{padding:10px 14px;border:none;border-radius:10px;cursor:pointer;font-weight:700;font-size:13px;text-decoration:none;display:inline-flex;align-items:center;gap:6px}");
    response->print(".primary{background:#667eea;color:#fff}");
    response->print(".secondary{background:#e2e8f0;color:#2d3748}");
    response->print(".danger{background:#fed7d7;color:#c53030}");
    response->print(".truncate{max-width:280px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:inline-block;vertical-align:middle}");
    response->print(".hint{font-size:12px;color:#718096;margin-top:6px}");
    response->print(".empty{text-align:center;padding:24px;color:#a0aec0;font-size:14px}");
    response->print(".storage-bar{width:100%;height:8px;background:#e2e8f0;border-radius:4px;overflow:hidden;margin-top:8px}");
    response->print(".storage-fill{height:100%;background:linear-gradient(90deg,#667eea,#764ba2);border-radius:4px;transition:width 0.3s}");
    response->print("@media(max-width:700px){.stats{grid-template-columns:1fr 1fr}table{font-size:12px}.truncate{max-width:140px}}");
    response->print("</style></head><body><canvas id='meshBg'></canvas><div class='container'>");

    // Header
    response->printf("<div class='card'><h1>%s LoRa Stats</h1>", "\xF0\x9F\x93\xA1");
    response->print("<div class='hint'>Radio statistics, known peers, and message history.</div>");
    response->printf("<div class='btns'><a href='/' class='btn secondary'>%s Dashboard</a>", "\xE2\x86\x90");
    response->printf("<button class='btn secondary' onclick='location.reload()'>%s Refresh</button>", "\xE2\x86\xBB");
    response->printf("<button class='btn danger' id='clearBtn' onclick='clearLog()'>%s Clear Log</button></div></div>", "\xF0\x9F\x97\x91");

    // Stats cards
    response->print("<div class='stats'>");
    response->print("<div class='stat-card'><div class='stat-value' id='msgCount'>-</div><div class='stat-label'>Messages</div></div>");
    response->print("<div class='stat-card'><div class='stat-value' id='peerCount'>-</div><div class='stat-label'>Known Peers</div></div>");
    response->print("<div class='stat-card'><div class='stat-value' id='rssiVal'>-</div><div class='stat-label'>Last RSSI</div></div>");
    response->print("<div class='stat-card'><div class='stat-value' id='snrVal'>-</div><div class='stat-label'>Last SNR</div></div>");
    response->print("</div>");

    // Peers table
    response->print("<div class='card'><h2>Known Peers</h2>");
    response->print("<div id='peersTable'><div class='empty'>Loading...</div></div></div>");

    // Message log table
    response->print("<div class='card'><h2>Message History</h2>");
    response->print("<div id='storageInfo'></div>");
    response->print("<div id='logTable'><div class='empty'>Loading...</div></div></div>");

    response->print("</div>");

    // JavaScript
    response->print("<script>");
    response->print("const typeLabels={D:'Direct',G:'Group',A:'ACK',N:'Notification',V:'Advert'};");
    response->print("const typeBadge={Client:'badge-client',Repeater:'badge-repeater',Router:'badge-router',Unknown:'badge-unknown'};");
    response->print("function ago(ts){if(!ts)return 'Never';const s=Math.floor(Date.now()/1000)-ts;if(s<60)return s+'s ago';if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';}");
    response->print("function fmtTime(ts){if(!ts)return '-';return new Date(ts*1000).toLocaleString();}");
    response->print("function escHtml(v){const s=String(v??'');return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('\\\"','&quot;').replaceAll(\"'\",'&#39;');}");

    // loadStats with error handling and retry
    response->print("let statsRetry=0;");
    response->print("async function loadStats(){try{");
    response->print("const res=await fetch('/api/lora-stats',{credentials:'include'});");
    response->print("if(!res.ok){document.getElementById('peersTable').innerHTML='<div class=\"empty\">Failed to load peers (HTTP '+res.status+'). <a href=\"#\" onclick=\"loadStats();return false\">Retry</a></div>';return;}");
    response->print("const d=await res.json();");
    response->print("statsRetry=0;");
    response->print("document.getElementById('msgCount').textContent=d.messageCount||0;");
    response->print("document.getElementById('peerCount').textContent=d.peers?d.peers.length:0;");
    response->print("document.getElementById('rssiVal').textContent=d.lastRssi?d.lastRssi+' dBm':'-';");
    response->print("document.getElementById('snrVal').textContent=d.lastSnr?(d.lastSnr).toFixed(1)+' dB':'-';");

    // Peers table
    response->print("if(d.peers&&d.peers.length>0){");
    response->print("let h='<table><tr><th>Name</th><th>Type</th><th>Hash</th><th>Last Seen</th></tr>';");
    response->print("for(const p of d.peers){");
    response->print("const cls=typeBadge[p.type]||'badge-unknown';");
    response->print("h+='<tr><td>'+((p.name&&p.name.length)?escHtml(p.name):'<em>unnamed</em>')+'</td>';");
    response->print("h+='<td><span class=\"badge '+cls+'\">'+escHtml(p.type||'-')+'</span></td>';");
    response->print("h+='<td class=\"mono\">0x'+p.hash.toString(16).toUpperCase().padStart(2,'0')+'</td>';");
    response->print("h+='<td>'+ago(p.lastAdvert)+'</td></tr>';}");
    response->print("h+='</table>';document.getElementById('peersTable').innerHTML=h;");
    response->print("}else{document.getElementById('peersTable').innerHTML='<div class=\"empty\">No peers discovered yet</div>';}");

    // Storage bar
    response->print("if(d.totalBytes){const pct=Math.min(100,((d.usedBytes||0)/d.totalBytes*100)).toFixed(1);");
    response->print("const logPct=((d.logBudget||0)/d.totalBytes*100).toFixed(1);");
    response->print("document.getElementById('storageInfo').innerHTML='<div class=\"hint\">Storage: '+(d.usedBytes/1024).toFixed(0)+'KB / '+(d.totalBytes/1024).toFixed(0)+'KB used ('+pct+'%). LoRa log budget: '+(d.logBudget/1024).toFixed(0)+'KB ('+logPct+'%)</div><div class=\"storage-bar\"><div class=\"storage-fill\" style=\"width:'+pct+'%\"></div></div>';}");

    response->print("}catch(e){console.error('loadStats error:',e);");
    response->print("document.getElementById('peersTable').innerHTML='<div class=\"empty\">Error loading peers: '+escHtml(e.message)+'. <a href=\"#\" onclick=\"loadStats();return false\">Retry</a></div>';");
    response->print("if(statsRetry<3){statsRetry++;setTimeout(loadStats,2000);}}}");

    // loadLog with error handling and retry
    response->print("let logRetry=0;");
    response->print("async function loadLog(){try{");
    response->print("const res=await fetch('/api/lora-log',{credentials:'include'});");
    response->print("if(!res.ok){document.getElementById('logTable').innerHTML='<div class=\"empty\">Failed to load log (HTTP '+res.status+'). <a href=\"#\" onclick=\"loadLog();return false\">Retry</a></div>';return;}");
    response->print("logRetry=0;");
    response->print("const txt=await res.text();");
    response->print("const lines=txt.split('\\n').filter(l=>l.trim().length);");
    response->print("if(lines.length===0){document.getElementById('logTable').innerHTML='<div class=\"empty\">No messages logged yet</div>';return;}");
    response->print("lines.reverse();");
    response->print("let h='<table><tr><th>Time</th><th>Dir</th><th>Type</th><th>Peer</th><th>Message</th><th>Status</th></tr>';");
    response->print("const max=200;const show=lines.slice(0,max);");
    response->print("for(const line of show){const p=line.split(',');if(p.length<6)continue;");
    response->print("const ts=parseInt(p[0]);const dir=p[1];const typ=p[2];const peer=p[3];const msg=p.slice(4,p.length-1).join(',');const st=p[p.length-1];");
    response->print("h+='<tr><td>'+fmtTime(ts)+'</td>';");
    response->print("h+='<td><span class=\"badge '+(dir==='S'?'badge-sent':'badge-recv')+'\">'+(dir==='S'?'Sent':'Recv')+'</span></td>';");
    response->print("h+='<td>'+escHtml(typeLabels[typ]||typ||'-')+'</td>';");
    response->print("h+='<td>'+escHtml(peer||'-')+'</td>';");
    response->print("h+='<td><span class=\"truncate\">'+escHtml(msg||'-')+'</span></td>';");
    response->print("h+='<td><span class=\"badge '+(st==='ok'?'badge-ok':'badge-fail')+'\">'+(st||'-')+'</span></td></tr>';}");
    response->print("if(lines.length>max)h+='<tr><td colspan=\"6\" class=\"hint\">Showing '+max+' of '+lines.length+' entries</td></tr>';");
    response->print("h+='</table>';document.getElementById('logTable').innerHTML=h;");
    response->print("}catch(e){console.error('loadLog error:',e);");
    response->print("document.getElementById('logTable').innerHTML='<div class=\"empty\">Error loading log: '+escHtml(e.message)+'. <a href=\"#\" onclick=\"loadLog();return false\">Retry</a></div>';");
    response->print("if(logRetry<3){logRetry++;setTimeout(loadLog,2000);}}}");

    response->print("async function clearLog(){if(!confirm('Clear LoRa message log?'))return;");
    response->print("await fetch('/api/lora-log',{method:'DELETE',credentials:'include'});location.reload();}");

    response->print("loadStats();loadLog();");
    response->print("</script><script>");
    response->print("(function(){");
    response->print("var c=document.getElementById('meshBg'),ctx=c.getContext('2d');");
    response->print("var dots=[],MAX=60,DIST=120;");
    response->print("function resize(){c.width=window.innerWidth;c.height=window.innerHeight;}");
    response->print("window.addEventListener('resize',resize);resize();");
    response->print("for(var i=0;i<MAX;i++){dots.push({x:Math.random()*c.width,y:Math.random()*c.height,vx:(Math.random()-0.5)*0.6,vy:(Math.random()-0.5)*0.6,r:Math.random()*1.5+1});}");
    response->print("function draw(){ctx.clearRect(0,0,c.width,c.height);");
    response->print("for(var i=0;i<dots.length;i++){var d=dots[i];d.x+=d.vx;d.y+=d.vy;");
    response->print("if(d.x<0||d.x>c.width)d.vx*=-1;if(d.y<0||d.y>c.height)d.vy*=-1;");
    response->print("ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fillStyle='rgba(72,187,120,0.8)';ctx.fill();");
    response->print("for(var j=i+1;j<dots.length;j++){var e=dots[j],dx=d.x-e.x,dy=d.y-e.y,dist=Math.sqrt(dx*dx+dy*dy);");
    response->print("if(dist<DIST){ctx.beginPath();ctx.moveTo(d.x,d.y);ctx.lineTo(e.x,e.y);");
    response->print("ctx.strokeStyle='rgba(72,187,120,'+(1-dist/DIST)*0.4+')';ctx.lineWidth=0.8;ctx.stroke();}}}");
    response->print("requestAnimationFrame(draw);}draw();})();");
    response->print("</script></body></html>");

    request->send(response);
  });

  server.begin();
}

static void startWifiConnectAttempt(bool restoreCaptiveOnFail) {
  wifiAttemptRestoreCaptive = restoreCaptiveOnFail;
  wifiAttemptInProgress = true;
  wifiAttemptStartMs = millis();
  setupWiFi(false);
}

// ============================================
// Auto OTA Update from Web Server
// ============================================

static bool parseSemVer(const String &version, int &major, int &minor, int &patch) {
  int start = 0;
  while (start < (int)version.length() && !isdigit(version[start])) {
    start++;
  }
  if (start >= (int)version.length()) return false;
  return sscanf(version.c_str() + start, "%d.%d.%d", &major, &minor, &patch) == 3;
}

// Compare semantic version strings: returns >0 if b > a, 0 if equal, <0 if a > b
static int compareSemVer(const String &a, const String &b) {
  int aMajor = 0, aMinor = 0, aPatch = 0;
  int bMajor = 0, bMinor = 0, bPatch = 0;
  bool aOk = parseSemVer(a, aMajor, aMinor, aPatch);
  bool bOk = parseSemVer(b, bMajor, bMinor, bPatch);

  if (!aOk && bOk) return 1;   // Non-semver (hash) should always update to semver
  if (aOk && !bOk) return -1;  // Semver should not downgrade to a non-semver
  if (!aOk && !bOk) return 0;

  if (bMajor != aMajor) return bMajor - aMajor;
  if (bMinor != aMinor) return bMinor - aMinor;
  return bPatch - aPatch;
}

// Check remote server for a firmware update and optionally apply it
// Returns true if an update was found (whether or not it was applied)
static bool checkAutoOtaUpdate(bool applyIfAvailable) {
  if (!wifiConnected || WiFi.status() != WL_CONNECTED) {
    Serial.println("[AutoOTA] WiFi not connected, skipping check");
    autoOtaLastCheckStatus = "no-wifi";
    return false;
  }
  if (settings.autoOtaUrl.length() == 0) {
    Serial.println("[AutoOTA] No OTA URL configured");
    autoOtaLastCheckStatus = "no-url";
    return false;
  }

  String versionUrl = settings.autoOtaUrl;
  // Ensure URL ends with /version.json
  if (!versionUrl.endsWith("/version.json")) {
    if (!versionUrl.endsWith("/")) versionUrl += "/";
    versionUrl += "version.json";
  }

  Serial.printf("[AutoOTA] Checking for updates: %s\n", versionUrl.c_str());

  HTTPClient http;
  WiFiClientSecure secureClient;
  bool isSecure = versionUrl.startsWith("https://");

  if (isSecure) {
    http.begin(secureClient, versionUrl);
  } else {
    Serial.println("[AutoOTA] Insecure OTA URL blocked: only HTTPS is allowed");
    autoOtaLastCheckStatus = "insecure-url";
    return false;
  }

  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setTimeout(15000);

  int httpCode = http.GET();
  if (httpCode != 200) {
    Serial.printf("[AutoOTA] Version check failed, HTTP %d\n", httpCode);
    http.end();
    autoOtaLastCheckStatus = "http-error-" + String(httpCode);
    return false;
  }

  String payload = http.getString();
  http.end();

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, payload);
  if (err) {
    Serial.printf("[AutoOTA] Failed to parse version.json: %s\n", err.c_str());
    autoOtaLastCheckStatus = "parse-error";
    return false;
  }

  String remoteVersion = doc["version"] | "";
  String firmwareUrl = doc["url"] | "";
  String notes = doc["notes"] | "";

  if (remoteVersion.length() == 0) {
    Serial.println("[AutoOTA] No version field in version.json");
    autoOtaLastCheckStatus = "no-version";
    return false;
  }

  autoOtaLatestVersion = remoteVersion;
  autoOtaLatestNotes = notes;

  String currentVersion = String(FIRMWARE_VERSION);
  Serial.printf("[AutoOTA] Current: %s, Remote: %s\n", currentVersion.c_str(), remoteVersion.c_str());

  // If current firmware is not a valid semver (e.g. git hash like "b8af24c"),
  // always accept any valid semver release from the server
  int localMaj = 0, localMin = 0, localPat = 0;
  bool localIsSemVer = (sscanf(currentVersion.c_str(), "%d.%d.%d", &localMaj, &localMin, &localPat) == 3);
  int remoteMaj = 0, remoteMin = 0, remotePat = 0;
  bool remoteIsSemVer = (sscanf(remoteVersion.c_str(), "%d.%d.%d", &remoteMaj, &remoteMin, &remotePat) == 3);

  if (!localIsSemVer && remoteIsSemVer) {
    Serial.printf("[AutoOTA] Local version '%s' is not semver, forcing update to %s\n",
                  currentVersion.c_str(), remoteVersion.c_str());
  } else {
    int cmp = compareSemVer(currentVersion, remoteVersion);
    if (cmp <= 0) {
      Serial.println("[AutoOTA] Firmware is up to date");
      autoOtaLastCheckStatus = "up-to-date";
      autoOtaLatestUrl = "";
      return false;
    }
  }

  Serial.printf("[AutoOTA] Update available: %s -> %s\n", currentVersion.c_str(), remoteVersion.c_str());
  if (notes.length() > 0) {
    Serial.printf("[AutoOTA] Release notes: %s\n", notes.c_str());
  }

  // Resolve firmware download URL
  if (firmwareUrl.length() == 0) {
    // Default: same base path as version.json but with firmware.bin
    firmwareUrl = settings.autoOtaUrl;
    if (!firmwareUrl.endsWith("/")) firmwareUrl += "/";
    firmwareUrl += "firmware.bin";
  }
  autoOtaLatestUrl = firmwareUrl;
  autoOtaLastCheckStatus = "update-available";

  if (!applyIfAvailable) {
    return true;
  }

  // --- Download and flash the firmware ---
  Serial.printf("[AutoOTA] Downloading firmware from: %s\n", firmwareUrl.c_str());
  autoOtaUpdateInProgress = true;
  autoOtaLastCheckStatus = "updating";

  WiFiClient *updateClient;
  WiFiClientSecure secureUpdateClient;
  bool firmwareIsSecure = firmwareUrl.startsWith("https://");

  if (firmwareIsSecure) {
    updateClient = &secureUpdateClient;
  } else {
    Serial.println("[AutoOTA] Insecure firmware URL blocked: only HTTPS is allowed");
    autoOtaLastCheckStatus = "insecure-firmware-url";
    autoOtaUpdateInProgress = false;
    return true;
  }


  httpUpdate.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  httpUpdate.rebootOnUpdate(false);  // We'll reboot ourselves after logging

  t_httpUpdate_return ret = httpUpdate.update(*updateClient, firmwareUrl);

  autoOtaUpdateInProgress = false;

  switch (ret) {
    case HTTP_UPDATE_OK:
      Serial.printf("[AutoOTA] Update successful! %s -> %s. Rebooting...\n",
                    currentVersion.c_str(), remoteVersion.c_str());
      autoOtaLastCheckStatus = "update-success";
      delay(500);
      ESP.restart();
      return true;

    case HTTP_UPDATE_FAILED:
      Serial.printf("[AutoOTA] Update failed: %s (error %d)\n",
                    httpUpdate.getLastErrorString().c_str(), httpUpdate.getLastError());
      autoOtaLastCheckStatus = "update-failed";
      return true;

    case HTTP_UPDATE_NO_UPDATES:
      Serial.println("[AutoOTA] Server reported no update available");
      autoOtaLastCheckStatus = "no-update";
      return false;

    default:
      autoOtaLastCheckStatus = "unknown-error";
      return false;
  }
}

// ============================================
// Main Loop
// ============================================
void loop() {
  if (captivePortalActive) {
    dnsServer.processNextRequest();

    // Hourly retry: pause hotspot and attempt STA connection.
    if (!wifiAttemptInProgress && millis() - lastCaptiveRetryMs >= CAPTIVE_RETRY_INTERVAL_MS) {
      Serial.println("[CaptivePortal] Hourly retry: stopping hotspot to try WiFi reconnect");
      stopCaptivePortal();
      startWifiConnectAttempt(true);
    }
  }

  if (settings.mqttEnabled) {
    initMqttClientOnce();
    ensureMqttConnected();
    // Flush any queued messages once connected
    if (mqttClient.connected() && mqttQueueSize() > 0) {
      mqttFlushQueue();
    }
  }

  if (pendingRestart && millis() >= restartAtMs) {
    Serial.println("Rebooting now...");
    delay(50);
    ESP.restart();
  }

  if (settings.loraEnabled) {
    // Periodic radio status check
    static unsigned long lastRadioCheck = 0;
    if (millis() - lastRadioCheck >= 30000) {  // Every 30 seconds
      Serial.println("[LoRa] Radio still listening for packets...");
      lastRadioCheck = millis();
    }
    
    // Check for LoRa packets (all devices listen)
    uint8_t message[256];
    int state = radio.receive(message, sizeof(message));
    
    if (state == RADIOLIB_ERR_NONE) {
      // Packet received successfully
      lastRssi = radio.getRSSI();
      lastSnr = radio.getSNR();
      
      Serial.println("\n=== LoRa Packet Received ===");
      size_t packetLen = radio.getPacketLength();
      if (packetLen == 0 || packetLen > sizeof(message)) {
        packetLen = sizeof(message);
      }
      Serial.printf("Raw length: %d bytes\n", (int)packetLen);
      Serial.print("Raw hex: ");
      for (size_t i = 0; i < packetLen && i < 32; i++) {
        Serial.printf("%02X ", message[i]);
      }
      if (packetLen > 32) Serial.print("...");
      Serial.println();
      Serial.printf("RSSI: %d dBm, SNR: %.2f dB\n", (int)lastRssi, lastSnr);
      Serial.println("===========================\n");
      
      // Handle the message
      handleLoRaMessage(message, packetLen);
      
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

    if (!wifiConnected && !wifiAttemptInProgress && millis() - lastWifiAttempt >= 10000) {
      Serial.println("WiFi disconnected, reconnecting...");
      startWifiConnectAttempt(false);
      lastWifiAttempt = millis();
    }

    if (wifiAttemptInProgress) {
      if (WiFi.status() == WL_CONNECTED) {
        wifiAttemptInProgress = false;
        wifiAttemptRestoreCaptive = false;
        wifiConnected = true;
        Serial.println("WiFi connected!");
        notifyIpChangeIfNeeded(WiFi.localIP().toString(), "reconnect");
      } else if (millis() - wifiAttemptStartMs >= WIFI_CONNECT_TIMEOUT_MS) {
        bool restoreCaptive = wifiAttemptRestoreCaptive;
        Serial.println("WiFi reconnect timed out");
        wifiAttemptInProgress = false;
        wifiAttemptRestoreCaptive = false;
        if (restoreCaptive || !captivePortalActive) {
          startCaptivePortal();
        }
      }
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

  // Handle deferred "Install Now" request from the web UI
  if (autoOtaApplyRequested && !autoOtaUpdateInProgress) {
    autoOtaApplyRequested = false;
    Serial.println("[AutoOTA] Applying deferred install request from web UI");
    checkAutoOtaUpdate(true);
  }

  // Periodic auto-OTA check
  if (settings.autoOtaEnabled != 0 && !captivePortalActive && !autoOtaUpdateInProgress) {
    unsigned long intervalMs = (unsigned long)settings.autoOtaCheckInterval * 1000UL;
    if (intervalMs < 60000UL) intervalMs = 3600000UL;
    if (autoOtaLastCheckMs == 0) {
      if (settings.autoOtaEnabled == 2) {
        // Delayed mode: skip boot check, just record the time
        autoOtaLastCheckMs = millis();
      } else {
        // Normal mode: check immediately on boot
        autoOtaLastCheckMs = millis();
        checkAutoOtaUpdate(true);
      }
    } else if (millis() - autoOtaLastCheckMs >= intervalMs) {
      autoOtaLastCheckMs = millis();
      checkAutoOtaUpdate(true);  // Check and apply if available
    }
  }
  
  delay(10);
}

// ============================================
// WiFi Setup
// ============================================
void setupWiFi(bool waitForConnect) {
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

  if (!waitForConnect) {
    return;
  }

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
  
  // Initialize mesh channels (public + user's channel)
  initMeshChannels();
  
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
void handleLoRaMessage(const uint8_t* message, size_t messageLen) {
  Serial.println("\n=== Processing MeshCore Packet ===");
  Serial.printf("Packet length: %d bytes\n", (int)messageLen);
  
  if (messageLen < 2) {
    Serial.println("Packet too short (need at least header + pathLen)");
    return;
  }
  
  // Parse MeshCore packet header
  uint8_t header = message[0];
  uint8_t routeType = header & 0x03;
  uint8_t payloadType = (header >> 2) & 0x0F;
  uint8_t version = (header >> 6) & 0x03;
  
  // Handle transport codes for route types 0 (TRANSPORT_FLOOD) and 3 (TRANSPORT_DIRECT)
  bool hasTransportCodes = (routeType == ROUTE_TYPE_TRANSPORT_FLOOD || routeType == ROUTE_TYPE_TRANSPORT_DIRECT);
  size_t hdrSize = 1 + (hasTransportCodes ? 4 : 0);  // header + optional transport codes
  
  if (messageLen < hdrSize + 1) {
    Serial.println("Packet too short for header + path_len");
    return;
  }
  
  uint8_t pathLen = message[hdrSize];  // path_len is after header (and optional transport codes)
  
  Serial.printf("Header: 0x%02X -> route=%d, payload=%d, version=%d, pathLen=%d, transport=%s\n", 
                header, routeType, payloadType, version, pathLen, hasTransportCodes ? "yes" : "no");
  
  // Check minimum packet size based on header + transport codes + path_len byte + path
  size_t pathStart = hdrSize + 1;  // offset where path bytes begin
  if (messageLen < (pathStart + pathLen)) {
    Serial.printf("Packet too short: have %d bytes, need at least %d (header + pathLen)\n", 
                  (int)messageLen, (int)(pathStart + pathLen));
    return;
  }
  
  // Capture sender path for potential direct reply
  uint8_t senderPath[64];
  size_t senderPathLen = (pathLen > 64) ? 64 : pathLen;
  if (pathLen > 0) {
    memcpy(senderPath, message + pathStart, senderPathLen);
  }

  // Build reverse path for replies (path uses node hashes)
  uint8_t replyPath[64];
  size_t replyPathLen = senderPathLen;
  if (senderPathLen > 0) {
    for (size_t i = 0; i < senderPathLen; i++) {
      replyPath[i] = senderPath[senderPathLen - 1 - i];
    }
  }
  
  // We handle PAYLOAD_TYPE_TXT (0x02), PAYLOAD_TYPE_GRP_TXT (0x05), PAYLOAD_TYPE_ADVERT (0x04),
  // PAYLOAD_TYPE_PATH (0x08), PAYLOAD_TYPE_REQ (0x00), PAYLOAD_TYPE_RESPONSE (0x01),
  // and PAYLOAD_TYPE_ANON_REQ (0x07)
  if (payloadType != PAYLOAD_TYPE_TXT && payloadType != PAYLOAD_TYPE_GRP_TXT && 
      payloadType != PAYLOAD_TYPE_ADVERT && payloadType != PAYLOAD_TYPE_PATH &&
      payloadType != PAYLOAD_TYPE_REQ && payloadType != PAYLOAD_TYPE_RESPONSE &&
      payloadType != PAYLOAD_TYPE_ANON_REQ) {
    Serial.printf("Unsupported payload type: %d\n", payloadType);
    return;
  }
  
  // Payload starts after header + optional transport codes + path_len byte + path bytes
  size_t idx = pathStart + pathLen;
  if (idx >= messageLen) {
    Serial.println("Packet too short for payload");
    return;
  }
  
  uint8_t channelKey[32];
  size_t channelKeyLen;
  const uint8_t* senderPubKey = nullptr;
  uint8_t senderHash = 0;

  // --- Handle ADVERT to populate peer cache ---
  if (payloadType == PAYLOAD_TYPE_ADVERT) {
    // Advert payload: [public_key(32)][timestamp(4)][signature(64)][app_data]
    size_t advertIdx = idx;  // idx already points to start of payload
    size_t remain = messageLen - advertIdx;
    if (remain < 32 + 4) {
      Serial.println("Advert payload too short for public key + timestamp");
      return;
    }
    const uint8_t* pub = message + advertIdx;
    advertIdx += 32;

    uint32_t advertTimestamp = (uint32_t)message[advertIdx] |
                               ((uint32_t)message[advertIdx + 1] << 8) |
                               ((uint32_t)message[advertIdx + 2] << 16) |
                               ((uint32_t)message[advertIdx + 3] << 24);
    advertIdx += 4;
    
    // Compute peer hash = first byte of public key
    uint8_t peerHash = pub[0];

    // Attempt to parse name and node type from app_data (after signature)
    String name = "";
    uint8_t peerNodeType = 0;  // 0=Unknown
    size_t appDataIdx = advertIdx + 64; // Skip signature(64)
    
    if (appDataIdx < messageLen) {
      uint8_t appFlags = message[appDataIdx++];
      peerNodeType = appFlags & 0x0F;  // Lower nibble = role (1=Client,2=Repeater,3=Router)
      // Bit 4 = has location: skip lat(4) + lon(4) = 8 bytes of GPS coords
      if ((appFlags & 0x10) && appDataIdx + 8 <= messageLen) {
        appDataIdx += 8;
      }
      // Bit 7 = has name: remaining bytes are the node name
      if ((appFlags & 0x80) && appDataIdx < messageLen) {
        size_t nameLen = messageLen - appDataIdx;
        if (nameLen > 0 && nameLen < 64) {
          char nameBuf[64];
          memcpy(nameBuf, message + appDataIdx, nameLen);
          nameBuf[nameLen] = '\0';
          // Strip any leading/trailing non-printable characters
          String raw = String(nameBuf);
          raw.trim();
          name = "";
          for (unsigned int ci = 0; ci < raw.length(); ci++) {
            char ch = raw.charAt(ci);
            if (ch >= 0x20 && ch <= 0x7E) name += ch;
          }
        }
      }
    }

    uint32_t useTimestamp = advertTimestamp;
    if (useTimestamp == 0) {
      useTimestamp = (uint32_t)time(nullptr);
    }

    upsertPeer(peerHash, pub, name, useTimestamp, peerNodeType);
    updateAdvertCache(pub, name, useTimestamp, peerNodeType);
    Serial.printf("[Advert] Cached peer hash=0x%02X name='%s' type=%d pubkey=%02X%02X%02X%02X... ts=%u\n", 
                  peerHash, name.c_str(), peerNodeType, pub[0], pub[1], pub[2], pub[3], useTimestamp);
    appendLoraLog('R', 'V', name.length() > 0 ? name : String("0x") + String(peerHash, HEX), String(nodeTypeName(peerNodeType)) + " advert", true);
    Serial.println("=== Packet Processing Complete ===\n");
    return;
  }
  
  // For group messages, try all matching channels; for direct messages, read dest/src hash and derive ECDH key
  String matchedChannelName = "";
  String text = "";
  if (payloadType == PAYLOAD_TYPE_GRP_TXT) {
    // Get channel hash from packet
    uint8_t receivedHash = (uint8_t)message[idx++];
    Serial.printf("Received channel hash: 0x%02X\n", receivedHash);
    
    // Save idx for retry with multiple channels
    size_t encDataIdx = idx;
    size_t encryptedLen = messageLen - encDataIdx;
    
    // Minimum: 2 bytes MAC + 16 bytes ciphertext (AES block)
    size_t minEncryptedLen = CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE;
    if (encryptedLen < minEncryptedLen) {
      Serial.printf("Packet too short for valid encrypted message (need at least %d, got %d)\n", 
                    (int)minEncryptedLen, (int)encryptedLen);
      return;
    }
    
    const uint8_t* encrypted = message + encDataIdx;
    uint8_t decrypted[256];
    size_t decryptedLen = 0;
    bool matched = false;
    
    // Try all channels with matching hash (like MeshCore's searchChannelsByHash + decrypt loop)
    for (int ch = 0; ch < meshChannelCount; ch++) {
      if (!meshChannels[ch].active) continue;
      if (meshChannels[ch].hash != receivedHash) continue;
      
      Serial.printf("  Trying channel '%s' (hash=0x%02X, keyLen=%d)...\n", 
                    meshChannels[ch].name, meshChannels[ch].hash, (int)meshChannels[ch].keyLen);
      
      decryptedLen = verifyAndDecrypt(meshChannels[ch].key, meshChannels[ch].keyLen, decrypted, encrypted, encryptedLen);
      if (decryptedLen > 0) {
        Serial.printf("  -> Decrypted successfully on channel '%s'!\n", meshChannels[ch].name);
        matchedChannelName = meshChannels[ch].name;
        matched = true;
        break;
      }
    }
    
    if (!matched) {
      // Log which hashes we have configured
      Serial.print("Channel hash mismatch or decryption failed. Configured channels: ");
      for (int ch = 0; ch < meshChannelCount; ch++) {
        Serial.printf("'%s'=0x%02X ", meshChannels[ch].name, meshChannels[ch].hash);
      }
      Serial.println();
      return;
    }
    
    // Parse the decrypted group message directly here
    Serial.printf("Decrypted %d bytes from channel '%s'\n", decryptedLen, matchedChannelName.c_str());
    
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
      if (textMessage[i] == '\0' || textMessage[i] == 0) {
        textMessage[i] = '\0';
      } else {
        break;
      }
    }
    
    text = String(textMessage);
    Serial.printf("[LoRa][%s] Group message: %s\n", matchedChannelName.c_str(), text.c_str());
    appendLoraLog('R', 'G', matchedChannelName, text, true);
    
  } else if (payloadType == PAYLOAD_TYPE_ANON_REQ) {
    // Anonymous request: [destHash(1)][senderPubKey(32)][MAC(2) + ciphertext]
    // Sender includes their full 32-byte Ed25519 public key instead of a 1-byte srcHash
    Serial.println("Processing as ANON_REQ (anonymous request with embedded public key)");

    size_t minAnonSize = 1 + 32 + CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE;
    if ((messageLen - idx) < minAnonSize) {
      Serial.printf("ANON_REQ too short: have %d bytes after path, need at least %d\n",
                    (int)(messageLen - idx), (int)minAnonSize);
      return;
    }
    uint8_t destHash = message[idx++];

    // Extract sender's full 32-byte Ed25519 public key
    static uint8_t anonSenderPub[32];
    memcpy(anonSenderPub, message + idx, 32);
    idx += 32;

    senderHash = anonSenderPub[0];
    Serial.printf("ANON_REQ: destHash=0x%02X senderPubKey=%02X%02X%02X%02X... (our hash=0x%02X)\n",
                  destHash, anonSenderPub[0], anonSenderPub[1], anonSenderPub[2], anonSenderPub[3], ourNodeHash);

    // Check if message is addressed to us
    uint8_t pubKeyFirstByte = ed25519_public_key[0];
    bool isForUs = (destHash == pubKeyFirstByte || destHash == ourNodeHashAlt);
    if (!isForUs) {
      Serial.printf("ANON_REQ not addressed to us; ignoring (dest=0x%02X)\n", destHash);
      return;
    }

    Serial.println("ANON_REQ is for us! Adding sender to peer cache...");

    // Add sender to peer cache (and advert cache for persistence)
    upsertPeer(anonSenderPub[0], anonSenderPub, String(""), (uint32_t)time(nullptr));
    updateAdvertCache(anonSenderPub, String(""), (uint32_t)time(nullptr));
    senderPubKey = anonSenderPub;

    uint8_t shared[32];
    if (!deriveSharedSecretWithPeer(senderPubKey, shared)) {
      Serial.println("Failed to derive shared secret for ANON_REQ");
      return;
    }
    memcpy(channelKey, shared, 32);
    channelKeyLen = 32;

    // Decrypt
    size_t encryptedLen = messageLen - idx;
    Serial.printf("ANON_REQ encrypted payload length: %d bytes\n", (int)encryptedLen);

    size_t minEncryptedLen = CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE;
    if (encryptedLen < minEncryptedLen) {
      Serial.printf("ANON_REQ payload too short (need %d, got %d)\n", (int)minEncryptedLen, (int)encryptedLen);
      return;
    }

    const uint8_t* encrypted = message + idx;
    uint8_t decrypted[256];

    size_t decryptedLen = verifyAndDecrypt(channelKey, channelKeyLen, decrypted, encrypted, encryptedLen);
    if (decryptedLen == 0) {
      uint8_t derivedKey[32];
      deriveDirectKeyFromShared(shared, derivedKey);
      decryptedLen = verifyAndDecrypt(derivedKey, 32, decrypted, encrypted, encryptedLen);
      if (decryptedLen > 0) {
        Serial.println("[LoRa] ANON_REQ decrypted using SHA-256 derived key");
      }
    }

    if (decryptedLen == 0) {
      Serial.println("ANON_REQ decryption or MAC verification failed");
      return;
    }

    Serial.printf("ANON_REQ decrypted %d bytes successfully\n", (int)decryptedLen);

    // Parse as REQ payload — for now log and send our advert so peer can reach us next time
    Serial.printf("[LoRa] Received ANON_REQ from peer (pubkey=%02X%02X...), %d decrypted bytes\n",
                  anonSenderPub[0], anonSenderPub[1], (int)decryptedLen);
    Serial.println("Sending our advert so peer can send direct messages next time...");
    sendBootAdvert();

    // If the decrypted payload looks like a TXT message (timestamp + type + text), extract it
    if (decryptedLen >= 5) {
      uint32_t timestamp = decrypted[0] | (decrypted[1] << 8) | (decrypted[2] << 16) | (decrypted[3] << 24);
      uint8_t txtType = decrypted[4];
      size_t textLen = decryptedLen - 5;
      char textMessage[256];
      memcpy(textMessage, &decrypted[5], textLen);
      textMessage[textLen] = '\0';

      // Strip trailing null padding
      for (int i = textLen - 1; i >= 0; i--) {
        if (textMessage[i] == '\0') continue;
        break;
      }

      // Send ACK
      size_t rawTextLen = strnlen((const char*)&decrypted[5], decryptedLen - 5);
      uint8_t txtTypeFlags = (txtType >> 2) & 0x3F;
      if (txtTypeFlags == TXT_TYPE_PLAIN && senderPubKey != nullptr) {
        size_t ackDataLen = 5 + rawTextLen;
        if (ackDataLen <= decryptedLen) {
          uint32_t ackHash = computeAckHash(decrypted, ackDataLen, senderPubKey);
          sendLoRaAck(ackHash, replyPath, replyPathLen);
        }
      }

      matchedChannelName = "Direct";
      text = String(textMessage);
      Serial.printf("[LoRa][Direct/ANON_REQ] Message: %s\n", text.c_str());
      {
        String peerName = "";
        if (senderPubKey != nullptr) {
          int pi = findPeerIndexByHash(senderPubKey[0]);
          if (pi >= 0) peerName = peers[pi].name;
        }
        if (peerName.length() == 0) peerName = "ANON";
        appendLoraLog('R', 'D', peerName, text, true);
      }
    } else {
      Serial.println("ANON_REQ payload too short for text extraction");
      Serial.println("=== Packet Processing Complete ===\n");
      return;
    }

  } else if (payloadType == PAYLOAD_TYPE_TXT || payloadType == PAYLOAD_TYPE_PATH ||
             payloadType == PAYLOAD_TYPE_REQ || payloadType == PAYLOAD_TYPE_RESPONSE) {
    // Direct/peer messages: [destHash(1)][srcHash(1)][MAC(2) + ciphertext]
    // TXT, PATH, REQ, RESPONSE all use the same format with dest/src hashes + encrypted data
    Serial.printf("Processing as peer message (payload type %d)\n", payloadType);
    
    size_t minDirectSize = 1 + 1 + CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE; // AES block minimum
    if ((messageLen - idx) < minDirectSize) {
      Serial.printf("Direct message too short: have %d bytes after path, need at least %d\n", 
                    (int)(messageLen - idx), minDirectSize);
      return;
    }
    uint8_t destHash = message[idx++];
    uint8_t srcHash = message[idx++];
    senderHash = srcHash;
    Serial.printf("Direct payload: destHash=0x%02X srcHash=0x%02X (our hash=0x%02X)\n", 
                  destHash, srcHash, ourNodeHash);

    // MeshCore node hash may be pubkey[0] or sha256(pubkey)[0]
    uint8_t pubKeyFirstByte = ed25519_public_key[0];
    Serial.printf("Checking: node hash pubkey[0]=0x%02X, alt sha256[0]=0x%02X\n", pubKeyFirstByte, ourNodeHashAlt);

    // Check if destHash matches our node hash
    bool isForUs = (destHash == pubKeyFirstByte || destHash == ourNodeHashAlt);
    
    if (!isForUs) {
      Serial.printf("Direct message not addressed to us; ignoring (dest=0x%02X)\n", destHash);
      return;
    }
    
    Serial.println("Direct message is for us!");

    // Lookup sender public key via srcHash
    int pidx = findPeerIndexByHash(srcHash);
    if (pidx < 0) {
      pidx = ensurePeerFromAdvertCache(srcHash);
    }
    if (pidx >= 0) {
      senderPubKey = peers[pidx].ed25519_pub;
      Serial.printf("Sender resolved from cache (hash=pubkey[0]) pubkey=%02X%02X%02X%02X...\n",
                    senderPubKey[0], senderPubKey[1], senderPubKey[2], senderPubKey[3]);
    } else {
      // Sender not in peer/advert cache — try configured direct nodes by matching srcHash
      Serial.printf("Sender not in cache (srcHash=0x%02X). Trying configured direct nodes...\n", srcHash);
      static uint8_t directNodePubkey[32];  // static to persist beyond this scope
      bool foundViaDirectNode = false;

      for (int i = 0; i < settings.loraDirectNodeCount; i++) {
        const String &pubHex = settings.loraDirectNodes[i].pubkeyHex;
        if (pubHex.length() == 0) continue;

        uint8_t candidatePub[32];
        if (!parseHexKeyToBytes(pubHex, candidatePub)) continue;

        uint8_t candidateHash = candidatePub[0];
        uint8_t candidateAltHash = computeNodeHashSha256(candidatePub);

        if (srcHash == candidateHash || srcHash == candidateAltHash) {
          String label = settings.loraDirectNodes[i].name;
          if (label.length() == 0) label = String("node-") + String(i + 1);
          Serial.printf("Matched configured direct node '%s' (pubkey[0]=0x%02X)\n", label.c_str(), candidateHash);

          memcpy(directNodePubkey, candidatePub, 32);
          // Add to peer + advert cache for future messages
          upsertPeer(candidatePub[0], candidatePub, label, (uint32_t)time(nullptr));
          updateAdvertCache(candidatePub, label, (uint32_t)time(nullptr));

          senderPubKey = directNodePubkey;
          foundViaDirectNode = true;
          break;
        }
      }

      if (!foundViaDirectNode) {
        // Last resort: brute-force try each configured direct node's key for decryption
        Serial.println("No hash match. Trying all configured direct nodes by decryption...");
        const uint8_t* encrypted = message + idx;
        size_t encryptedLen = messageLen - idx;

        for (int i = 0; i < settings.loraDirectNodeCount; i++) {
          const String &pubHex = settings.loraDirectNodes[i].pubkeyHex;
          if (pubHex.length() == 0) continue;

          uint8_t candidatePub[32];
          if (!parseHexKeyToBytes(pubHex, candidatePub)) continue;

          uint8_t tryShared[32];
          if (!deriveSharedSecretWithPeer(candidatePub, tryShared)) continue;

          uint8_t tryDecrypted[256];
          size_t tryLen = verifyAndDecrypt(tryShared, 32, tryDecrypted, encrypted, encryptedLen);
          if (tryLen == 0) {
            uint8_t derivedKey[32];
            deriveDirectKeyFromShared(tryShared, derivedKey);
            tryLen = verifyAndDecrypt(derivedKey, 32, tryDecrypted, encrypted, encryptedLen);
          }

          if (tryLen > 0) {
            String label = settings.loraDirectNodes[i].name;
            if (label.length() == 0) label = String("node-") + String(i + 1);
            Serial.printf("Decryption succeeded with configured node '%s'!\n", label.c_str());

            memcpy(directNodePubkey, candidatePub, 32);
            upsertPeer(candidatePub[0], candidatePub, label, (uint32_t)time(nullptr));
            updateAdvertCache(candidatePub, label, (uint32_t)time(nullptr));

            senderPubKey = directNodePubkey;
            foundViaDirectNode = true;
            break;
          }
        }
      }

      if (!foundViaDirectNode) {
        Serial.printf("Unknown sender for direct message (srcHash=0x%02X not resolved)\n", srcHash);
        Serial.println("Sending our advert to establish peer relationship...");
        sendBootAdvert();
        return;
      }
    }

    uint8_t shared[32];
    if (!deriveSharedSecretWithPeer(senderPubKey, shared)) {
      Serial.println("Failed to derive shared secret for direct message");
      return;
    }
    // MeshCore uses the raw ECDH shared secret directly for encrypt/decrypt
    memcpy(channelKey, shared, 32);
    channelKeyLen = 32;
    
    // --- Decrypt and parse direct message ---
    size_t encryptedLen = messageLen - idx;
    Serial.printf("Encrypted payload length: %d bytes\n", encryptedLen);
    
    size_t minEncryptedLen = CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE;
    if (encryptedLen < minEncryptedLen) {
      Serial.printf("Packet too short for valid encrypted message (need at least %d bytes, got %d)\n", 
                    (int)minEncryptedLen, (int)encryptedLen);
      Serial.println("This may be a different packet type or corrupted packet");
      return;
    }
    
    const uint8_t* encrypted = message + idx;
    uint8_t decrypted[256];
    
    // Try raw shared secret first (MeshCore standard)
    size_t decryptedLen = verifyAndDecrypt(channelKey, channelKeyLen, decrypted, encrypted, encryptedLen);
    if (decryptedLen == 0 && senderPubKey != nullptr) {
      // Fallback: try SHA-256 derived key (in case peer uses derived key)
      uint8_t derivedKey[32];
      deriveDirectKeyFromShared(shared, derivedKey);
      decryptedLen = verifyAndDecrypt(derivedKey, 32, decrypted, encrypted, encryptedLen);
      if (decryptedLen > 0) {
        Serial.println("[LoRa] Direct message decrypted using SHA-256 derived key (non-standard)");
      }
    }
    
    if (decryptedLen == 0) {
      Serial.println("Decryption or MAC verification failed");
      return;
    }
    
    Serial.printf("Decrypted %d bytes successfully\n", decryptedLen);
    
    // Handle PATH payload type (route establishment)
    if (payloadType == PAYLOAD_TYPE_PATH) {
      // PATH decrypted data: [path_len(1)][path(path_len)][extra_type(1)][extra(rest)]
      if (decryptedLen < 2) {
        Serial.println("[PATH] Decrypted PATH payload too short");
        Serial.println("=== Packet Processing Complete ===\n");
        return;
      }
      uint8_t returnPathLen = decrypted[0];
      if (1 + returnPathLen + 1 > decryptedLen) {
        Serial.println("[PATH] PATH data incomplete");
        Serial.println("=== Packet Processing Complete ===\n");
        return;
      }
      const uint8_t* returnPath = &decrypted[1];
      uint8_t extraType = decrypted[1 + returnPathLen] & 0x0F;
      
      Serial.printf("[PATH] Return path from peer (len=%d), extra_type=%d\n", returnPathLen, extraType);
      
      // If there's an embedded ACK in the PATH, process it
      if (extraType == PAYLOAD_TYPE_ACK && 1 + returnPathLen + 1 + 4 <= decryptedLen) {
        uint32_t ackHash;
        memcpy(&ackHash, &decrypted[1 + returnPathLen + 1], 4);
        Serial.printf("[PATH] Contains embedded ACK hash: 0x%08X\n", ackHash);
      }
      
      Serial.println("=== Packet Processing Complete ===\n");
      return;
    }
    
    // Handle REQ/RESPONSE payload types (log and ignore for now)
    if (payloadType == PAYLOAD_TYPE_REQ || payloadType == PAYLOAD_TYPE_RESPONSE) {
      Serial.printf("[LoRa] Received %s from peer (srcHash=0x%02X), %d decrypted bytes\n",
                    payloadType == PAYLOAD_TYPE_REQ ? "REQUEST" : "RESPONSE",
                    senderHash, decryptedLen);
      Serial.println("=== Packet Processing Complete ===\n");
      return;
    }
    
    // --- Parse TXT message payload ---
    if (decryptedLen < 5) {
      Serial.println("Decrypted payload too short for TXT message");
      return;
    }
    
    uint32_t timestamp = decrypted[0] | (decrypted[1] << 8) | (decrypted[2] << 16) | (decrypted[3] << 24);
    uint8_t txtType = decrypted[4];
    
    Serial.printf("Timestamp: %u, Text type: %d\n", timestamp, txtType);
    
    size_t textLen = decryptedLen - 5;
    char textMessage[256];
    memcpy(textMessage, &decrypted[5], textLen);
    textMessage[textLen] = '\0';
    
    // Compute ACK hash BEFORE stripping padding, using strlen on raw decrypted data
    // MeshCore ACK: SHA256(data[0..4+strlen(&data[5])] || sender_pubkey)[0..3]
    size_t rawTextLen = strnlen((const char*)&decrypted[5], decryptedLen - 5);
    
    for (int i = textLen - 1; i >= 0; i--) {
      if (textMessage[i] == '\0') {
        textMessage[i] = '\0';
      } else {
        break;
      }
    }
    
    Serial.printf("Decoded message: \"%s\"\n", textMessage);

    // Send ACK for direct plain text messages
    if (senderPubKey != nullptr) {
      uint8_t txtTypeFlags = (txtType >> 2) & 0x3F;  // upper 6 bits = txt_type
      if (txtTypeFlags == TXT_TYPE_PLAIN) {
        size_t ackDataLen = 5 + rawTextLen;
        if (ackDataLen <= decryptedLen) {
          uint32_t ackHash = computeAckHash(decrypted, ackDataLen, senderPubKey);
          sendLoRaAck(ackHash, replyPath, replyPathLen);
        }
      }
    }
    
    matchedChannelName = "Direct";
    text = String(textMessage);
    Serial.printf("[LoRa][Direct] Message: %s\n", text.c_str());
    {
      String peerName = "";
      if (senderPubKey != nullptr) {
        int pi = findPeerIndexByHash(senderPubKey[0]);
        if (pi >= 0) peerName = peers[pi].name;
      }
      if (peerName.length() == 0 && senderHash != 0) { char hx[8]; snprintf(hx, sizeof(hx), "0x%02X", senderHash); peerName = hx; }
      if (peerName.length() == 0) peerName = "Unknown";
      appendLoraLog('R', 'D', peerName, text, true);
    }
  } else {
    // Unhandled payload type that passed the initial filter
    Serial.printf("Payload type %d not processed for text extraction\n", payloadType);
    Serial.println("=== Packet Processing Complete ===\n");
    return;
  }
  
  // ===== Common text handling for both group and direct messages =====
  String msgStr = text;

  // Check if this is a response to a pending MeshCore node status check.
  // Direct messages from a node we polled should be routed to processMeshNodeResponse
  // and not forwarded to notification services.
  if (matchedChannelName == "Direct") {
    int pendingSvcIdx = consumePendingMeshCheck(senderHash);
    if (pendingSvcIdx >= 0) {
      processMeshNodeResponse(pendingSvcIdx, msgStr);
      Serial.println("[MeshNode] Response consumed, suppressing notification forwarding");
      Serial.println("=== Packet Processing Complete ===\n");
      return;
    }
  }

  // Check if this is our own message by checking if the message starts with our node name
  if (msgStr.startsWith(ourNodeName + ":")) {
    Serial.println("This is our own message, not forwarding to notification services");
    Serial.println("=== Packet Processing Complete ===\n");
    return;
  }
  
  // Only process direct messages and messages from the configured channel.
  // Public channel messages are ignored when LORA_IGNORE_PUBLIC is enabled.
  if (matchedChannelName == "Public" && settings.loraIgnorePublic) {
    Serial.println("[LoRa] Public channel message ignored (LORA_IGNORE_PUBLIC enabled)");
    Serial.println("=== Packet Processing Complete ===\n");
    return;
  }
  
  // Check for direct commands (ping, status, reboot)
  // Format: "sender: pin:command" — pin comes first to allow multi-word commands
  String trimmedMsg = msgStr;
  trimmedMsg.trim();

  // Extract command from "sender: pin:command" format, or use full text.
  // If the prefix is an actual command (e.g., "ping"), don't strip it.
  int colonPos = trimmedMsg.indexOf(':');
  String commandRaw = trimmedMsg;
  if (colonPos != -1 && colonPos < trimmedMsg.length() - 1) {
    String before = trimmedMsg.substring(0, colonPos);
    before.trim();
    String beforeLower = before;
    beforeLower.toLowerCase();
    if (beforeLower != "ping" && beforeLower != "status" && beforeLower != "reboot") {
      commandRaw = trimmedMsg.substring(colonPos + 1);
    }
  }
  commandRaw.trim();

  // Parse pin:command format — PIN is before the first ':', command is everything after
  String pinPart = "";
  String command = commandRaw;
  int pinSep = commandRaw.indexOf(':');
  if (pinSep != -1 && pinSep < commandRaw.length() - 1) {
    pinPart = commandRaw.substring(0, pinSep);
    command = commandRaw.substring(pinSep + 1);
  }
  pinPart.trim();
  command.trim();

  String commandLower = command;
  commandLower.toLowerCase();
  bool pinOk = (settings.loraCommandPin.length() > 0 && pinPart == settings.loraCommandPin);
  
  // Handle "ping" command
  if (commandLower == "ping") {
    Serial.println("[Command] Received ping, sending pong");
    if (senderPubKey != nullptr) {
      sendLoRaDirectMessage("pong", senderPubKey, senderHash, replyPath, replyPathLen);
    } else {
      Serial.println("[Command] Missing sender public key; cannot reply");
    }
    Serial.println("=== Packet Processing Complete ===\n");
    return;
  }
  
  // Handle "status" command
  if (commandLower == "status") {
    Serial.println("[Command] Received status request, sending status");
    if (!pinOk) {
      Serial.println("[Command] Status denied: invalid or missing PIN");
      if (senderPubKey != nullptr) {
        sendLoRaDirectMessage("unauthorized", senderPubKey, senderHash, replyPath, replyPathLen);
      }
      Serial.println("=== Packet Processing Complete ===\n");
      return;
    }
    
    // Get IP address
    String ip = WiFi.localIP().toString();
    
    // Get battery stats
    BatteryStats battery = getBatteryStats();
    String batteryStr = battery.valid ? String(battery.voltage, 2) + "V (" + String(battery.percent) + "%)" : "N/A";
    
    // Get uptime
    unsigned long uptimeSeconds = millis() / 1000;
    unsigned long days = uptimeSeconds / 86400;
    unsigned long hours = (uptimeSeconds % 86400) / 3600;
    unsigned long minutes = (uptimeSeconds % 3600) / 60;
    String uptimeStr = String(days) + "d " + String(hours) + "h " + String(minutes) + "m";
    
    // Count up/down services
    int upCount = 0;
    int downCount = 0;
    for (int i = 0; i < serviceCount; i++) {
      if (services[i].isUp) {
        upCount++;
      } else {
        downCount++;
      }
    }
    
    // Build status message
    String statusMsg = "Status: IP=" + ip + ", Battery=" + batteryStr + 
                      ", Uptime=" + uptimeStr + ", Services: " + String(upCount) + " up / " + 
                      String(downCount) + " down";
    
    if (senderPubKey != nullptr) {
      sendLoRaDirectMessage(statusMsg, senderPubKey, senderHash, replyPath, replyPathLen);
    } else {
      Serial.println("[Command] Missing sender public key; cannot reply");
    }
    Serial.println("=== Packet Processing Complete ===\n");
    return;
  }

  // Handle "reboot" command (PIN required)
  if (commandLower == "reboot") {
    Serial.println("[Command] Received reboot request");
    if (!pinOk) {
      Serial.println("[Command] Reboot denied: invalid or missing PIN");
      if (senderPubKey != nullptr) {
        sendLoRaDirectMessage("unauthorized", senderPubKey, senderHash, replyPath, replyPathLen);
      }
      Serial.println("=== Packet Processing Complete ===\n");
      return;
    }
    // Ensure ack/reply messages are sent successfully before rebooting
    bool replySent = false;
    if (senderPubKey != nullptr) {
      for (int attempt = 0; attempt < 3 && !replySent; attempt++) {
        if (attempt > 0) {
          Serial.printf("[Command] Retrying reboot reply (attempt %d/3)\n", attempt + 1);
          delay(200);
        }
        replySent = sendLoRaDirectMessage("rebooting", senderPubKey, senderHash, replyPath, replyPathLen);
      }
      if (!replySent) {
        Serial.println("[Command] WARNING: Failed to send reboot reply after 3 attempts, rebooting anyway");
      }
    }
    // Allow time for the final transmission to fully propagate before restarting
    pendingRestart = true;
    restartAtMs = millis() + 2000;
    Serial.println("[Command] Reboot scheduled after successful ack/reply");
    Serial.println("=== Packet Processing Complete ===\n");
    return;
  }

  // Handle "repeater on" command (PIN required)
  if (commandLower == "repeater on") {
    Serial.println("[Command] Received 'repeater on' request");
    if (!pinOk) {
      Serial.println("[Command] Repeater on denied: invalid or missing PIN");
      if (senderPubKey != nullptr) {
        sendLoRaDirectMessage("unauthorized", senderPubKey, senderHash, replyPath, replyPathLen);
      }
      Serial.println("=== Packet Processing Complete ===\n");
      return;
    }
    settings.repeaterEnabled = true;
    saveSettingsOverrides();
    sendBootAdvert();  // Re-advertise with new role
    if (senderPubKey != nullptr) {
      sendLoRaDirectMessage("repeater enabled", senderPubKey, senderHash, replyPath, replyPathLen);
    }
    Serial.println("[Command] Repeater mode enabled via remote command");
    Serial.println("=== Packet Processing Complete ===\n");
    return;
  }

  // Handle "repeater off" command (PIN required)
  if (commandLower == "repeater off") {
    Serial.println("[Command] Received 'repeater off' request");
    if (!pinOk) {
      Serial.println("[Command] Repeater off denied: invalid or missing PIN");
      if (senderPubKey != nullptr) {
        sendLoRaDirectMessage("unauthorized", senderPubKey, senderHash, replyPath, replyPathLen);
      }
      Serial.println("=== Packet Processing Complete ===\n");
      return;
    }
    settings.repeaterEnabled = false;
    saveSettingsOverrides();
    sendBootAdvert();  // Re-advertise with new role
    if (senderPubKey != nullptr) {
      sendLoRaDirectMessage("repeater disabled", senderPubKey, senderHash, replyPath, replyPathLen);
    }
    Serial.println("[Command] Repeater mode disabled via remote command");
    Serial.println("=== Packet Processing Complete ===\n");
    return;
  }
  
  // Also check path for our node hash to detect own messages
  if (pathLen >= 1) {
    size_t pathIdx = pathStart;
    for (size_t i = 0; i < pathLen; i++) {
      if (pathIdx < pathStart + pathLen) {
        uint8_t nodeHashInPath = (uint8_t)message[pathIdx];
        if (nodeHashInPath == ourNodeHash || nodeHashInPath == ourNodeHashAlt) {
          Serial.printf("Found our node hash (0x%02X/0x%02X) in path, not forwarding\n", ourNodeHash, ourNodeHashAlt);
          Serial.println("=== Packet Processing Complete ===\n");
          return;
        }
        pathIdx += 1;
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
  
  String forwardMsg = msgStr;

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
