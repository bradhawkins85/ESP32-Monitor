#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <RadioLib.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
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

// --- MeshCore protocol constants ---
#define CIPHER_BLOCK_SIZE 16
#define CIPHER_MAC_SIZE 2
#define PAYLOAD_TYPE_GRP_TXT 0x05
#define TXT_TYPE_PLAIN 0x00
#define ROUTE_TYPE_FLOOD 0x01

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

// --- Global Variables ---
SX1262 radio = new Module(LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY);
int lastRssi = 0;
float lastSnr = 0;
bool wifiConnected = false;
unsigned long lastMessageTime = 0;
int messageCount = 0;
unsigned long lastPingTime = 0;

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

void initNodeIdentity() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  ourNodeId = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
  char nodeName[18];
  snprintf(nodeName, sizeof(nodeName), "%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  ourNodeName = String(nodeName);
  Serial.printf("Node identity: %s (ID: 0x%08X)\n", ourNodeName.c_str(), ourNodeId);
}

// Send LoRa notification for service status changes
void sendLoRaNotification(const String& serviceName, bool isUp, const String& message) {
#if LORA_ENABLED
  String notification = "[Monitor] " + serviceName + ": " + (isUp ? "UP" : "DOWN");
  if (message.length() > 0) {
    notification += " - " + message;
  }
  
  // Derive channel hash and key
  uint8_t channelHash;
  uint8_t channelKey[32];
  size_t channelKeyLen = 0;
  deriveChannelKey(CHANNEL_NAME, CHANNEL_SECRET, &channelHash, channelKey, &channelKeyLen);
  
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
#endif
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

  deriveChannelKey(CHANNEL_NAME, CHANNEL_SECRET, &channelHash, channelKey, &channelKeyLen);

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
                CHANNEL_NAME, nodeName, message.c_str(), timestamp, (unsigned int)pktIdx);

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
  
  // Setup WiFi (needed for forwarding and NTP sync)
  setupWiFi();
  
  // Initialize node identity for filtering own messages
  initNodeIdentity();
  
  // Sync time via NTP for proper timestamps
  if (wifiConnected) {
    syncNTP();
  }
  
  // Setup LoRa
  setupLoRa();
  
  Serial.println("System Ready");

  // Initialize LittleFS
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

      if (username == ADMIN_USERNAME && password == ADMIN_PASSWORD) {
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

  // --- Web Server Endpoints ---
  // ElegantOTA integration
  // ElegantOTA.setAuth(ADMIN_USERNAME, ADMIN_PASSWORD);  // Protect OTA with admin credentials
  // ElegantOTA.begin(&server);  // Temporarily disabled due to header conflicts

  // Status page (modern styled HTML)
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
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
    html += "<div class='header'><h1>🚀 ESP32 Uptime Monitor</h1><div class='subtitle'>Real-time service monitoring dashboard</div></div>";
    
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
      if (isAuthed) {
        html += "<div class='service-actions'>";
        html += "<button class='icon-btn' onclick='editService(" + String(i) + ")' title='Edit'>✏️</button>";
        html += "<button class='icon-btn delete' onclick='deleteService(" + String(i) + ")' title='Delete'>🗑️</button>";
        html += "</div>";
      }
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
    html += "function gotoOta(){if(!isAuthed){alert('Login required');return;}location.href='/ota';}";
    html += "const loginForm=document.getElementById('loginForm');";
    html += "if(loginForm){loginForm.addEventListener('submit',async e=>{e.preventDefault();const fd=new FormData(loginForm);const res=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({username:fd.get('username'),password:fd.get('password')})});if(res.ok){location.reload();}else{alert('Invalid credentials');}});}";
    html += "function logout(){fetch('/api/logout',{method:'POST',credentials:'include'}).then(()=>location.reload());}";
    html += "setInterval(()=>{if(!modalOpen) location.reload();},30000);";
    html += "updateFieldVisibility(document.getElementById('serviceType').value);";
    html += "</script>";
    html += "</body></html>";
    request->send(200, "text/html", html);
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
    // Shift services array
    for (int i = idx; i < serviceCount - 1; i++) {
      services[i] = services[i + 1];
    }
    serviceCount--;
    saveServices();  // Persist to LittleFS
    request->send(200, "text/plain", "Service deleted");
  });

  // API endpoint to test notifications
  server.on("/api/test-notification", HTTP_POST, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    const String testMsg = "This is a test notification from ESP32 Monitor";

  #if LORA_ENABLED
    sendLoRaNotification("Test", true, testMsg);
  #endif
  #if NTFY_ENABLED
    forwardToNtfy(testMsg);
  #endif
  #if DISCORD_ENABLED
    forwardToDiscord(testMsg);
  #endif
  #if WEBHOOK_ENABLED
    forwardToWebhook(testMsg);
  #endif
  #if EMAIL_ENABLED
    forwardToEmail(testMsg);
  #endif

    request->send(200, "text/plain", "Test notification triggered on enabled channels");
  });

  // OTA update page (protected)
  server.on("/ota", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!isAuthenticated(request)) return;
    String page = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
    page += "<title>OTA Update</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f7fafc;padding:24px;color:#2d3748;}";
    page += ".card{max-width:520px;margin:0 auto;background:#fff;border-radius:12px;padding:24px;box-shadow:0 8px 24px rgba(0,0,0,0.08);}";
    page += "h1{margin:0 0 12px;font-size:24px;}p{margin:0 0 16px;color:#4a5568;}";
    page += "input[type=file]{width:100%;padding:12px;border:2px dashed #cbd5e0;border-radius:10px;background:#f8fafc;cursor:pointer;margin-bottom:16px;}";
    page += "button{padding:12px 18px;border:none;border-radius:8px;background:#667eea;color:#fff;font-weight:600;cursor:pointer;}";
    page += "button:disabled{opacity:0.6;cursor:not-allowed;}";
    page += "#status{margin-top:12px;font-weight:600;}";
    page += "</style></head><body><div class='card'><h1>OTA Firmware Update</h1><p>Select a .bin file to upload and flash. Device will reboot after a successful update.</p>";
    page += "<input type='file' id='file' accept='.bin,.bin.gz'>";
    page += "<button id='uploadBtn'>Upload & Flash</button><div id='status'></div>";
    page += "<script>const btn=document.getElementById('uploadBtn');const fileInput=document.getElementById('file');const statusEl=document.getElementById('status');";
    page += "btn.onclick=async()=>{if(!fileInput.files.length){alert('Choose a firmware file');return;}btn.disabled=true;statusEl.textContent='Uploading...';";
    page += "const fd=new FormData();fd.append('firmware',fileInput.files[0]);";
    page += "try{const res=await fetch('/ota/upload',{method:'POST',body:fd,credentials:'include'});const txt=await res.text();statusEl.textContent=txt;if(res.ok){statusEl.textContent+=' Rebooting...';setTimeout(()=>location.href='/',4000);}else{btn.disabled=false;}}catch(e){statusEl.textContent='Upload failed';btn.disabled=false;}};";
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
      request->send(ok ? 200 : 500, "text/plain", ok ? "Update successful." : "Update failed.");
      if (ok) {
        delay(500);
        ESP.restart();
      }
    },
    [](AsyncWebServerRequest *request, String filename, size_t index, uint8_t *data, size_t len, bool final){
      if (!isAuthenticated(request, false)) return;
      if (index == 0) {
        if (!Update.begin()) {
          Update.printError(Serial);
        }
      }
      if (Update.write(data, len) != len) {
        Update.printError(Serial);
      }
      if (final) {
        if (!Update.end(true)) {
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

#if LORA_ENABLED
        sendLoRaNotification(source, true, message);
#endif
#if NTFY_ENABLED
        forwardToNtfy(combined);
#endif
#if DISCORD_ENABLED
        forwardToDiscord(combined);
#endif
#if WEBHOOK_ENABLED
        forwardToWebhook(combined);
#endif
#if EMAIL_ENABLED
        forwardToEmail(combined);
#endif

        request->send(200, "application/json", "{\"status\":\"ok\"}");
      }
    }
  );

  server.begin();
}

// ============================================
// Main Loop
// ============================================
void loop() {
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
  
  // Track and heal WiFi connectivity
  static unsigned long lastWifiAttempt = 0;
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
  
  // Check all services periodically
  checkAllServices();
  
  delay(10);
}

// ============================================
// WiFi Setup
// ============================================
void setupWiFi() {
  Serial.print("Connecting to WiFi: ");
  Serial.println(WIFI_SSID);
  
  WiFi.mode(WIFI_STA);
  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  
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
  } else {
    wifiConnected = false;
    Serial.println("\nWiFi connection failed!");
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
  int state = radio.begin(LORA_FREQ, LORA_BANDWIDTH, LORA_SPREADING_FACTOR, LORA_CODING_RATE, 
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
  Serial.print(LORA_FREQ);
  Serial.println(" MHz");
  Serial.print("Spreading Factor: SF");
  Serial.println(LORA_SPREADING_FACTOR);
  Serial.print("Bandwidth: ");
  Serial.print(LORA_BANDWIDTH);
  Serial.println(" kHz");
  Serial.print("Coding Rate: 4/");
  Serial.println(LORA_CODING_RATE);
  Serial.print("Channel: ");
  Serial.println(CHANNEL_NAME);
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
  deriveChannelKey(CHANNEL_NAME, CHANNEL_SECRET, &channelHash, channelKey, &channelKeyLen);
  
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
  
  #if NTFY_ENABLED
  #if NTFY_MESH_RELAY
  forwardToNtfy(forwardMsg);
  #else
  Serial.println("Ntfy mesh relay disabled, skipping");
  #endif
  #endif
  
  #if DISCORD_ENABLED
  #if DISCORD_MESH_RELAY
  forwardToDiscord(forwardMsg);
  #else
  Serial.println("Discord mesh relay disabled, skipping");
  #endif
  #endif
  
  #if WEBHOOK_ENABLED
  #if WEBHOOK_MESH_RELAY
  forwardToWebhook(forwardMsg);
  #else
  Serial.println("Webhook mesh relay disabled, skipping");
  #endif
  #endif
  
  #if EMAIL_ENABLED
  #if EMAIL_MESH_RELAY
  forwardToEmail(forwardMsg);
  #else
  Serial.println("Email mesh relay disabled, skipping");
  #endif
  #endif
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
  HTTPClient http;
  String url = String(NTFY_SERVER) + "/" + String(NTFY_TOPIC);
  
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
  http.addHeader("X-Message-ID", String(millis()));  // avoid dedup on server
  
  // Add authentication - MUST be after begin() and headers
  String ntfyToken = String(NTFY_TOKEN);
  String ntfyUsername = String(NTFY_USERNAME);
  String ntfyPassword = String(NTFY_PASSWORD);
  
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
  Serial.println("Would send: " + message);
  // TODO: Implement ESP_Mail_Client integration
}

// ============================================
// Forward to Discord
// ============================================
void forwardToDiscord(String message) {
  HTTPClient http;
  
  Serial.print("Forwarding to Discord: ");
  Serial.println(DISCORD_WEBHOOK_URL);
  
  // Create JSON payload
  JsonDocument doc;
  doc["content"] = "**ESP32 Uptime Alert**\n" + message;
  doc["username"] = "ESP32 Receiver";
  
  String payload;
  serializeJson(doc, payload);
  
  http.begin(DISCORD_WEBHOOK_URL);
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
  HTTPClient http;
  
  Serial.print("Forwarding to webhook: ");
  Serial.println(WEBHOOK_URL);
  
  // Create JSON payload
  JsonDocument doc;
  doc["message"] = message;
  doc["source"] = "ESP32_Uptime_Receiver";
  doc["timestamp"] = millis();
  doc["rssi"] = lastRssi;
  doc["snr"] = lastSnr;
  
  String payload;
  serializeJson(doc, payload);
  
  http.begin(WEBHOOK_URL);
  http.addHeader("Content-Type", "application/json");
  
  int httpResponseCode;
  if (String(WEBHOOK_METHOD) == "POST") {
    httpResponseCode = http.POST(payload);
  } else if (String(WEBHOOK_METHOD) == "PUT") {
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
