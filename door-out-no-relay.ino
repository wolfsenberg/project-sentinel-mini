#include <SPI.h>
#include <MFRC522.h>
#include <WiFi.h>
#include <PubSubClient.h>

// ==================== CONFIGURATION ====================
#define SS_PIN 5
#define RST_PIN 27

// ── WiFi (Connect to Master's SoftAP) ──
const char* WIFI_SSID     = "SENTINEL_MASTER";
const char* WIFI_PASSWORD = "sentinel123";

// ── MQTT Broker (Mosquitto on PC) ──
// -- MQTT Broker (Mosquitto on PC) --
// Connect your PC to SENTINEL_MASTER WiFi, then run Mosquitto.
// The PC's IP on the SoftAP network is usually 192.168.4.2.
const char* MQTT_BROKER = "192.168.4.2";
const int   MQTT_PORT   = 1883;

// ── MQTT Topics ──
const char* TOPIC_TAPIN  = "sentinel/tapin";
const char* TOPIC_TAPOUT = "sentinel/tapout";

// ── Dynamic registered-card list ──
// (Handled server-side by Python Database)

// ==================== OBJECTS ====================
MFRC522 rfid(SS_PIN, RST_PIN);
WiFiClient espClient;
PubSubClient mqtt(espClient);

unsigned long lastWifiReconnect = 0;
unsigned long lastMqttReconnect = 0;

// ==================== SERIAL COMMAND PROCESSING ====================
void processSerialCommands() {
  while (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line == "ID?") {
      Serial.println("ID:TAPOUT");
    }
  }
}

// ==================== LIGHT RFID RECOVERY ====================
void lightRFIDRecover() {
  rfid.PCD_Init();
  delay(30);
  byte v = rfid.PCD_ReadRegister(rfid.VersionReg);
  if (v == 0x00 || v == 0xFF) {
    Serial.println("STATUS:RFID_RECOVER_FULL");
    SPI.end();
    delay(30);
    SPI.begin(18, 19, 23, 5);
    rfid.PCD_Init();
    delay(30);
  } else {
    Serial.println("STATUS:RFID_OK_LIGHT");
  }
}

// ==================== WIFI CONNECT ====================
void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;
  if (millis() - lastWifiReconnect < 3000) return;
  lastWifiReconnect = millis();

  Serial.println("STATUS:WIFI_CONNECTING");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(250);
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("STATUS:WIFI_CONNECTED_");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("STATUS:WIFI_FAIL");
  }
}

// ==================== MQTT RECONNECT ====================
void mqttReconnect() {
  if (mqtt.connected()) return;
  if (WiFi.status() != WL_CONNECTED) return;
  if (millis() - lastMqttReconnect < 3000) return;
  lastMqttReconnect = millis();

  Serial.println("STATUS:MQTT_CONNECTING");
  if (mqtt.connect("SENTINEL_SLAVE")) {
    Serial.println("STATUS:MQTT_CONNECTED");
  } else {
    Serial.print("STATUS:MQTT_FAIL_RC_");
    Serial.println(mqtt.state());
  }
}

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  delay(800);

  // Disable brownout
  #include "soc/rtc_cntl_reg.h"
  WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
  Serial.println("STATUS:BROWNOUT_DISABLED");

  SPI.begin();
  rfid.PCD_Init();
  Serial.println("STATUS:RFID_OK");

  // ── WiFi Station (connect to Master AP) ──
  WiFi.mode(WIFI_STA);
  Serial.print("STATUS:MAC_"); Serial.println(WiFi.macAddress());
  connectWiFi();

  // ── MQTT ──
  mqtt.setServer(MQTT_BROKER, MQTT_PORT);

  Serial.println("SYSTEM:READY");
  Serial.println("---");
}

// ==================== LOOP ====================
void loop() {
  // Process serial commands from PC app
  processSerialCommands();

  // Keep WiFi + MQTT alive
  connectWiFi();
  if (!mqtt.connected()) {
    mqttReconnect();
  }
  mqtt.loop();

  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String uid = "";
    for (byte i = 0; i < rfid.uid.size; i++) {
      uid += String(rfid.uid.uidByte[i], HEX);
    }
    uid.toUpperCase();

    Serial.print("TAP:");
    Serial.print(uid); Serial.println(",UNKNOWN");

    // Publish TAPOUT event via MQTT
    String payload = uid + ",TAPOUT,UNKNOWN," + String(millis());
    mqtt.publish(TOPIC_TAPOUT, payload.c_str());

    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();

    delay(80);
    lightRFIDRecover();
    delay(120);
  }
}