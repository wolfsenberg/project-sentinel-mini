#include <SPI.h>
#include <MFRC522.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <esp_task_wdt.h>

// ==================== CONFIGURATION ====================
#define SS_PIN 5
#define RST_PIN 27
#define RELAY_PIN 32
#define BUTTON_PIN 34            // Manual unlock button (input-only GPIO)
#define LED_PIN 2                // Built-in LED for countdown blink
#define DOOR_OPEN_TIME 3000      // 3 seconds
#define MANUAL_OPEN_TIME 7000    // 7 seconds for manual button

// ── WiFi SoftAP Settings ──
const char* AP_SSID     = "SENTINEL_MASTER";
const char* AP_PASSWORD = "sentinel123";

// -- MQTT Broker (Mosquitto on PC) --
// Connect your PC to SENTINEL_MASTER WiFi, then run Mosquitto.
// The PC's IP on the SoftAP network is usually 192.168.4.2.
const char* MQTT_BROKER = "192.168.4.2";
const int   MQTT_PORT   = 1883;

// ── MQTT Topics ──
const char* TOPIC_TAPIN     = "sentinel/tapin";
const char* TOPIC_TAPOUT    = "sentinel/tapout";
const char* TOPIC_UNREG_UID = "sentinel/unreg_uid";

// ── Dynamic registered-card list (populated from DB via serial) ──
String registeredCards[100];
int totalRegisteredCards = 0;

// ==================== OBJECTS ====================
MFRC522 rfid(SS_PIN, RST_PIN);
WiFiClient espClient;
PubSubClient mqtt(espClient);

unsigned long doorOpenStartTime = 0;
bool doorIsOpening = false;
bool needRebootAfterLock = false;

unsigned long lastMqttReconnect = 0;

// ==================== SERIAL COMMAND PROCESSING ====================
void processSerialCommands() {
  while (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line == "ID?") {
      Serial.println("ID:TAPIN");
      continue;
    }
    if (line.startsWith("CARDS:")) {
      // Full card list: CARDS:uid1,uid2,uid3,...
      String data = line.substring(6);
      totalRegisteredCards = 0;
      if (data.length() > 0) {
        int start = 0;
        while (start < (int)data.length() && totalRegisteredCards < 100) {
          int comma = data.indexOf(',', start);
          if (comma == -1) comma = data.length();
          String uid = data.substring(start, comma);
          uid.trim();
          if (uid.length() > 0) {
            registeredCards[totalRegisteredCards++] = uid;
          }
          start = comma + 1;
        }
      }
      Serial.print("STATUS:CARDS_LOADED_"); Serial.println(totalRegisteredCards);
    } else if (line.startsWith("CARD_ADD:")) {
      String uid = line.substring(9);
      uid.trim();
      if (uid.length() > 0 && totalRegisteredCards < 100) {
        // Avoid duplicates
        bool found = false;
        for (int i = 0; i < totalRegisteredCards; i++) {
          if (registeredCards[i] == uid) { found = true; break; }
        }
        if (!found) {
          registeredCards[totalRegisteredCards++] = uid;
          Serial.print("STATUS:CARD_ADDED_"); Serial.println(uid);
        }
      }
    } else if (line.startsWith("CARD_REMOVE:")) {
      String uid = line.substring(12);
      uid.trim();
      for (int i = 0; i < totalRegisteredCards; i++) {
        if (registeredCards[i] == uid) {
          // Shift remaining cards down
          for (int j = i; j < totalRegisteredCards - 1; j++) {
            registeredCards[j] = registeredCards[j + 1];
          }
          totalRegisteredCards--;
          Serial.print("STATUS:CARD_REMOVED_"); Serial.println(uid);
          break;
        }
      }
    } else if (line == "UNLOCK:") {
      // Python API says this tap is allowed
      unlockDoor();
      needRebootAfterLock = true;
    }
  }
}

// ==================== CARD MANAGEMENT ====================
bool isRegistered(String uid) {
  for (int i = 0; i < totalRegisteredCards; i++) {
    if (registeredCards[i] == uid) return true;
  }
  return false;
}

// ==================== RFID RECOVERY ====================
bool isRFIDAlive() {
  byte v = rfid.PCD_ReadRegister(rfid.VersionReg);
  return (v != 0x00 && v != 0xFF);
}

void recoverRFID() {
  SPI.end();
  delay(50);
  SPI.begin(18, 19, 23, 5);
  SPI.setFrequency(1000000);
  rfid.PCD_Init();
  delay(80);
  rfid.PCD_SoftPowerUp();
  delay(80);
  Serial.println(isRFIDAlive() ? "STATUS:RFID_RECOVERED" : "STATUS:RFID_RECOVER_FAIL");
}

// ==================== DOOR CONTROL ====================
void unlockDoor() {
  Serial.println("DOOR:UNLOCKING");
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
  rfid.PCD_SoftPowerDown();
  SPI.end();
  digitalWrite(RELAY_PIN, LOW);
  doorOpenStartTime = millis();
  doorIsOpening = true;
}

void checkDoorTimer() {
  if (doorIsOpening && millis() - doorOpenStartTime >= DOOR_OPEN_TIME) {
    digitalWrite(RELAY_PIN, HIGH);
    doorIsOpening = false;
    Serial.println("DOOR:LOCKED");

    delay(200);
    recoverRFID();

    if (needRebootAfterLock) {
      Serial.println("STATUS:CYCLE_SUCCESS_REBOOTING");
      delay(400);
      ESP.restart();
    }
  }
}

// ==================== MANUAL BUTTON UNLOCK ====================
void checkManualButton() {
  if (doorIsOpening) return;  // already open, ignore
  if (digitalRead(BUTTON_PIN) == LOW) {  // button pressed (active LOW)
    delay(50);  // debounce
    if (digitalRead(BUTTON_PIN) != LOW) return;  // false trigger

    Serial.println("DOOR:MANUAL_UNLOCK");

    // Shut down RFID to avoid conflicts
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    rfid.PCD_SoftPowerDown();
    SPI.end();

    // Cut relay power
    digitalWrite(RELAY_PIN, LOW);

    // 7-second countdown with LED blink
    for (int i = 7; i >= 1; i--) {
      esp_task_wdt_reset();  // keep watchdog happy
      Serial.print("DOOR:COUNTDOWN_"); Serial.println(i);

      // Blink LED: ON for 200ms, OFF for 800ms = 1 second per count
      digitalWrite(LED_PIN, HIGH);
      delay(200);
      digitalWrite(LED_PIN, LOW);
      delay(800);
    }

    // Re-lock door
    digitalWrite(RELAY_PIN, HIGH);
    digitalWrite(LED_PIN, LOW);
    Serial.println("DOOR:LOCKED");

    delay(200);
    SPI.begin(18, 19, 23, 5);
    SPI.setFrequency(1000000);
    rfid.PCD_Init();
    delay(80);
    rfid.PCD_SoftPowerUp();
    delay(80);
    recoverRFID();
  }
}

// ==================== MQTT CALLBACK ====================
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  String msg = "";
  for (unsigned int i = 0; i < length; i++) {
    msg += (char)payload[i];
  }
  Serial.print("RECV:"); Serial.println(msg);
}

// ==================== MQTT RECONNECT ====================
void mqttReconnect() {
  if (mqtt.connected()) return;
  if (millis() - lastMqttReconnect < 3000) return;  // retry every 3s
  lastMqttReconnect = millis();

  Serial.println("STATUS:MQTT_CONNECTING");
  if (mqtt.connect("SENTINEL_MASTER")) {
    Serial.println("STATUS:MQTT_CONNECTED");
    mqtt.subscribe(TOPIC_TAPOUT);
  } else {
    Serial.print("STATUS:MQTT_FAIL_RC_");
    Serial.println(mqtt.state());
  }
}

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  delay(600);

  // Disable brownout
  #include "soc/rtc_cntl_reg.h"
  WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
  Serial.println("STATUS:BROWNOUT_DISABLED");

  esp_task_wdt_init(10, true);  // 10s watchdog
  esp_task_wdt_add(NULL);

  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, HIGH);

  pinMode(BUTTON_PIN, INPUT);  // GPIO34 is input-only, use external pull-up
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  SPI.begin(18, 19, 23, 5);
  SPI.setFrequency(1000000);
  rfid.PCD_Init();
  delay(100);
  recoverRFID();

  // ── WiFi SoftAP ──
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASSWORD);
  delay(500);
  Serial.print("STATUS:SOFTAP_IP_");
  Serial.println(WiFi.softAPIP());
  Serial.println("STATUS:SOFTAP_OK");

  // -- MQTT --
  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  mqtt.setCallback(mqttCallback);

  needRebootAfterLock = false;
  Serial.print("STATUS:REGISTERED_CARDS_"); Serial.println(totalRegisteredCards);
  Serial.println("SYSTEM:READY");
  Serial.println("---");
}

// ==================== LOOP ====================
void loop() {
  esp_task_wdt_reset();
  processSerialCommands();
  checkDoorTimer();
  checkManualButton();

  // Keep MQTT alive
  if (!mqtt.connected()) {
    mqttReconnect();
  }
  mqtt.loop();

  if (doorIsOpening) return;

  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String uid = "";
    for (byte i = 0; i < rfid.uid.size; i++) {
      uid += String(rfid.uid.uidByte[i], HEX);
    }
    uid.toUpperCase();

    bool reg = isRegistered(uid);

    Serial.print("TAP:"); Serial.print(uid);
    Serial.print(","); Serial.println(reg ? "REG" : "UNREG");

    // Publish TAPIN event via MQTT (optional redundancy)
    String payload = uid + ",TAPIN," + (reg ? "REG" : "UNREG") + "," + String(millis());
    mqtt.publish(TOPIC_TAPIN, payload.c_str());

    if (!reg) {
      mqtt.publish(TOPIC_UNREG_UID, uid.c_str());
    }

    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    delay(150);
  }
}