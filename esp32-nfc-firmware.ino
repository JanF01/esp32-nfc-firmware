  #include <PN532_HSU.h>

  #include <PN532.h>

  #include <WiFi.h>

  #include <HTTPClient.h>

  #include <WebServer.h> 

  #include <ArduinoJson.h>

  #include <mbedtls/ecdsa.h>
  #include <mbedtls/sha256.h>
  #include <mbedtls/base64.h>
  #include <mbedtls/ecp.h>
  #include <mbedtls/oid.h>
  #include <mbedtls/x509_crt.h>
  #include <nvs_flash.h>
  #include <nvs.h>

  #define YELLOW_LED 19
  #define RED_LED 21
  #define GREEN_LED 23

  HardwareSerial mySerial(1);

  PN532_HSU pn532hsu(mySerial);

  PN532 nfc(pn532hsu);

  WebServer server(9111); 

  const char* AGGREGATOR_PUBKEY_PEM = "-----BEGIN PUBLIC KEY-----\n"
                                      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE65pSD538b3PQnfD98phf4fpu2HCh\n"
                                      "ytwJDhtOFtU5rIHtCHeQI41VVdH82ml8XcCHwhKI/LlNOByy7K5yyurjAw==\n"
                                      "-----END PUBLIC KEY-----\n";

  uint8_t keya[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // default key A for Mifare Classic

  uint8_t uid[7];   // Buffer to store the returned UID

  uint8_t uidLength;

  unsigned long greenLedOnTime = 0;
  bool greenLedActive = false;

  unsigned long redLedOnTime = 0;
  bool redLedActive = false;
  
  const char* ssid = "TP-LINK_9FF644";

  const char* password = "password";





  const char* serverUrl = "http://192.168.0.178:8000/access";

  bool verifySignature(const String& data, const char* signatureHex);
  void handleAccessEvent(StaticJsonDocument<1024>& doc);

  bool retrievePublicKey(const char* userId, char* publicKeyBuffer, size_t bufferSize) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("user_keys", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
      Serial.printf("Error (%s) opening NVS handle!\n", esp_err_to_name(err));
      return false;
    }

    size_t requiredSize;
    err = nvs_get_str(nvs_handle, userId, NULL, &requiredSize);
    if (err != ESP_OK || requiredSize > bufferSize) {
      nvs_close(nvs_handle);
      Serial.printf("Error (%s) retrieving key size or buffer too small.\n", esp_err_to_name(err));
      return false;
    }
    
    err = nvs_get_str(nvs_handle, userId, publicKeyBuffer, &requiredSize);
    nvs_close(nvs_handle);
    
    if (err != ESP_OK) {
      Serial.printf("Error (%s) reading key!\n", esp_err_to_name(err));
      return false;
    }

    return true;
  }


  void setup() {

    Serial.begin(115200);
    pinMode(YELLOW_LED, OUTPUT);
    pinMode(GREEN_LED, OUTPUT);
    pinMode(RED_LED, OUTPUT);
    digitalWrite(YELLOW_LED, LOW);
    digitalWrite(GREEN_LED, LOW);
    digitalWrite(RED_LED, LOW);

     esp_err_t ret = nvs_flash_init();
      if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        
          ESP_ERROR_CHECK(nvs_flash_erase());
          ret = nvs_flash_init();
      }
      ESP_ERROR_CHECK(ret);

    

    connectToWiFi();


    server.on("/receive_block", handleAddPubkey);
      
      // Start the server
    server.begin();
    Serial.println("HTTP server started");

    mySerial.begin(115200, SERIAL_8N1, 16, 17);

    nfc.begin();





    uint32_t versiondata = nfc.getFirmwareVersion();

    if (!versiondata) {

      Serial.println("Didn't find PN53x module");

      while (1);

    }



    nfc.SAMConfig();

    nfc.inRelease();        // stop any passive polling

    Serial.println("Waiting for an ISO14443A Card ...");

  }





  void loop() {

    server.handleClient();


    uint8_t id = nfc.inListPassiveTarget();



    if(id){



    uint8_t apduCommand[] = {

    0x00,    // CLA

    0xA4,    // INS = SELECT

    0x04, 0x00, // P1, P2 = select by name

    0x07,    // Lc = length of AID (7 bytes)

    0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // AID bytes, must match your phone's AID

    0x00    // Le = max expected length of response (0 = max)

    };



      uint8_t response[64];   // buffer for response

      uint8_t responseLength = sizeof(response);



      // Send APDU command to the card emulator

      bool success = nfc.inDataExchange(apduCommand, sizeof(apduCommand), response, &responseLength);



      if (success) {

      if (responseLength > 2 && response[responseLength - 2] == 0x90 && response[responseLength - 1] == 0x00) {

        Serial.println("✅ APDU response OK");

        response[responseLength - 2] = '\0';

        StaticJsonDocument<200> doc;

        DeserializationError error = deserializeJson(doc, (char*)response);



        if (error) {

        Serial.print("❌ JSON deserialization failed: ");

        Serial.println(error.f_str());

        } else {

        const char* userId = doc["id"];

        const char* roomName = doc["room"];

        

        if (userId && roomName) {

          Serial.print("📄 Parsed data: ID = ");

          Serial.print(userId);

          Serial.print(", Room = ");

          Serial.println(roomName);



          // Send data over WiFi

          sendDataToWifi(String(userId), String(roomName));

        } else {

          Serial.println("❌ JSON data is missing 'id' or 'room' fields.");

        }

        }

      } else {

        Serial.print("❌ APDU error status: ");

        Serial.print(response[responseLength - 2], HEX);

        Serial.print(" ");

        Serial.println(response[responseLength - 1], HEX);

      }

      } else {

      Serial.println("❌ APDU exchange failed");

      }



      delay(1000);

    }
    if (greenLedActive && millis() - greenLedOnTime >= 30000) {
      digitalWrite(GREEN_LED, LOW);
      greenLedActive = false;
    }
    if (redLedActive && millis() - redLedOnTime >= 30000) {
      digitalWrite(RED_LED, LOW);
      redLedActive = false;
    }
  }
  void handleAddPubkey() {
    String requestBody = server.arg("plain");

    StaticJsonDocument<1024> doc;
    DeserializationError error = deserializeJson(doc, requestBody);
    
    if (error) {
      server.send(400, "text/plain", "Bad Request: Invalid JSON");
      return;
    }

    const char* type = doc["type"];
    if (type == nullptr) {
      server.send(400, "text/plain", "Bad Request: Missing type field");
      return;
    }

    if (strcmp(type, "add_pubkey_event") == 0) {

    const char* type = doc["type"];
    const char* userId = doc["user_id"];
    const char* publicKey = doc["public_key"];
    const char* aggregatorSignature = doc["aggregator_signature"];

    // Create a new, canonicalized JSON object for signature verification
    StaticJsonDocument<512> canonicalDoc; 
    canonicalDoc["type"] = doc["type"];
    canonicalDoc["block_height"] = doc["block_height"];
    canonicalDoc["user_id"] = doc["user_id"];
    canonicalDoc["public_key"] = doc["public_key"];
    canonicalDoc["timestamp"] = doc["timestamp"];
    canonicalDoc["previous_block_hash"] = doc["previous_block_hash"];

    String canonicalString;
    serializeJson(canonicalDoc, canonicalString);
    Serial.print("Canonical string for verification: ");
    Serial.println(canonicalString);

    // Verify the signature
    if (verifySignature(canonicalString, aggregatorSignature, AGGREGATOR_PUBKEY_PEM)) {
      Serial.println("✅ Signature verified successfully!");
      
      // Save to NVS
        nvs_handle_t nvs_handle;
        esp_err_t err = nvs_open("user_keys", NVS_READWRITE, &nvs_handle);
        if (err != ESP_OK) {
         Serial.printf("Error (%s) opening NVS handle!\n", esp_err_to_name(err));
         server.send(500, "text/plain", "Internal Server Error: NVS open failed");
         return;
       }
      
       // Store the public key associated with the user ID
       err = nvs_set_str(nvs_handle, userId, publicKey);
       if (err != ESP_OK) {
         Serial.printf("Error (%s) writing to NVS!\n", esp_err_to_name(err));
         nvs_close(nvs_handle);
         server.send(500, "text/plain", "Internal Server Error: NVS write failed");
         return;
       }
      
       nvs_commit(nvs_handle);
       nvs_close(nvs_handle);
      Serial.println("✅ Public key saved to NVS.");
      server.send(200, "text/plain", "Public key received and stored successfully.");
      for (int i = 0; i < 5; i++) {
        digitalWrite(YELLOW_LED, HIGH);
        delay(200);
        digitalWrite(YELLOW_LED, LOW);
        delay(200);
      }
    } else {
      Serial.println("❌ Signature verification failed.");
      server.send(401, "text/plain", "Unauthorized: Signature verification failed.");
    }

    }else if (strcmp(type, "access_event") == 0) {
      handleAccessEvent(doc); // Call the new function for access_event
    } else {
      server.send(400, "text/plain", "Bad Request: Unknown event type");
    }
  }

  bool verifySignature(const String& data, const char* signatureHex, const char* publicKeyPem) {
    // 1. Convert hex signature to binary
    size_t sig_len = strlen(signatureHex) / 2;
    unsigned char signature_binary[sig_len];
    for (size_t i = 0; i < sig_len; i++) {
        sscanf(signatureHex + 2 * i, "%2hhx", &signature_binary[i]);
    }

    // 2. Hash the data
    unsigned char hash[32];
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (const unsigned char*)data.c_str(), data.length());
    mbedtls_sha256_finish(&sha256_ctx, hash);
    mbedtls_sha256_free(&sha256_ctx);

    // 3. Load the public key
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)publicKeyPem, strlen(publicKeyPem) + 1);
    if (ret != 0) {
        Serial.printf("❌ Failed to parse public key: -0x%x\n", -ret);
        mbedtls_pk_free(&pk);
        return false;
    }

    // 4. Verify the signature using the correct function
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature_binary, sizeof(signature_binary));
    mbedtls_pk_free(&pk);

    if (ret != 0) {
        Serial.printf("❌ Signature verification failed: -0x%x\n", -ret);
        return false;
    }
    
    return true;
  }

  void handleAccessEvent(StaticJsonDocument<1024>& doc) {
    // 1. Verify each individual vote
    JsonArray votes = doc["votes"].as<JsonArray>();
    if (votes.isNull()) {
      server.send(400, "text/plain", "Bad Request: Missing or invalid votes array");
      return;
    }

   for (JsonObject vote : votes) {
    const char* nodeId = vote["node_id"];
    const char* signature = vote["signature"];
    const char* publicKeyToUse;


    if (nodeId == nullptr || signature == nullptr) {
        server.send(400, "text/plain", "Bad Request: Vote is missing node_id or signature");
        return;
    }

    // Check if the nodeId is an aggregator and use the aggregator's public key
    if (strcmp(nodeId, "TyuP8hYipi8o") == 0) {
        publicKeyToUse = AGGREGATOR_PUBKEY_PEM;
        Serial.println("Using Aggregator's public key for TyuP8hYipi8o node.");
    } else {
        // Retrieve the public key for other nodes from NVS
        static char publicKeyBuffer[512]; // Use static to avoid stack overflow
        if (!retrievePublicKey(nodeId, publicKeyBuffer, sizeof(publicKeyBuffer))) {
            Serial.printf("❌ Public key for node %s not found in NVS.\n", nodeId);
            server.send(401, "text/plain", "Unauthorized: Public key for node not found.");
            return;
        }
        publicKeyToUse = publicKeyBuffer;
    }

    // Canonicalize the vote JSON for verification
    StaticJsonDocument<256> canonicalVoteDoc;
    canonicalVoteDoc["room"] = vote["room"];
    canonicalVoteDoc["candidate"] = vote["candidate"];  
    canonicalVoteDoc["node_id"] = vote["node_id"];
    canonicalVoteDoc["vote"] = vote["vote"];
  

    String canonicalVoteString;
    serializeJson(canonicalVoteDoc, canonicalVoteString);

    // Verify the signature with the selected public key
    if (!verifySignature(canonicalVoteString, signature, publicKeyToUse)) {
        Serial.printf("❌ Vote signature failed for node %s.\n", nodeId);
        server.send(401, "text/plain", "Unauthorized: Vote signature failed.");
        return;
    }
    Serial.printf("✅ Vote signature verified for node %s.\n", nodeId);
}

    // 2. Verify the aggregator signature
    const char* aggregatorSignature = doc["aggregator_signature"];
    if (aggregatorSignature == nullptr) {
      server.send(400, "text/plain", "Bad Request: Missing aggregator signature.");
      return;
    }

    // Create a new, canonicalized JSON object for the entire block
    StaticJsonDocument<1024> canonicalBlockDoc;
    canonicalBlockDoc["type"] = doc["type"];
    canonicalBlockDoc["block_height"] = doc["block_height"];
    canonicalBlockDoc["room"] = doc["room"];
    canonicalBlockDoc["timestamp"] = doc["timestamp"];
    canonicalBlockDoc["previous_block_hash"] = doc["previous_block_hash"];
    canonicalBlockDoc["votes"] = doc["votes"]; // Re-insert the votes array
    canonicalBlockDoc["user_id"] = doc["user_id"];
    canonicalBlockDoc["voting_summary"] = doc["voting_summary"];
    canonicalBlockDoc["added_to_chain"] = doc["added_to_chain"];

    String canonicalBlockString;
    serializeJson(canonicalBlockDoc, canonicalBlockString);

    // Use the pre-defined aggregator public key
    if (verifySignature(canonicalBlockString, aggregatorSignature, AGGREGATOR_PUBKEY_PEM)) {
      if(canonicalBlockDoc["added_to_chain"]==false){
        Serial.println("❌ Aggregator signature verified. Access not permitted");
        server.send(200, "text/plain", "Access event verified. Access not permitted.");
        digitalWrite(RED_LED, HIGH);
        redLedOnTime = millis();
        redLedActive = true;
      }else{
      Serial.println("✅ Aggregator signature verified successfully!");
      server.send(200, "text/plain", "Access event verified. Access granted.");
      digitalWrite(GREEN_LED, HIGH);
      greenLedOnTime = millis();
      greenLedActive = true;
      }
    } else {
      Serial.println("❌ Aggregator signature verification failed.");
      server.send(401, "text/plain", "Unauthorized: Aggregator signature failed.");
      digitalWrite(RED_LED, HIGH);
      redLedOnTime = millis();
      redLedActive = true;
    }
  }

  void connectToWiFi() {

  Serial.print("📡 Connecting to Wi-Fi...");

  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {

    delay(500);

    Serial.print(".");

  }

  Serial.println("\n✅ Wi-Fi connected");

  Serial.print("🌐 IP Address: ");

  Serial.println(WiFi.localIP());

  }

  void sendDataToWifi(String userId, String roomName) {

  if (WiFi.status() == WL_CONNECTED) {

    HTTPClient http;

    http.begin(serverUrl);

    http.addHeader("Content-Type", "application/json");
    http.setTimeout(5000);


    StaticJsonDocument<200> doc;

    doc["user"] = userId;

    doc["room"] = roomName;



    String jsonString;

    serializeJson(doc, jsonString);



    Serial.print("📤 Sending JSON: ");

    Serial.println(jsonString);



    int httpResponseCode = http.POST(jsonString);



    if (httpResponseCode > 0) {

    Serial.print("✅ HTTP Response code: ");

    Serial.println(httpResponseCode);

    String payload = http.getString();

    Serial.println(payload);

    } else {

    Serial.print("❌ HTTP POST failed. Error code: ");

    Serial.println(httpResponseCode);

    }



    http.end();

  } else {

    Serial.println("❌ Wi-Fi not connected. Cannot send data.");

  }

  }
