# AntiRot

A system-wide website blocker built on a macOS NetworkExtension content filter
(`NEFilterDataProvider`), the same mechanism Screen Time and Freedom use. It
blocks by hostname at the flow level, so it is immune to CDN IP rotation (the
x.com / Cloudflare problem), IPv6, and DNS caching.

> `CLAUDE.md` and `README.md` are symlinks to this file. Edit `AGENTS.md` only.

## Why this approach

| Layer | Blocks by | Beaten by |
|---|---|---|
| `/etc/hosts` | name to IP | browser DNS cache |
| `pf` firewall | IP address | CDN/anycast rotation, IPv6, VPN tunnels |
| content filter | hostname per flow | ECH, proxy/VPN tunnels (see limits) |

## Layout

- `App/` is the SwiftUI app (non-sandboxed). It activates the extension
  (`OSSystemExtensionRequest`), enables the filter (`NEFilterManager`), and edits
  the blocklist. It is a menu bar agent: `LSUIElement` keeps it out of the Dock,
  and a `MenuBarExtra` scene in `.window` style hosts the entire UI, so the panel
  carries its own Quit button.
- Running means blocking. `AppDelegate` drives both ends: launching enables the
  filter (`FilterController.enableOnLaunch`) and quitting disables it
  (`applicationShouldTerminate` defers the exit until the config save lands, and
  no longer than 5s). The toggle pauses blocking while the app runs. The
  extension stays installed across a quit; only `Deactivate` removes it, and
  reinstalling needs approval again.
- Launch submits an activation request unconditionally. Activation is
  idempotent, so an already-installed extension completes without prompting, and
  a missing or stale one is reinstalled.
- Every `NEFilterManager` mutation is queued through `FilterController.serialized`
  and runs alone. The manager is a process-wide singleton and each step awaits
  IPC, so concurrent callers interleave and the last save silently wins.
- `FilterExtension/` is the `NEFilterDataProvider` system extension. It runs as
  root, inspects TCP/443 TLS ClientHellos for the SNI hostname, and drops blocked ones.
  - `FilterDataProvider.swift`: `handleNewFlow` drops QUIC (UDP/443) and peeks
    TCP/443; `handleOutboundData` reads the SNI and matches the list.
  - `SNIInspector.swift`: parses the SNI from a TLS ClientHello.
  - `main.swift`: the entry point (`NEProvider.startSystemExtensionMode()` + `dispatchMain()`).
- `Shared/Blocklist.swift`: app-local list storage (`UserDefaults.standard`) plus
  the `isBlocked(_:in:)` matcher the extension calls.
- `project.yml`: the XcodeGen spec. The project is generated, not hand-built.

## How the blocklist reaches the extension

The extension runs as root, so it cannot read the app's files, `UserDefaults`, or
App Group container (those resolve to a different home for root). The app passes
the list through `NEFilterProviderConfiguration.vendorConfiguration` (key
`domains`), which the NetworkExtension framework delivers across the user/root
boundary.

- The app sets `vendorConfiguration` when enabling the filter and on every edit
  (`FilterController` owns `domains`; its `didSet` persists and syncs).
- Saving a changed config does not reload a running provider, so an edit bounces
  `isEnabled` off then on to restart the provider with the new list.
- The extension reads the list from `filterConfiguration.vendorConfiguration["domains"]`.

## Prerequisites (Apple Developer account)

- Paid account. The NE entitlement is not on the free tier.
- App IDs, with these capabilities enabled in the portal:
  - `com.ethancatzel.AntiRot`: System Extension, Network Extensions.
  - `com.ethancatzel.AntiRot.FilterExtension`: Network Extensions.
- Manual Developer ID provisioning profiles named `AntiRot` and
  `AntiRotFilterExtension`. Automatic signing cannot provision the
  `content-filter-provider-systemextension` entitlement, so signing is manual and
  `project.yml` references the profiles by `PROVISIONING_PROFILE_SPECIFIER`.

Change the bundle-ID prefix in one place (`project.yml`) and regenerate. The
extension ID must be prefixed by the app ID.

## What makes activation work

These are the non-obvious requirements. Missing any one fails activation:

- App is non-sandboxed, hardened runtime on, with entitlements
  `com.apple.developer.system-extension.install` and
  `com.apple.developer.networking.networkextension` = [`content-filter-provider-systemextension`].
  Its `Info.plist` has `NSSystemExtensionUsageDescription`.
- Extension `Info.plist` has `CFBundlePackageType` = `SYSX` and
  `NSSystemExtensionUsageDescription`. Its entitlements include
  `content-filter-provider-systemextension`.
- The extension's `PRODUCT_NAME` equals its full bundle ID, so the
  `.systemextension` filename matches the bundle ID (the framework requires this).

## Build, sign, run

```sh
xcodegen generate                        # regenerate the project from project.yml
xcodebuild -project AntiRot.xcodeproj -scheme AntiRot \
  -configuration Debug CODE_SIGNING_ALLOWED=NO build   # compile-check, no signing
```

To run it (a system extension loads only when notarized, in `/Applications`, with
SIP on):

1. Xcode: Product, Archive. Then Distribute App, Direct Distribution, Export (notarizes).
2. Move `AntiRot.app` to `/Applications`.
3. Launch it. It submits the activation request itself; approve in System
   Settings, General, Login Items and Extensions, Network Extensions.
4. Approve the content-filter prompt.

Replacing a build: macOS keys extension replacement off `CFBundleVersion`. A
same-version reinstall keeps the old extension, so bump
`CURRENT_PROJECT_VERSION` (or click Deactivate, then relaunch) to force the new
one.

## Release

`MARKETING_VERSION` is `YYYY.M.D`, the tag is `vYYYY.MM.DD`. Ship the notarized
bundle from `/Applications`, not a fresh build: verify it, zip it with `ditto`
(plain `zip` mangles the bundle's symlinks and breaks the signature), attach it
to a GitHub release.

```sh
spctl -a -vvv -t exec /Applications/AntiRot.app   # expect: source=Notarized Developer ID
xcrun stapler validate /Applications/AntiRot.app
ditto -c -k --keepParent --sequesterRsrc /Applications/AntiRot.app AntiRot-<version>.zip
gh release create v<version> AntiRot-<version>.zip --target main --title v<version> --notes '...'
```

## Conventions and gotchas

- XcodeGen owns the project. Edit `project.yml`, then `xcodegen generate`. Signing
  lives in `project.yml` (manual, Developer ID, per-target profile specifiers). Do
  not hand-edit `AntiRot.xcodeproj` or the generated Info.plist files.
- State is `@Observable` + `@MainActor`. The `OSSystemExtensionRequest` delegate
  callbacks are `nonisolated` and use `MainActor.assumeIsolated`, which is sound
  only because requests submit with `queue: .main`.
- Swift 5 language mode is deliberate. The code is Swift-6-clean on concurrency;
  the blocker is `NENetworkRule`'s `NS_REFINED_FOR_SWIFT` initializer importing as
  `__remoteNetwork:` under Swift 6.
- Blocking is two steps: activate the system extension (approved once), then
  enable the filter. Activation is not filtering. The app does both on launch,
  but they fail independently.
- `main.swift` is required. A system extension is a plain executable, not an
  auto-`main` app extension. Do not delete it.

## How blocking works and its limits

The filter reads the SNI hostname from the TLS ClientHello on TCP/443 and drops
the flow if the host is on the list. QUIC (UDP/443) is dropped outright so
browsers fall back to TCP/TLS, where the SNI is readable. This is immune to IP
rotation, IPv6, and DNS caching.

Limits, inherent to any non-MITM on-device filter:

- ECH (Encrypted Client Hello) encrypts the SNI, so it cannot be read. Cloudflare,
  which fronts x.com, supports it.
- Traffic that reaches a site only through a proxy or VPN tunnel bypasses the
  filter, because the SNI it sees is the tunnel endpoint, not the site.

## Debugging

- The filter logs at `info` level, which `log show` hides by default. Use:
  `log show --last 5m --info --predicate 'subsystem == "com.ethancatzel.AntiRot"'`
- Confirm a block at the network layer: `nc -z <ip> 443` succeeds (TCP opens) but
  `curl https://<host>` returns `000` (dropped at the SNI). A control host that is
  not on the list should return `200`.
- `systemextensionsctl list` shows activation state. The extension is a separate
  root process.
