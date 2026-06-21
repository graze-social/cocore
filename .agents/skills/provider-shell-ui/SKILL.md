---
disable-model-invocation: false
name: provider-shell-ui
user-invocable: true
description: Build, launch, and drive the cocore macOS menu-bar app (provider-shell) to visually verify SwiftUI changes. Builds the DEV bundle, runs it, clicks through the tray menu/tabs via AppleScript/System Events, screencaptures window regions, and iterates. Use whenever you change provider-shell Swift UI and want to see the real rendered result rather than guessing.
---

# provider-shell UI dev loop

`provider-shell/` is a SwiftUI **menu-bar (LSUIElement) app** — there's no dock icon and no
window until you open one from the tray. So "does my UI change look right?" can't be answered by
reading code; you have to **build it, launch it, drive the tray to open the window, screenshot a
region, and look.** This skill is that loop.

Use it for any change under `provider-shell/Sources/CoCoreShell/*.swift` (Models/Status/Settings/
About tabs, menu bar, windows). It is the single most effective way to catch SwiftUI rendering
quirks (grouped-`Form` section bugs, clipped/cut-off content, label-vs-field layout, padding) that
are invisible in source.

## One-time setup: permissions

The process running these commands (your terminal/agent host) needs two macOS TCC grants. You'll
hit these as errors the first time:

- **Accessibility** — required to drive the app via `System Events`. Symptom:
  `osascript ... System Events got an error: ... not allowed assistive access. (-1719)`.
  Grant it under System Settings → Privacy & Security → Accessibility for your terminal app.
- **Screen Recording** — required for `screencapture`. Symptom:
  `screencapture: could not create image from display` (or `from rect`).
  Grant it under System Settings → Privacy & Security → Screen Recording.

If you can't grant them yourself, ask the user to (they may need to toggle the terminal app and
re-run). Until both are granted you can still build/run and read `/tmp/cocore.log`, just not
drive/screenshot.

## 1. Build the DEV bundle (never the prod one)

```bash
cd <repo root>
CONFIG=debug ./scripts/build-mac-app.sh        # DEV=1 auto-on for debug
```

This produces `provider-shell/build/cocore-dev.app` with a **distinct identity**
(`dev.cocore.shell.dev`, display name "co/core (dev)"). That isolation matters: a prod
`/Applications/cocore.app` shares the bundle id `dev.cocore.shell` and a login item, so without the
`.dev` id they fight over the single status item and you can end up driving/screenshotting the prod
app instead of your build. The DEV split (in `scripts/build-mac-app.sh`) is what makes this safe.

The script also (re)builds the bundled Rust `cocore` CLI via cargo — incremental, so it's a no-op
when unchanged. For a **fast type-check only** (no bundle, ~3s) while iterating:

```bash
swift build --package-path provider-shell -c debug 2>&1 | grep -iE 'error|Build complete'
```

## 2. Launch the LOCAL build, capturing logs

```bash
killall CoCoreShell 2>/dev/null; sleep 1
/Users/<you>/Documents/cocore/provider-shell/build/cocore-dev.app/Contents/MacOS/CoCoreShell \
  > /tmp/cocore.log 2>&1 &
sleep 3
```

Run the **binary directly** (not `open`): it guarantees the local build runs and pipes stderr to
`/tmp/cocore.log`, which is where SwiftUI fatal errors land. Example crash you'll see there:
`Fatal error: No ObservableObject of type AppState found` → a view lost its `.environmentObject(...)`.
(`open <path>` also runs the local bundle but logs go to the unified system log; avoid `open -n`,
which can spawn a confusing duplicate.)

Confirm it's the local build, not prod:

```bash
ps -o command= -p "$(pgrep -n CoCoreShell)"   # should print .../provider-shell/build/cocore-dev.app/...
```

## 3. Drive the tray → open the window → pick a tab

The status item lives in **menu bar 2** (menu bar 1 is the system bar). Open the main window and
land on a tab in one shot:

```bash
osascript <<'EOF'
tell application "System Events" to tell process "CoCoreShell"
  set sb to menu bar item 1 of menu bar 2
  click sb
  delay 0.6
  click menu item "Open co/core…" of menu 1 of sb
  delay 1.2
  set frontmost to true
  delay 0.3
  perform action "AXRaise" of window 1
  delay 0.3
  click button "Models" of toolbar 1 of window 1      -- or "Status" / "Settings" / "About"
  delay 0.6
  set p to position of window 1
  set s to size of window 1
  return "" & (item 1 of p) & " " & (item 2 of p) & " " & (item 1 of s) & " " & (item 2 of s)
end tell
EOF
```

The returned `x y w h` is the window frame **in points** — feed it straight to `screencapture -R`.
The window is an `NSTabViewController` (`.toolbar` tabs); the tabs are
`button "<label>" of toolbar 1 of window 1`.

## 4. Screenshot a region and look at it

```bash
screencapture -x -R 605,156,540,688 /tmp/shot.png    # x,y,w,h from step 3 (points, not pixels)
```

Then **Read `/tmp/shot.png`** with the Read tool — it renders the image so you can actually judge
the layout. Capture a tight region (e.g. `-R x,156,540,300`) to zoom into one section.

**Critical gotcha:** this is an accessory app, so its window constantly loses front position to
your editor/other apps — and `screencapture` grabs whatever pixels are on top. **Always re-raise
right before every capture:**

```bash
osascript -e 'tell application "System Events" to tell process "CoCoreShell"
  set frontmost to true
  perform action "AXRaise" of window 1
end tell' >/dev/null 2>&1
sleep 0.3
```

If a screenshot shows your code editor instead of the app, that's why — re-raise and recapture.

## 5. Scroll within the window

`System Events` can't post scroll-wheel events, and `CGScrollWheel` needs pyobjc Quartz (usually
absent). Instead, set the scroll area's scrollbar value (`0.0` = top, `1.0` = bottom):

```bash
osascript <<'EOF'
tell application "System Events" to tell process "CoCoreShell"
  set q to (UI elements of window 1)
  repeat while (count of q) > 0
    set e to item 1 of q
    set q to rest of q
    try
      if role of e is "AXScrollBar" then set value of e to 1.0
    end try
    try
      set q to q & (UI elements of e)
    end try
  end repeat
end tell
EOF
```

## 6. Iterate

Edit Swift → rebuild bundle (step 1) → `killall CoCoreShell` → relaunch (step 2) → drive (step 3) →
screenshot + Read (step 4) → repeat. Keep `/tmp/cocore.log` open in your head: an empty `pgrep`
after launch means it crashed; read the log.

## Handy techniques

- **Discover the AX tree** (find tab labels, button help text, text values) when selectors are
  unknown — recurse `UI elements of window 1` and print `role`/`title`/`description`/`value`. Buttons
  carry their `help` (e.g. trash buttons used `help "Remove this model"`).
- **Simulate app states without real data** by hand-writing the provision marker the UI polls:
  `~/.cocore/provision-status.json`, e.g.
  `{"phase":"provisioning","models":["mlx-community/Qwen2.5-3B-Instruct-4bit"],"bytesDownloaded":1288490188,"updatedAt":"<recent RFC3339>"}`
  (mtime must be <1h old). Delete it after. The running agent only overwrites it while actually
  provisioning, so it's safe to inject otherwise.
- **Reduce `@Published` churn:** the Models tab polls a marker every 0.5s; guard `@Published`
  writes (`if x != y { y = x }`) so an idle poll doesn't re-render the whole `Form`. Unbounded
  re-renders were a real source of grouped-`Form` glitches here.
- **Verify a screenshot caught the right window** before trusting it: check the `co/core` title bar
  / the blue toolbar tab is visible. If you see editor chrome or another app, re-raise (step 4).

## Cleanup

```bash
rm -f /tmp/shot*.png /tmp/cocore.log ~/.cocore/provision-status.json 2>/dev/null   # only if you injected the marker
killall CoCoreShell 2>/dev/null
```

## Gotchas worth remembering

- **Don't hardcode the window frame** — always re-query `position`/`size`; it varies.
- **`screencapture -R` is points**, same coordinate space as AppleScript `position`. Retina pixels
  are 2× but you don't deal with them here.
- **The DEV bundle id is the whole point** — if you ever drive what looks like the app but your
  code changes aren't there, you're on the prod `/Applications` build. Re-check the running path.
- **Grouped `Form` on recent macOS is finicky**: a section whose rows are a dynamic `ForEach` can
  render its last row *outside* the section background. Workaround used here: render the list inside
  one Form row as a `VStack` with manual `Divider()`s (see `ModelsView` "Active models").
