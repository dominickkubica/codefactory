"""Privacy: personal data going where it shouldn't, and Apple's privacy requirements for iOS apps.

Personal data (contact details, names, birth dates, location, health readings, device identifiers) written to logs,
sent to analytics or crash reporting, or stored unencrypted. Matched per line: a log, analytics or storage call whose
arguments name personal data. Every language.

Apple: every protected resource the code uses (camera, photos, location, health, contacts…) needs a usage
description in Info.plist, or App Review rejects the app and iOS ends it when it asks for permission. Native code
that uses a "required reason" API (UserDefaults, file timestamps, disk space, system uptime) needs a privacy manifest
(PrivacyInfo.xcprivacy). Expo apps declare both in app.json (`ios.infoPlist`, `ios.privacyManifests`, or a config
plugin's permission option), which counts.
"""

from __future__ import annotations

import contextlib
import json
import re
from pathlib import Path

from .checks import SRC_EXT, Check, Evidence, _docstring_lines
from .paths import is_script, is_test, walk

PERSONAL = re.compile(
    r"\b(?:e_?mail|email_?address|phone(?:_?number)?|mobile_?number|ssn|social_?security|date_?of_?birth|dob|birth_?(?:date|day)|"
    r"(?:home_?|street_?|postal_?|billing_?|shipping_?)address|zip_?code|postcode|first_?name|last_?name|full_?name|"
    r"passport|national_?id|tax_?id|latitude|longitude|lat|lng|coords|coordinates|geolocation|user_?location|heart_?rate|"
    r"blood_?(?:pressure|glucose|type|oxygen)|body_?(?:weight|fat|mass)|bodyweight|medical_?\w+|diagnosis|"
    r"health_?(?:data|record|samples?|info)|menstrual|credit_?card|card_?number|iban|ip_?address|device_?id|idfa|"
    r"advertising_?id|gaid|imei|android_?id)\b",
    re.I,
)
LOG = re.compile(
    r"(?:\bconsole\.(?:log|info|warn|error|debug)|\bprint|\bprintln|\bputs|\bNSLog|\bos_log|\blogger\.\w+|"
    r"\blogging\.(?:info|warning|error|debug|critical|exception)|\blog\.(?:info|warn|warning|error|debug|d|i|e|w|v)|"
    r"\bLog\.(?:d|i|e|w|v)|\bfmt\.Print\w*|\bslog\.\w+)\s*\(",
)
ANALYTICS = re.compile(
    r"(?:\banalytics\(\)?\.(?:track|identify|logEvent|setUserProperties?|setUserId|screen)|\blogEvent|\bmixpanel\.\w+|"
    r"\bamplitude\.\w+|\bposthog\.\w+|\bsegment\.\w+|\bSentry\.(?:setUser|setContext|setExtra|addBreadcrumb|captureMessage)|"
    r"\bcrashlytics\(\)\.\w+|\bFirebaseAnalytics\.\w+|\bAnalytics\.logEvent|\bBugsnag\.\w+|\bdatadogRum\.\w+)\s*\(",
)
STORE = re.compile(
    r"(?:\bAsyncStorage\.setItem|\blocalStorage\.setItem|\bsessionStorage\.setItem|\bUserDefaults\.standard\.set|"
    r"\bdefaults\.set|\bputString|\bSharedPreferences|\bMMKV\.set\w*|\bstorage\.set\w*)\s*\(",
)
ANY_SINK = re.compile(f"{ANALYTICS.pattern}|{LOG.pattern}|{STORE.pattern}")  # one search to skip lines with no sink
KEYS = ("privacy_analytics", "privacy_log", "privacy_storage", "ios_usage_missing", "ios_privacy_manifest")

# resource -> (Info.plist key, code that uses it, Expo config plugins that add the key themselves)
USAGE = {
    "camera": (
        "NSCameraUsageDescription",
        r"AVCaptureDevice|UIImagePickerController|launchCameraAsync|expo-camera|vision-camera|CameraView",
        ("expo-camera", "expo-image-picker", "react-native-vision-camera"),
    ),
    "photo library": (
        "NSPhotoLibraryUsageDescription",
        r"PHPhotoLibrary|PHPickerViewController|launchImageLibraryAsync|expo-media-library|MediaLibrary\.",
        ("expo-image-picker", "expo-media-library"),
    ),
    "location": (
        "NSLocationWhenInUseUsageDescription",
        r"CLLocationManager|getCurrentPositionAsync|watchPositionAsync|expo-location|navigator\.geolocation",
        ("expo-location",),
    ),
    "microphone": (
        "NSMicrophoneUsageDescription",
        r"AVAudioRecorder|Audio\.Recording|requestRecordPermission|expo-av|useAudioRecorder",
        ("expo-av", "expo-audio", "expo-camera"),
    ),
    "contacts": ("NSContactsUsageDescription", r"CNContactStore|expo-contacts|Contacts\.getContactsAsync", ("expo-contacts",)),
    "health data": (
        "NSHealthShareUsageDescription",
        r"HKHealthStore|HKQuantityType|react-native-health|healthkit",
        ("react-native-health", "@kingstinct/react-native-healthkit"),
    ),
    "calendar": ("NSCalendarsUsageDescription", r"EKEventStore|expo-calendar|Calendar\.getCalendarsAsync", ("expo-calendar",)),
    "Bluetooth": ("NSBluetoothAlwaysUsageDescription", r"CBCentralManager|CBPeripheralManager|react-native-ble", ()),
    "Face ID": (
        "NSFaceIDUsageDescription",
        r"LAContext|evaluatePolicy|expo-local-authentication|authenticateAsync",
        ("expo-local-authentication",),
    ),
    "motion": ("NSMotionUsageDescription", r"CMMotionActivityManager|CMPedometer|Pedometer\.", ("expo-sensors",)),
    "tracking": (
        "NSUserTrackingUsageDescription",
        r"ATTrackingManager|requestTrackingPermissionsAsync|expo-tracking-transparency",
        ("expo-tracking-transparency",),
    ),
}
# Apple's "required reason" API categories, as used from native code
REQUIRED_REASON = {
    "NSPrivacyAccessedAPICategoryUserDefaults": r"\bUserDefaults\b|\bNSUserDefaults\b|@AppStorage",
    # the file attribute keys, not a model's own `self.creationDate` (Loop's WatchContext)
    "NSPrivacyAccessedAPICategoryFileTimestamp": (
        r"FileAttributeKey\.(?:creation|modification)Date\b|(?<![\w)\]])\.(?:creation|modification)Date\b|"
        r"NSFileCreationDate|NSFileModificationDate|(?:creation|contentModification|attributeModification)DateKey"
    ),
    "NSPrivacyAccessedAPICategorySystemBootTime": r"systemUptime|mach_absolute_time",
    "NSPrivacyAccessedAPICategoryDiskSpace": r"volumeAvailableCapacity|NSFileSystemFreeSize|systemFreeSize|statfs\(",
}
NATIVE = (".swift", ".m", ".mm")


def _argument_text(line: str, call: re.Match) -> str:
    """The text of a call's arguments on this line (up to its closing parenthesis)."""
    depth, out = 1, []
    for ch in line[call.end() :]:
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0:
            break
        out.append(ch)
    text = "".join(out)

    def values_only(m: re.Match) -> str:  # a string's fixed text isn't data; only what's interpolated into it is
        found = re.findall(r"\$?\{([^{}]*)\}|\\\(([^()]*)\)|\$([A-Za-z_][\w.]*)", m.group(0))  # {x} ${x} \(x) $x
        return " ".join(a or b or c for a, b, c in found)

    return re.sub(r"""(["'`])(?:(?!\1).)*\1""", values_only, text)


def personal_data(root: Path, files: list[str], out: dict[str, Check]) -> None:
    for fid in files:
        if not fid.endswith(SRC_EXT) or is_test(fid):
            continue
        try:
            text = (root / fid).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not PERSONAL.search(text) or not ANY_SINK.search(text):
            continue
        prose = _docstring_lines(text) if fid.endswith(".py") else set()  # a docstring's example isn't the code
        # a CLI or seed script printing to the terminal of whoever runs it: the operator sees their own input
        terminal = is_script(fid) or re.search(r"(?:^|/)(?:cli|commands?|seeds?|seeders?|console)(?:/|$)", fid)
        mobile = fid.endswith((".swift", ".m", ".mm", ".kt", ".dart")) or "/android/" in fid or "/ios/" in fid
        for i, line in enumerate(text.splitlines(), 1):
            if len(line) > 1000 or line.lstrip().startswith(("#", "//", "*")) or not ANY_SINK.search(line) or i in prose:
                continue
            for key, pat in (("privacy_analytics", ANALYTICS), ("privacy_log", LOG), ("privacy_storage", STORE)):
                m = pat.search(line)
                args = _argument_text(line, m) if m else ""
                word = m and next((w for w in PERSONAL.finditer(args) if _personal(w, args, mobile, line)), None)
                if key == "privacy_log" and word and terminal and re.match(r"console\.|print|puts|IO\.puts|echo", m.group(0)):
                    break
                if m and word:
                    out[key].hits.append(Evidence(fid, i, line.strip()[:140]))
                    out[key].data[f"{fid}:{i}"] = word.group(0)
                    break


def _personal(word: re.Match, args: str, mobile: bool, line: str = "") -> bool:
    """Whether a personal-data word names a person's data here: not a repository's `FullName()` (or a gem version's,
    a script's), a server's own listen `ip_address`, or a device ID outside a phone app (syncthing's device IDs are key
    fingerprints)."""
    w = word.group(0).lower().replace("_", "")
    before = args[: word.start()]
    if w == "fullname" and re.search(
        r"(?:repo|repository|project|org|organization|team|package|pkg|group|app|module|version|gem|script|spec|class|"
        r"job|task|plugin|image|file|node|service|branch|tag|model|dataset|workflow|template)\w*\.\s*$",
        before,
        re.I,
    ):
        return False
    if w == "ipaddress" and re.search(r"listen|bind|server|local|host", line or args, re.I):
        return False
    return not (w in ("deviceid", "androidid", "imei", "idfa", "gaid", "advertisingid") and not mobile)


def _declared_keys(root: Path) -> tuple[set[str], set[str], bool]:
    """(usage-description keys declared, Expo config plugins listed, whether a privacy manifest exists)."""
    keys, plugins, manifest = set(), set(), False
    wanted = ("PrivacyInfo.xcprivacy", "Info.plist", "app.json", "app.config.json", "app.config.js", "app.config.ts")
    for rel in walk(root, names=wanted, suffixes=(".entitlements",)):
        path = root / rel
        if path.name == "PrivacyInfo.xcprivacy":
            manifest = True
        elif path.name == "Info.plist" or path.name.endswith(".entitlements"):
            keys |= set(re.findall(r"<key>(NS\w+UsageDescription)</key>", path.read_text(encoding="utf-8", errors="replace")))
        elif path.name in ("app.json", "app.config.json") and path.parent == root:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            expo = data.get("expo", data)
            ios = expo.get("ios", {})
            keys |= {k for k in ios.get("infoPlist", {}) if k.endswith("UsageDescription")}
            manifest = manifest or bool(ios.get("privacyManifests"))
            for p in expo.get("plugins", []):
                plugins.add(p[0] if isinstance(p, list) else p)
        elif path.name.startswith("app.config.") and path.parent == root:  # JS/TS config: look for the keys as text
            text = path.read_text(encoding="utf-8", errors="replace")
            keys |= set(re.findall(r"(NS\w+UsageDescription)", text))
            manifest = manifest or "privacyManifests" in text
            plugins |= set(re.findall(r"""["'](expo-[\w-]+|react-native-[\w-]+|@[\w-]+/[\w-]+)["']""", text))
    return keys, plugins, manifest


def _first_line(texts: dict[str, str], pattern: str) -> tuple[str, int, str] | None:
    """(file, line number, line) of the first match in code, not in a comment (`//  NSUserDefaults+Status.swift`, a
    file's own header, names the file): one search per file, lines only where it matched."""
    from .checks import COMMENT_LINE

    rx = re.compile(pattern)
    for fid, text in texts.items():
        for m in rx.finditer(text):
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.start())
            line = text[start : end if end >= 0 else None]
            if not COMMENT_LINE.match(line):
                return fid, text.count("\n", 0, m.start()) + 1, line
    return None


def apple(root: Path, files: list[str], out: dict[str, Check]) -> None:
    ios_project = (root / "ios").is_dir() or any(f.endswith(NATIVE) for f in files) or (root / "app.json").is_file()
    if not ios_project:
        return
    texts: dict[str, str] = {}
    for fid in files:
        if fid.endswith(SRC_EXT) and not is_test(fid):
            with contextlib.suppress(OSError):
                texts[fid] = (root / fid).read_text(encoding="utf-8", errors="replace")
    keys, plugins, manifest = _declared_keys(root)
    try:
        deps = set(json.loads((root / "package.json").read_text(encoding="utf-8")).get("dependencies", {}))
    except (OSError, ValueError):
        deps = set()
    for resource, (key, uses, plugin_names) in USAGE.items():
        if key in keys or plugins & set(plugin_names):
            continue
        where = _first_line(texts, uses)
        if where is None and not deps & set(plugin_names):
            continue
        fid, line, text = where or ("package.json", 1, ", ".join(sorted(deps & set(plugin_names))))
        out["ios_usage_missing"].hits.append(Evidence(fid, line, f"{resource}: no {key} ({text.strip()[:100]})"))
    if not manifest:
        # the manifest rule is for iOS, iPadOS, watchOS, tvOS and visionOS apps: not a Mac target's code (a Flutter or
        # React Native project's macos/ folder, an AppKit file)
        apple_mobile = {
            f: t
            for f, t in texts.items()
            if f.endswith(NATIVE) and "macos/" not in f.lower() and not re.search(r"^import (?:AppKit|Cocoa)\b", t, re.M)
        }
        for category, uses in REQUIRED_REASON.items():
            hit = _first_line(apple_mobile, uses)
            if hit:
                fid, line, text = hit
                name = category.removeprefix("NSPrivacyAccessedAPICategory")
                out["ios_privacy_manifest"].hits.append(
                    Evidence(fid, line, f"{name} API without a privacy manifest: {text.strip()[:100]}")
                )


def scan(root: Path, files: list[str]) -> dict[str, Check]:
    out = {k: Check(k) for k in KEYS}
    personal_data(root, files, out)
    apple(root, files, out)
    return out
