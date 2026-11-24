"""Personal data in logs, analytics and unencrypted storage; Apple's usage descriptions and privacy manifests."""

import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from codefactory.privacy import scan


def tree(files: dict[str, str]) -> tuple[Path, list[str]]:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return root, sorted(files)


class PersonalDataTest(unittest.TestCase):
    def test_sinks_and_look_alikes(self):
        root, files = tree({"src/profile.ts": '''
            console.log("saved", user.email);
            analytics().logEvent("signup", { phone_number: form.phone_number });
            await AsyncStorage.setItem("profile", JSON.stringify({ date_of_birth: dob }));
            console.log(`API on http://${host}:${port}/api/health`);
            console.log("On your phone, open the app");
            console.log("steps", workout.steps.length);
            logger.info(`user ${userId} signed in`);
            '''})  # fmt: skip
        out = scan(root, files)
        self.assertEqual([e.line for e in out["privacy_log"].hits], [2])
        self.assertEqual([e.line for e in out["privacy_analytics"].hits], [3])
        self.assertEqual([e.line for e in out["privacy_storage"].hits], [4])


class AppleTest(unittest.TestCase):
    def test_usage_description_and_privacy_manifest(self):
        root, files = tree({
            "app.json": json.dumps({"expo": {"ios": {"infoPlist": {"NSHealthShareUsageDescription": "To read workouts"}},
                                             "plugins": [["expo-camera", {"cameraPermission": "To scan barcodes"}]]}}),
            "src/scan.tsx": "import { CameraView } from 'expo-camera';\nimport * as Location from 'expo-location';\n"
                            "const pos = await Location.getCurrentPositionAsync();\n",
            "targets/watch/Store.swift": "let id = UserDefaults.standard.string(forKey: \"wid\")\nlet h = HKHealthStore()\n",
        })  # fmt: skip
        out = scan(root, files)
        missing = [e.text for e in out["ios_usage_missing"].hits]
        self.assertEqual(len(missing), 1)
        self.assertTrue(
            missing[0].startswith("location: no NSLocationWhenInUseUsageDescription")
        )  # camera via plugin; health declared
        self.assertEqual([e.file for e in out["ios_privacy_manifest"].hits], ["targets/watch/Store.swift"])

    def test_a_manifest_in_app_json_counts(self):
        root, files = tree({
            "app.json": json.dumps({"expo": {"ios": {"privacyManifests": {"NSPrivacyAccessedAPITypes": []}}}}),
            "targets/watch/Store.swift": "let id = UserDefaults.standard.string(forKey: \"wid\")\n",
        })  # fmt: skip
        self.assertFalse(scan(root, files)["ios_privacy_manifest"].hits)


if __name__ == "__main__":
    unittest.main()
