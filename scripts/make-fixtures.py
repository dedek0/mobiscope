#!/usr/bin/env python3
"""Generate synthetic APK/IPA fixtures for mobiscope smoke tests.

The fixtures are minimal but realistic enough to exercise platform detection,
the Android inventory (manifest + NSC + secret patterns) and the iOS analyzer
set (plist ATS, entitlements, Mach-O magic, strings).
"""
import argparse
import io
import os
import struct
import zipfile


ANDROID_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.smoke">
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.INTERNET" />
    <permission android:name="com.example.smoke.SYNC" android:protectionLevel="normal" />
    <application
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/smoke_nsc">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
            </intent-filter>
        </activity>
        <provider android:name=".DataProvider"
            android:exported="true"
            android:grantUriPermissions="true"
            android:authorities="com.example.smoke.provider" />
    </application>
</manifest>
"""

NSC = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set overridePins="true">
            <pin digest="SHA-256">YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
"""

JAVA_WITH_SECRET = """package com.example.smoke;

public class Config {
    public static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
    public static final String API_URL = "https://api.example.com/v1";
}
"""

JAVA_WITH_CRYPTO = """package com.example.smoke;

import java.security.MessageDigest;
import javax.crypto.Cipher;

public class Crypto {
    public String hash(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(s.getBytes()).toString();
    }
    public Cipher cipher() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
"""

INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.smoke</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleExecutable</key>
    <string>SmokeApp</string>
    <key>MinimumOSVersion</key>
    <string>14.0</string>
    <key>UIFileSharingEnabled</key>
    <true/>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
        <key>NSExceptionDomains</key>
        <dict>
            <key>api.example.com</key>
            <dict>
                <key>NSExceptionAllowsInsecureHTTPLoads</key>
                <true/>
            </dict>
        </dict>
    </dict>
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>https</string>
                <string>smokeapp</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
"""

ENTITLEMENTS_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>aps-environment</key>
    <string>development</string>
    <key>com.apple.private.security.container-manager</key>
    <true/>
</dict>
</plist>
"""

SWIFT_WITH_SECRET = """import Foundation

class APIClient {
    let token = "ghp_abcdefghijklmnopqrstuvwxyz123456"
    func md5(_ s: String) -> Data {
        // CC_MD5 misuse for the iOS rule pack
        return Data()
    }
}
"""


def minimal_macho_arm64_encrypted() -> bytes:
    """A tiny 64-bit LE Mach-O with one LC_ENCRYPTION_INFO_64 (cryptid=1)."""
    buf = bytearray(128)
    # MH_MAGIC_64 LE
    buf[0:4] = bytes([0xCF, 0xFA, 0xED, 0xFE])
    # CPU_TYPE_ARM64 (0x0100000c LE)
    buf[4:8] = struct.pack("<I", 0x0100000C)
    # MH_EXECUTE
    buf[12:16] = struct.pack("<I", 0x2)
    # ncmds = 1
    buf[16:20] = struct.pack("<I", 1)
    # Load command at offset 32: LC_ENCRYPTION_INFO_64 (0x2c), cmdsize 24
    buf[32:36] = struct.pack("<I", 0x2C)
    buf[36:40] = struct.pack("<I", 24)
    # cryptid at cmd+16
    buf[48:52] = struct.pack("<I", 1)
    return bytes(buf)


def write_zip(path: str, entries: dict) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


def make_apk(path: str) -> None:
    write_zip(path, {
        "AndroidManifest.xml": ANDROID_MANIFEST,
        "classes.dex": b"dex\n035\x00" + b"\x00" * 32,
        "classes2.dex": b"dex\n035\x00" + b"\x00" * 16,
        "res/xml/smoke_nsc.xml": NSC,
        "res/layout/main.xml": "<LinearLayout/>",
        "unknown/com/example/smoke/Config.java": JAVA_WITH_SECRET,
        "unknown/com/example/smoke/Crypto.java": JAVA_WITH_CRYPTO,
        "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
    })


def make_ipa(path: str) -> None:
    app = "Payload/SmokeApp.app"
    write_zip(path, {
        f"{app}/Info.plist": INFO_PLIST,
        f"{app}/entitlements.plist": ENTITLEMENTS_PLIST,
        f"{app}/SmokeApp": minimal_macho_arm64_encrypted(),
        f"{app}/_CodeSignature/CodeResources": "<plist/>",
        f"{app}/APIClient.swift": SWIFT_WITH_SECRET,
        f"{app}/Frameworks/Alamofire.framework/Alamofire": minimal_macho_arm64_encrypted(),
    })


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("platform", choices=["apk", "ipa", "both"])
    ap.add_argument("-o", "--outdir", default=".smoke-fixtures")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    if args.platform in ("apk", "both"):
        p = os.path.join(args.outdir, "smoke.apk")
        make_apk(p)
        print(f"apk: {p} ({os.path.getsize(p)} bytes)")
    if args.platform in ("ipa", "both"):
        p = os.path.join(args.outdir, "smoke.ipa")
        make_ipa(p)
        print(f"ipa: {p} ({os.path.getsize(p)} bytes)")


if __name__ == "__main__":
    main()
