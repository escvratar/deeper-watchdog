#!/bin/bash
# Builds the Android app without Gradle: aapt2 → javac → d8 → zipalign → apksigner. Output: build/deeper-watchdog.apk
set -e
cd "$(dirname "$0")"
SDK=${ANDROID_HOME:-/root/Android/Sdk}; BT=$SDK/build-tools/34.0.0; JAR=$SDK/platforms/android-34/android.jar
VERSION=${VERSION:-1.1}; CODE=${CODE:-2}
rm -rf build; mkdir -p build/gen build/classes build/dex
$BT/aapt2 compile --dir res -o build/res.zip
$BT/aapt2 link -I $JAR --manifest AndroidManifest.xml -o build/base.apk build/res.zip --java build/gen \
  --min-sdk-version 24 --target-sdk-version 34 --version-code $CODE --version-name $VERSION --auto-add-overlay
javac -nowarn -source 11 -target 11 -encoding UTF-8 -classpath $JAR -d build/classes $(find src build/gen -name '*.java') 2>&1 | grep -v "bootstrap classpath\|^warning\|^1 warning" || true
$BT/d8 --lib $JAR --min-api 24 --release --output build/dex $(find build/classes -name '*.class')
cp build/base.apk build/unsigned.apk; (cd build/dex && zip -q ../unsigned.apk classes.dex)
$BT/zipalign -f -p 4 build/unsigned.apk build/aligned.apk
# The signing key stays in this folder: an update must be signed with the same key to install over the old app
[ -f release.jks ] || keytool -genkeypair -keystore release.jks -storepass deeperwatchdog -keypass deeperwatchdog -alias app \
  -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Deeper Watchdog" >/dev/null 2>&1
$BT/apksigner sign --ks release.jks --ks-pass pass:deeperwatchdog --ks-key-alias app --out build/deeper-watchdog.apk build/aligned.apk
$BT/apksigner verify build/deeper-watchdog.apk && ls -l build/deeper-watchdog.apk
