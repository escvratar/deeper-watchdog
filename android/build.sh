#!/bin/bash
# Builds the Android app without Gradle: aapt2 → javac → d8 → zipalign → apksigner. Output: build/deeper-watchdog.apk
set -e
cd "$(dirname "$0")"
SDK=${ANDROID_HOME:-/root/Android/Sdk}; BT=$SDK/build-tools/35.0.0; JAR=$SDK/platforms/android-34/android.jar
VERSION=${VERSION:-1.2}; CODE=${CODE:-3}
# SSH for installing on a server: JSch (BSD), its Java 8 classes only (the jar's META-INF/versions are for newer JDKs)
JSCH=2.28.8; JSCH_JAR=libs/jsch-$JSCH.jar
[ -f $JSCH_JAR ] || { mkdir -p libs; curl -fsSL -o $JSCH_JAR https://repo1.maven.org/maven2/com/github/mwiede/jsch/$JSCH/jsch-$JSCH.jar; }
rm -rf build; mkdir -p build/gen build/classes build/dex build/assets build/jsch
cp ../install/dw-install.sh build/assets/
(cd build/jsch && unzip -q ../../$JSCH_JAR 'com/*')
$BT/aapt2 compile --dir res -o build/res.zip
$BT/aapt2 link -I $JAR --manifest AndroidManifest.xml -o build/base.apk build/res.zip --java build/gen -A build/assets \
  --min-sdk-version 26 --target-sdk-version 34 --version-code $CODE --version-name $VERSION --auto-add-overlay
javac -nowarn -source 11 -target 11 -encoding UTF-8 -classpath $JAR:$JSCH_JAR -d build/classes $(find src build/gen -name '*.java') 2>&1 | grep -v "bootstrap classpath\|^warning\|^1 warning" || true
$BT/d8 --lib $JAR --min-api 26 --release --output build/dex $(find build/classes build/jsch -name '*.class') 2>&1 \
  | grep -v "^Warning\|Missing class\|Type .* was not found\|is not found\|^ *$" || true
cp build/base.apk build/unsigned.apk; (cd build/dex && zip -q ../unsigned.apk classes.dex)
$BT/zipalign -f -p 4 build/unsigned.apk build/aligned.apk
# The signing key stays in this folder: an update must be signed with the same key to install over the old app
[ -f release.jks ] || keytool -genkeypair -keystore release.jks -storepass deeperwatchdog -keypass deeperwatchdog -alias app \
  -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Deeper Watchdog" >/dev/null 2>&1
$BT/apksigner sign --ks release.jks --ks-pass pass:deeperwatchdog --ks-key-alias app --out build/deeper-watchdog.apk build/aligned.apk
$BT/apksigner verify build/deeper-watchdog.apk && ls -l build/deeper-watchdog.apk
