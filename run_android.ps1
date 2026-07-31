./build_android.bat
cd ui-android
.\gradlew.bat installDebug
adb shell am start -n com.nexa.pipe/.MainActivity

cd ..

adb logcat -c
rm nexa_vpn_log.txt
adb logcat -s NexaVpnService:D > nexa_vpn_log.txt