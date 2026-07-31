@echo off
set CC_aarch64_linux_android=C:\Users\eason\AppData\Local\Android\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android29-clang.cmd
set AR_aarch64_linux_android=C:\Users\eason\AppData\Local\Android\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-ar.cmd
set PATH=%PATH%;C:\Users\eason\AppData\Local\Android\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin
cargo build --target aarch64-linux-android --features jni,local-proxy --release
copy target\aarch64-linux-android\release\libnexapipe_client.so c:\Users\eason\rust\nexapipe\ui-android\app\src\main\jniLibs\arm64-v8a\libnexapipe_client.so