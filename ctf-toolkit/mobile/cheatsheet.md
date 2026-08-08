# mobile security cheatsheet

## first steps
```bash
file challenge.apk                           # verify it's a ZIP/APK
unzip challenge.apk -d extracted/            # manual extract
```

---

## apk analysis

### decompile apk

#### jadx (RECOMMENDED — best decompiler)
```bash
# https://github.com/skylot/jadx/releases
jadx challenge.apk                           # decompile to current dir
jadx -d output/ challenge.apk                # decompile to output dir
jadx-gui challenge.apk                       # GUI mode (easiest!)

# In jadx-gui:
# - Search (Ctrl+Shift+F) for "flag", "password", "secret", "key"
# - Look at AndroidManifest.xml for activities, permissions
# - Check res/values/strings.xml for hardcoded values
```

#### apktool (resource extraction + smali)
```bash
# https://ibotpeaches.github.io/Apktool/
apktool d challenge.apk -o output/           # decode APK
# Output: smali code, resources, AndroidManifest.xml

# Rebuild after modification:
apktool b output/ -o modified.apk
```

#### dex2jar + JD-GUI
```bash
# Convert DEX to JAR
d2j-dex2jar challenge.apk -o output.jar

# Open JAR in JD-GUI
jd-gui output.jar
```

### quick strings
```bash
strings challenge.apk | grep -iE "flag|ctf|inctf|password|secret|key|http"
unzip -p challenge.apk classes.dex | strings | grep -iE "flag|key|secret"
```

### androidmanifest.xml
```bash
# After apktool decode:
cat output/AndroidManifest.xml

# Look for:
# - android:debuggable="true"          -> can attach debugger
# - android:allowBackup="true"         -> can extract app data
# - exported activities/services       -> accessible from other apps
# - custom permissions
# - intent filters (deeplinks)
```

### resources to check
```bash
# Hardcoded strings:
cat output/res/values/strings.xml

# Shared preferences (stored secrets):
find output/ -name "*.xml" | xargs grep -l "password\|key\|secret\|flag"

# Assets folder:
ls output/assets/                            # databases, config files

# Native libraries:
ls output/lib/                               # .so files (arm64, x86)
```

---

## static analysis

### vuln patterns to search for
```bash
# In jadx output, search for:
grep -r "SharedPreferences" output/          # stored secrets
grep -r "getExternalStorage" output/         # world-readable storage
grep -r "MODE_WORLD_READABLE" output/        # insecure file permissions
grep -r "addJavascriptInterface" output/     # WebView JS bridge
grep -r "setJavaScriptEnabled" output/       # WebView JS enabled
grep -r "WRITE_EXTERNAL" output/             # external storage access
grep -r "Log\." output/                      # debug logging
grep -r "BuildConfig.DEBUG" output/          # debug checks
grep -r "SQLiteDatabase" output/             # local databases
grep -r "http://" output/                    # insecure HTTP
grep -r "checkServerTrusted" output/         # cert pinning bypass points
```

### hardcoded secrets
```bash
grep -rn "api[_-]key\|apikey\|secret\|password\|token" output/ --include="*.java" --include="*.xml" --include="*.json"
grep -rn "BEGIN.*KEY\|BEGIN.*CERTIFICATE" output/
```

---

## frida (dynamic analysis)

### setup
```bash
# Install Frida
pip install frida-tools

# On rooted Android device/emulator:
# Download frida-server for your arch from:
# https://github.com/frida/frida/releases
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Verify:
frida-ps -U                                  # list processes on device
```

### frida scripts

#### hook a function
```javascript
// hook.js
Java.perform(function() {
    var MainActivity = Java.use('com.example.app.MainActivity');
    
    // Hook checkPassword method
    MainActivity.checkPassword.implementation = function(input) {
        console.log('[*] checkPassword called with: ' + input);
        var result = this.checkPassword(input);
        console.log('[*] Result: ' + result);
        return result;  // or return true to bypass
    };
});
```

```bash
# Run:
frida -U -l hook.js -f com.example.app
```

#### bypass root detection
```javascript
Java.perform(function() {
    var RootDetection = Java.use('com.example.app.RootDetection');
    RootDetection.isRooted.implementation = function() {
        console.log('[*] isRooted bypassed');
        return false;
    };
});
```

#### bypass ssl pinning
```javascript
// Use: https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
Java.perform(function() {
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    // Create custom TrustManager that accepts all certs
    var TrustAllCerts = Java.registerClass({
        name: 'com.bypass.TrustAllCerts',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
});
```

#### dump func args
```javascript
Java.perform(function() {
    // Hook all methods of a class
    var target = Java.use('com.example.app.CryptoHelper');
    var methods = target.class.getDeclaredMethods();
    methods.forEach(function(method) {
        console.log('[*] Method: ' + method.getName());
    });
    
    // Hook specific encrypt method
    target.encrypt.overload('java.lang.String').implementation = function(input) {
        console.log('[*] encrypt input: ' + input);
        var result = this.encrypt(input);
        console.log('[*] encrypt output: ' + result);
        return result;
    };
});
```

### objection
```bash
pip install objection

# Explore app
objection -g com.example.app explore

# Inside objection:
android hooking list classes                  # list all classes
android hooking list class_methods com.example.app.MainActivity
android hooking watch class com.example.app.CryptoHelper  # watch all methods
android sslpinning disable                   # bypass SSL pinning
android root disable                         # bypass root detection
```

---

## adb commands
```bash
adb devices                                  # list connected devices
adb install challenge.apk                    # install APK
adb shell                                    # shell on device
adb pull /data/data/com.app/files/ ./local/  # pull app files
adb push local_file /sdcard/                 # push file to device
adb logcat | grep -i flag                    # check logs for flag
adb logcat -s "TAG"                          # filter by tag

# App data (requires root):
adb shell "run-as com.example.app cat /data/data/com.example.app/shared_prefs/prefs.xml"
```

---

## tools

| Tool | What | URL |
|------|------|-----|
| **jadx** | APK -> Java decompiler | https://github.com/skylot/jadx |
| **apktool** | APK decode/rebuild | https://ibotpeaches.github.io/Apktool/ |
| **Frida** | Dynamic instrumentation | https://frida.re/ |
| **objection** | Frida-powered toolkit | `pip install objection` |
| **MobSF** | Auto analysis | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| **Genymotion** | Android emulator | https://www.genymotion.com/ |
| **dex2jar** | DEX -> JAR | https://github.com/pxb1988/dex2jar |

## decision tree
```
Mobile challenge?
├- APK file -> jadx-gui -> search for flag/key/password
├- Need dynamic -> install on emulator -> Frida hook
├- Encrypted data -> find crypto class -> hook decrypt method
├- Root detection -> Frida bypass script
├- Network traffic -> Burp proxy + SSL pinning bypass
└- Native lib (.so) -> Ghidra -> reverse native code
```
