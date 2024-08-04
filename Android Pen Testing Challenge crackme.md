
Checking the android apk file on virus total, here the apk file had no detections for checking  malicious program.
![[Pasted image 20240708215127.png]]
Checking the Hashes
**MD5**
```
30b7e0f19f73994bd9f3ab7cf8dc6756
```
**SHA-1**
```
1c47ff60241717e4ffe84eab33f80eedb6f924b6
```
**SHA-256**
```
529d4f9742292d6a0425eaa4bf7c05fea13a9454bb999e755546188f1146cce3
```
**Vhash**
```
fb0265538d33b76ba8bef35a864be454
```
### Executive Summary

The purpose of this assessment was to identify and exploit vulnerabilities within the "CrackMeNative" Android application. The application was subjected to a thorough static and dynamic analysis to uncover potential security flaws, focusing particularly on extracting and analyzing the native C++ library where the secret key was stored. The findings highlight the presence of hardcoded secrets within the native library, which can be exploited to bypass the application's security mechanisms.
### Scope

The assessment scope included the following activities:

- Decompiling the APK to understand its structure and components.
- Analyzing the AndroidManifest.xml file for configuration details.
- Examining native libraries using reverse engineering techniques.
- Identifying and extracting the secret key stored within the native library.
### Methodology

#### Tools Used

- **APKTool**: For decompiling the APK.
- **Radare2**: For analyzing the native C++ library.
- **Kali Linux**: As the operating system for performing the analysis.

#### Steps Performed

1. **Decompilation**: Used APKTool to decompile the APK and explore the application’s resources.
2. **Manifest Analysis**: Examined the AndroidManifest.xml file for insights into the application’s configuration.
3. **Native Library Analysis**: Used Radare2 to analyze the native C++ library (`libcrackmenative.so`) to locate the secret key.

### Findings

```yml
Contents
apkFileName: crackme.apk
compressionType: false
doNotCompress:
- resources.arsc
- assets/dexopt/baseline.prof
- assets/dexopt/baseline.profm
- lib/arm64-v8a/libcrackmenative.so
- lib/armeabi-v7a/libcrackmenative.so
- lib/x86/libcrackmenative.so
- lib/x86_64/libcrackmenative.so
- png
- webp
isFrameworkApk: false
packageInfo:
  forcedPackageId: '127'
  renameManifestPackage: null
sdkInfo:
  minSdkVersion: '26'
  targetSdkVersion: '33'
sharedLibrary: false
sparseResources: false
unknownFiles:
  DebugProbesKt.bin: '8'
  kotlin-tooling-metadata.json: '8'
usesFramework:
  ids:
  - 1
  tag: null
version: 2.7.0-dirty
versionInfo:
  versionCode: '1'
  versionName: '1.0'
```

#### Static Analysis

##### APK Decompilation

The APK was successfully decompiled using APKTool, revealing the following structure:


`AndroidManifest.xml apktool.yml assets kotlin lib META-INF original res smali unknown`

![[Pasted image 20240708214929.png]]
```

┌──(kali㉿Ashutosh)-[~]
└─$ ls
crackme.apk

┌──(kali㉿Ashutosh)-[~]
└─$ apktool d crackme.apk
I: Using Apktool 2.7.0-dirty on crackme.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/kali/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
I: Copying META-INF/services directory
```

```
┌──(kali㉿Ashutosh)-[~]
└─$ cd crackme

┌──(kali㉿Ashutosh)-[~/crackme]
└─$ ls
AndroidManifest.xml  apktool.yml  assets  kotlin  lib  META-INF  original  res  smali  unknown
```

AndroidManifest.xml file

```xml

┌──(kali㉿Ashutosh)-[~/crackme]
└─$ cat AndroidManifest.xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="33" android:compileSdkVersionCodename="13" package="com.shield.crackmenative" platformBuildVersionCode="33" platformBuildVersionName="13">    <permission android:name="com.shield.crackmenative.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature"/>
    <uses-permission android:name="com.shield.crackmenative.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application android:allowBackup="true" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules" android:extractNativeLibs="false" android:fullBackupContent="@xml/backup_rules" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:supportsRtl="true" android:theme="@style/Theme.CrackMeNative">
        <activity android:exported="true" android:name="com.shield.crackmenative.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <provider android:authorities="com.shield.crackmenative.androidx-startup" android:exported="false" android:name="androidx.startup.InitializationProvider">
            <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer" android:value="androidx.startup"/>
            <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer" android:value="androidx.startup"/>
        </provider>
    </application>
</manifest>
```

```

┌──(kali㉿Ashutosh)-[~/crackme/lib]
└─$ ls
arm64-v8a  armeabi-v7a  x86  x86_64

┌──(kali㉿Ashutosh)-[~/crackme/lib]
└─$ cd armeabi-v7a/

┌──(kali㉿Ashutosh)-[~/crackme/lib/armeabi-v7a]
└─$ ls
libcrackmenative.so
```

now we will analyze the libcrackmenative.so using radare2

![[Pasted image 20240708220007.png]]

```c
┌──(kali㉿Ashutosh)-[~/crackme/lib/armeabi-v7a]
└─$ r2 libcrackmenative.so
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x00000654]> aaa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze entrypoint (af@ entry0)
INFO: Analyze symbols (af@@@s)
INFO: Recovering variables
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods
INFO: Finding xrefs in noncode section (e anal.in=io.maps.x)
INFO: Emulate functions to find computed references (aaef)
INFO: Recovering local variables (afva)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
[0x00000654]>
```

![[Pasted image 20240708220059.png]]

```c
[0x00000654]> pdf
            ;-- section..text:
            ;-- entry.fini1:
            ;-- pc:
            ;-- r15:
            ; NULL XREF from aav.0x00000014 @ +0x4(r)
┌ 12: entry0 ();
│           0x00000654      04009fe5       ldr r0, [0x00000660]        ; [0x660:4]=0x12c0 ; [13] -r-x section size 524 named .text
│           0x00000658      00008fe0       add r0, pc, r0              ; 0x1920 ; " \x19"
└       ┌─< 0x0000065c      870000ea       b sym.imp.__cxa_atexit
[0x00000654]>

```

```c
[0x00000654]> afl
0x00000880    1     12 sym.imp.__cxa_atexit
0x00000874    1     12 sym.imp.__cxa_finalize
0x0000088c    1     16 sym.imp.__register_atfork
0x000008d4    1      8 sym.imp.__stack_chk_fail
0x000008bc    1      4 sym.imp.__strlen_chk
0x000008b0    1     12 sym.imp.malloc
0x000008a4    1      8 sym.imp.strlen
0x000008e0    1     12 sym.imp.memcpy
0x00000654    1     12 entry0
0x000007cc    7    114 sym.JNI_OnLoad
0x00000714    1    166 sym.compareKey
0x000008d0    1      4 fcn.000008d0
0x00000850    2     16 fcn.00000850
0x000008f0    1     12 fcn.000008f0
0x000006d8    1     60 sym.concat
0x000008c0    1     12 fcn.000008c0
0x000006cc    2     20 sym.getPC
0x000006b4    1      8 sym.getPD
0x000006c0    1      8 sym.getPE
0x000006a8    1      8 sym.getPb
0x00000668    2      8 entry.fini0
0x00000900    1     12 fcn.00000900
0x00000860    3     10 fcn.00000860
[0x00000654]>
```


```c
┌ 166: sym.compareKey (int16_t arg1, int16_t arg3, size_t size);
│           ; arg int16_t arg1 @ r0
│           ; arg int16_t arg3 @ r2
│           ; arg size_t size @ fp+0x0
│           ; var int16_t var_21h @ sp+0x7
│           ; var int16_t var_8h @ sp+0x8
│           ; var int16_t var_ch @ sp+0x28
│           0x00000714      f0b5           push {r4, r5, r6, r7, lr}
│           0x00000716      03af           add r7, var_ch
│           0x00000718      2de9000f       push.w {r8, sb, sl, fp}
│           0x0000071c      83b0           sub sp, 0xc
│           0x0000071e      0646           mov r6, r0                  ; arg1
│           0x00000720      2748           ldr r0, [0x000007c0]        ; [0x7c0:4]=0x12d0
│           0x00000722      1546           mov r5, r2                  ; arg3
│           0x00000724      a7f12102       sub.w r2, var_21h
│           0x00000728      7844           add r0, pc                  ; 0x19fc
│                                                                      ; reloc.__stack_chk_guard
│           0x0000072a      2946           mov r1, r5
│           0x0000072c      d0f800b0       ldr.w fp, [r0]              ; 0x19fc
│                                                                      ; reloc.__stack_chk_guard
│           0x00000730      dbf80000       ldr.w r0, [fp]
│           0x00000734      0290           str r0, [var_8h]
│           0x00000736      3068           ldr r0, [r6]
│           0x00000738      d0f8a432       ldr.w r3, [r0, 0x2a4]
│           0x0000073c      3046           mov r0, r6                  ; size_t size
│           0x0000073e      9847           blx r3
│           0x00000740      0446           mov r4, r0
│           0x00000742      00f0b6e8       blx sym.imp.malloc          ;  void *malloc(size_t size)
│           0x00000746      8046           mov r8, r0
│           0x00000748      3068           ldr r0, [r6]
│           0x0000074a      2946           mov r1, r5
│           0x0000074c      2246           mov r2, r4
│           0x0000074e      d0f8a832       ldr.w r3, [r0, 0x2a8]
│           0x00000752      3046           mov r0, r6
│           0x00000754      9847           blx r3
│           0x00000756      1b48           ldr r0, [0x000007c4]        ; [0x7c4:4]=0xfffffe6c
│           0x00000758      7844           add r0, pc                  ; 0x5c8 ; "whatawonderfulworld" ; size_t size
│           0x0000075a      00f0aae8       blx sym.imp.malloc          ;  void *malloc(size_t size)
│           0x0000075e      8246           mov sl, r0
│           0x00000760      1948           ldr r0, [0x000007c8]        ; [0x7c8:4]=0xfffffe8c
│           0x00000762      7844           add r0, pc                  ; 0x5f2 ; "bylouisarmstrong" ; size_t size
│           0x00000764      00f0a4e8       blx sym.imp.malloc          ;  void *malloc(size_t size)
│           0x00000768      8146           mov sb, r0
│           0x0000076a      5046           mov r0, sl                  ; void *s1
│           0x0000076c      1421           movs r1, 0x14               ; const void *s2
│           0x0000076e      00f0b8e8       blx sym.imp.memcpy          ; void *memcpy(void *s1, const void *s2, size_t n)
│           0x00000772      0646           mov r6, r0
│           0x00000774      4846           mov r0, sb                  ; void *s1
│           0x00000776      1121           movs r1, 0x11               ; const void *s2
│           0x00000778      00f0b2e8       blx sym.imp.memcpy          ; void *memcpy(void *s1, const void *s2, size_t n)
│           0x0000077c      451c           adds r5, r0, 1
│           0x0000077e      a819           adds r0, r5, r6
│           0x00000780      00f0a6e8       blx fcn.000008d0
│           0x00000784      5146           mov r1, sl
│           0x00000786      3246           mov r2, r6
│           0x00000788      0446           mov r4, r0
│           0x0000078a      00f062e8       blx fcn.00000850
│           0x0000078e      a019           adds r0, r4, r6
│           0x00000790      4946           mov r1, sb
│           0x00000792      2a46           mov r2, r5
│           0x00000794      00f05ce8       blx fcn.00000850
│           0x00000798      4046           mov r0, r8
│           0x0000079a      2146           mov r1, r4
│           0x0000079c      00f0a8e8       blx fcn.000008f0
│           0x000007a0      0299           ldr r1, [var_8h]
│           0x000007a2      dbf80020       ldr.w r2, [fp]
│           0x000007a6      8a42           cmp r2, r1
│           0x000007a8      01bf           itttt eq
│           0x000007aa      b0fa80f0       clz r0, r0
│           0x000007ae      4009           lsrs r0, r0, 5
│           0x000007b0      03b0           add sp, 0xc
│           0x000007b2      bde8000f       pop.w {r8, sb, sl, fp}
│           0x000007b6      08bf           it eq
└           0x000007b8      f0bd           pop {r4, r5, r6, r7, pc}
[0x00000654]>
```
### Radare2 Commands

1. **Launching Radare2 with the Binary**
    `r2 libcrackmenative.so`
    
    This command opens the binary file `libcrackmenative.so` in Radare2 for analysis.
    
2. **Analysis of the Binary**
    `aaa`
    
    The `aaa` command stands for "analyze all" and performs a series of analyses:
    
    - `aa`: Analyze all flags starting with `sym.` and `entry0`.
    - `af@@@i`: Analyze imports.
    - `af@ entry0`: Analyze entry point.
    - `af@@@s`: Analyze symbols.
    - `afva@@@F`: Analyze all functions' arguments and locals.
    - `aac`: Analyze function calls.
    - `aar`: Analyze a specified length of bytes of instructions for references.
    - `avrr`: Find and parse C++ vtables.
    - `aaef`: Emulate functions to find computed references.
    - `aaft`: Type matching analysis for all functions.
    - `aanr`: Propagate noreturn information.
3. **Listing All Functions**
    `afl`
    
    The `afl` command lists all the functions found in the binary with their addresses and sizes.
    
4. **Printing Disassembly of a Function**
    `pdf`
    
    The `pdf` command stands for "print disassembly function" and prints the disassembly of the current function. This is useful to see the detailed assembly instructions of a specific function.
    
5. **Listing Information About the Current Address**
    
    `[0x00000654]>`
    
    This prompt shows the current address in the disassembled binary, where `0x00000654` is the address being examined.
    

### Example Workflow Explanation

Here's a step-by-step explanation of the commands used in the workflow provided:

1. **Open the Binary in Radare2**
    `r2 libcrackmenative.so`
    
    This opens the binary in Radare2 for analysis.
    
2. **Analyze the Binary**
    `aaa`
    
    Performs a comprehensive analysis of the binary to identify functions, symbols, and other key elements.
    
3. **List All Functions**
    `afl`
    
    Lists all the functions discovered during the analysis, showing their addresses, sizes, and names.
    
4. **Print Disassembly of a Function**
    `pdf`
    
    Prints the disassembly of the currently selected function, allowing you to see the detailed instructions.
![[Pasted image 20240708220624.png]]

i could identify the string here "whatawonderfulworld" "bylouisarmstrong" why joining them and proving the input secret key in the application. was correct here!!
##### Key Extraction

The strings "whatawonderfulworld" and "bylouisarmstrong" were identified as parts of the secret key. Concatenating these strings revealed the secret key: `whatawonderfulworldbylouisarmstrong`.


![[Pasted image 20240708221005.png]]
### Recommendations

- To enhance the security of the application, the following measures are recommended:

1. **Avoid Hardcoding Secrets**: Store sensitive data securely, using Android's Keystore system or secure backend services.
2. **Code Obfuscation**: Use ProGuard or similar tools to obfuscate the code, making reverse engineering more difficult.
3. **Dynamic Analysis Resistance**: Implement techniques to detect and resist dynamic analysis tools like Radare2.
4. **Secure Key Management**: Use environment variables and secure storage for managing keys and sensitive data