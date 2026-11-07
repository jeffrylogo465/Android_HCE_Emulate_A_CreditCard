# Android HCE Emulate a Credit Card (EMV card)

This app will explain how to run an emulation of a Credit Card ("EMV card", CC) using the **Host Based 
Card Emulation (HCE)** feature on Android devices. It is showing the basics on how to get called 
by a Credit Card Terminal (NFC Reader), process the incoming messages from the terminal and respond 
accordingly to the terminal.

The complete process is a kind of "Question & Answer" game - the terminal requests some data, the
(emulated) card responds the requested data, the terminal requests new data (based on the data send 
to the terminal in the first step) - the card is answering and so on. It may take up to 10 rounds 
before a transaction is finished and processed by the CC terminal ("POS Terminal").

As this repository is the accompanying resource for a tutorial on medium.com I wrote there is no real 
"final" code but a lot of pieces that will form the complete picture.

The tutorial is published here: https://medium.com/@androidcrypto/how-to-emulate-a-credit-card-on-android-with-host-based-card-emulation-hce-in-java-0652342da0f1

This app is based on the tutorial "**How to use Host-based Card Emulation (HCE) in Android — a beginner 
tutorial (Java)**" that is published here: https://medium.com/@androidcrypto/how-to-use-host-based-card-emulation-hce-in-android-a-beginner-tutorial-java-32974dd89529.

The tutorial is accompanied by a GitHub repository as well: https://github.com/AndroidCrypto/Android_HCE_Beginner_App/. 

**I strongly recommend to read this tutorial before starting with this one as I won't repeat some parts 
here.**

## To avoid any disappointments
This app is just the base for a final app and will help you to understand how the basics of the Host 
Based Emulation for emulating Credit Cards is setup, but it will not be a ready to application that 
is being able to run a complete transaction on a POS Terminal !

A second note: for good reasons a Credit Card (EMV card) is not a simple NFC storage tag that you can read or 
write. Even when comparing a Credit Card with a MIFARE DESFire EV3 tag the EMV tag has some features 
that go far beyond the DESFire one. The most important reason is that sensitive data should never leave 
the tag - they will never be exposed by a read command. Some tasks when working with an EMV card include 
cryptographic calculations, they are completely done within the tag and only the result will be 
responded to the POS Terminal. Some operation e.g. are secured by a digital signature that is 
calculated by the EMV card on base of transaction parameters. A digital signature is done by using a 
**Private Key** and later verified by the "**Public Key**. As the Public Key is available (as the name 
says) in the public everyone can use them to verify the response (or better the signature based on 
the response). The Private Key is written to tag during card manufacturing by the Credit Card issuer 
and you will never get knowledge about this key. So your emulated CC will never being able to create 
a valid signature that can get responded to the terminal and has a valid signature. Of course, not 
every transaction may get processed with high "security" priority, but in general it is really hard 
to make a working code.

## Link to my NFC Credit Card Reader tutorial

**Talk to your Credit Card**: https://medium.com/@androidcrypto/talk-to-your-credit-card-android-nfc-java-d782ff19fc4a

The final app is available on GitHub for self compiling (recommended) or you can download the final 
app (subfolder debug-release) of part 7 here: [https://github.com/AndroidCrypto/TalkToYourCreditCardPartG8](https://github.com/AndroidCrypto/TalkToYourCreditCardG8)

It is recommended to use this app for your first steps as this is an EMV/Credit Card Reader application 
that is acting like a real POS terminal. Of course - if you should have an own POS terminal feel free to 
use it instead of the app. But please be aware: the final app won't allow to make payments as a lot of steps are missing. 
It is unpredictable how a business terminal act's on my emulated Credit Card.

## These are the three steps to create a HCE Credit Card emulator

### 1 Setup an application with just a MainActivity class (Activity)

As the HCE Emulation is done in a background service we do not need much UI stuff. Additionally create a service class
(e.g. "HceCcEmulationService.java") that **extends HostApduService**. See the HCE Beginner tutorial 
how on to do so: https://medium.com/@androidcrypto/how-to-use-host-based-card-emulation-hce-in-android-a-beginner-tutorial-java-32974dd89529

### 2 Modify your AndroidManifest.xml file

As we need a binding of the service class to our app we need to append the HCE related service data:

```plaintext
<service                                                                                         
    android:name=".HceCcEmulationService"                                                        
    android:exported="true"                                                                      
    android:permission="android.permission.BIND_NFC_SERVICE">                                    
    <intent-filter>                                                                              
        <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE" />             
        <!-- category required!!! this was not included in official android HCE documentation -->
        <category android:name="android.intent.category.DEFAULT" />                              
    </intent-filter>                                                                             
    <meta-data                                                                                   
        android:name="android.nfc.cardemulation.host_apdu_service"                               
        android:resource="@xml/apduservice" />                                                   
</service>                                                                                       
```

There are two file names defined: the *android:name=".HceCcEmulationService"* is pointing to the service 
class you created in 1) and the resource for meta-data: *android:resource="@xml/apduservice" /> * - 
this is the file "apduservice.xml", located in the "res" part of your project in the subfolder "xml".

This is one of the most important settings you are going to do. The content of "apduservice.xml" may look like mine:

```plaintext
<?xml version="1.0" encoding="utf-8"?>
<host-apdu-service xmlns:android="http://schemas.android.com/apk/res/android"
    android:description="@string/servicedesc"
    android:apduServiceBanner="@drawable/hce_260_96"
    android:requireDeviceUnlock="false">
    <aid-group android:description="@string/aiddescription"
        android:category="other">
        <!-- select PPSE 2PAY.SYS.DDF01 -->
        <aid-filter android:name="@string/hcePpse"/>
        <aid-filter android:name="@string/aidVisaCard"/>
        <aid-filter android:name="@string/aidMastercard"/>
    </aid-group>
</host-apdu-service>
```

There are 3 **aid-filter** defined in the file. The data behind the placeholders is in the res/values/strings.xml 
file:

```plaintext
<!-- select PPSE 2PAY.SYS.DDF01 -->
<string name="hcePpse">325041592E5359532E4444463031</string>
<!-- visa credit or debit card -->
<string name="aidVisaCard">A0000000031010</string>
<!-- mastercard credit or debit card -->
<string name="aidMastercard">A0000000041010</string>
```

You should not change the information given here but you can append new filters. The first filter 
("hcePpse") defines a "Select Payment Card" ("PPSE" command) call that is used by all POS terminals 
in the world when using contactless (NFC) cards. If you leave this command out or modify it your app 
will never called by terminal in default configuration. The emulated tag will respond some data to 
inform the terminal which applications are available on the 
(HCE) tag. 

The second ("aidVisaCard") and third ("aidMastercard") entries define a possible application of a Credit 
Card Issuer on the tag - that are the major Credit Card Companies like "Mastercard" or "Visa". At minimum one the 
two AIDs need to match the data that was responded by our HCE emulated tag on the "Select Payment Card" 
command. As the POS terminal receives the "PPSE respond" it selects which of (possible) multiple AIDs 
on the tag it should use for processing a payment. This application is called by a "Select Application 
by AID" command. If our Android application does not include this AID the call will never get forwarded 
from Android's OS to the app (or better to the service).

### 3 Modify your blank service class

Simply add four lines of code to your class. The "SELECT_OK_SW" defines a response that is "SUCCESS". 
The print on System's console prints out a byte array in hex encoding. After the print the method 
returns a "SUCCESS" to the reader.

```plaintext
...
public static byte[] SELECT_OK_SW = hexStringToByteArray("9000");
...
@Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle bundle) {
        System.out.println("processCommandApdu: " + bytesToHexNpe(commandApdu));
        System.out.println("processCommandApdu: " + new String(commandApdu, StandardCharsets.UTF_8));
        return SELECT_OK_SW;
    }
```

When tapping the device to the "Talk to your Credit Card" app there is just one line in the console:

```none
processCommandApdu: 00a404000e325041592e5359532e444446303100
processCommandApdu: ??�??2PAY.SYS.DDF01??
```

Beneath some unprintable bytes there is a cleartext message withing the incoming commandApdu: 
**2PAY.SYS.DDF01**. Using a search machine brings you to an article within the previous mentioned article series 
"Talk to your Credit Card" that explains what an NFC based Credit Card reader is doing to retrieve the data. 
In [Part 1](https://medium.com/@androidcrypto/talk-to-your-credit-card-android-nfc-java-d782ff19fc4a) 
you find the string "2PAY.SYS.DDF01" as well, it is the same as we defined in the "apduservice.xml" 
file. 

**Congratulations** - you took the most important hurdle on your way to implement an Credit Card Emulator !

## Next steps to emulate a Credit Card with HCE

For the next steps it is very helpful if you can use **your own Credit Card** with the "Talk to your 
Credit Card app". The log file of the app after reading a Credit Card is the best teacher to understand 
the next steps.

## A Note on processing sensitive data (e.g. Credit Card numbers, Expire dates)

Please **never ask a friend to hand out his or her Credit Card for test purposes**. The "Talk to your 
Credit Card app" exposes very sensitive data in a very easy way. Once the data is read out it is in the 
world.

Second: **never ever publish those data in forums or web sites**, even if they look harmless. When using 
the app you read the data from the card, and for example you get this analyzed data from a file:

```none
70 81 B4 -- Record Template (EMV Proprietary)
         9F 46 81 B0 -- ICC Public Key Certificate
                     47 46 1F FC A1 4B 5D FD C2 09 56 9C 8A 14 F1 76
                     44 25 1A A3 F4 AB EA 25 12 62 13 4B 92 09 82 F0
                     25 07 41 F9 6F CC B4 08 00 29 30 54 C0 D8 98 24
                     BA 7A C4 4E E7 BA B0 6F A1 57 FC CF 7E 52 D3 C6
                     4B 4D 8A CD 41 B9 77 4B 80 15 19 ED 6F EC 82 7E
                     C2 EC 29 F8 99 11 67 C4 53 77 65 59 A4 A0 6F D9
                     8C 4B 9B D1 54 8A 65 AF 2F 56 00 2A 83 6B DF 9A
                     04 0A 92 53 E6 53 58 4C 92 83 3C 3D 1A A8 E0 8C
                     4D E9 CD A1 02 60 44 F8 0F 39 A9 32 6A 57 49 65
                     98 98 7A 6B 3E 18 A5 F5 6A 8B DE DE 75 28 70 E8
                     79 37 76 DB 9D 32 5C CD 9C 7C A5 DB 33 C2 8F 04 (BINARY)
```

If you are familiar with cryptography you know that a key certificate is a chain of certificates 
that proof the correctness of some data. But, the **ICC Pub Key Certificate** contains additionally
these data after decryption:

```none
parsed recovered ICC Public Key
Recovered Data Header:                    106
Recovered Data Header Byte:               6a
Certificate Format:                       4
--------------------------------
Application Pan:                          4921828094896752ffff
Certificate Expiration Date:              0225
--------------------------------
Certificate Serial Number:                54f6de
Hash Algorithm Indicator                  1
ICC Public Key Algorithm Indicator:       1
ICC Public Key Length:                    128
ICC Public Key Exponent Length:           1
Leftmost Digits of the ICC Public Key:    cc1804e562a5d6b1f10bd992faec97a803fdbcb2ac8f8936fb18098688755d67ea37e5082f5c1a61075a43a720259f604ba7ed5eba751c53984b32526a5a319c9f07a6e8227785cb186201a0e9a3071e450b99feaa8e2182d68c112d422736dfeb0a3366370eba09ce8b32a51621d789cda3ae2e7e0ce66c28c74eff64c24eb5
Optional padding:                         bbbbbbbbbbbb
Hash Result :                             4dbe2c4f35c3a549af80f991318ad6ee76327d2a
Data Trailer:                             188
Data Trailer Byte:                        bc
```

**Oops, the certificate is containing e.g. the PAN that is the Credit Card number.** To all card 
"hijackers" - the data is from an **outdated Credit Card** that is no longer in use, so this number is 
**worthless**.

The decryption of the data is available with an Android app that is available on GitHub since many 
years. 

**To repeat it again: never ever publish data related to a payment card in the public !**

## Troubleshooting

Developing a HCE application brings a lot of frustration as in most times the claim is: "It does not 
work". Well, if your Credit Card reader doesn't find your HCE emulated tag or your HCE app (better: 
the service) isn't called there IS indeed a problem on your side. I'm trying to identify the problem.

### Is your Android device Host Based Card Emulation (HCE) "ready" ?

This sounds crazy on first thought, but even if you can work with your NFC reader to read an NFC tag 
there is not guaranty that HCE is supported. Solution in case of "not supported": get another Android 
device.

### Is the NFC service on your phone enabled ?

Don't rely on the fact that YOU did not put the service ever "off". Go to the "Connection" settings 
of your device to be clear that NFC is set to "on".

### Is your HCE service running and enabled on your Android device ?

When developing HCE apps you often installed not just one app. When more than one app is concurring 
with other apps to listen and answer to a "Select Payment Card" command (the first one in the 
communication chain) there may be hick-ups. To verify your service is up and no other apps can disturb 
the communication go to "Connect" settings, select "NFC" and click on a "button" that has something 
to do with "payments" (even on my different Samsung devices they are named different). Usually you 
are on a page informing you about apps for "contactless payments". Scroll down and there is a tab menu 
for "Payments" and "Other" - click on "Other". You may get a large list of applications that all run 
a HCE service on your device. Each of them can get enabled or disabled. Please deactivate for now 
all other apps and just leave the "HCE Credit Card" app enabled - that is our sample app. Btw: if the 
"HCE Credit Card" app isn't showing up here the  service is not running (either not started yet or 
was stopped).

### Is your HCE app listening to incoming commands ?

Your app will only listening to incoming command when the service is registered for some addresses 
called "Application Identifier" (AID). This registration is done by changing 3 files:
- **AndroidManifest.xml**: setups the service for HCE with 2 main parameter: 
- a) which class is the processing class (in my case "HceCcEmulationService.java") for incoming commands ?
- b) which file contains the addresses for AIDs and other data (in my case "apduservice.xml")
- **HceCcEmulationService.java**: does this class extend the "HostApduService" ?
- **apduservice.xml**: does this file use the category "Other" ? Does this file contain at least the AID "325041592E5359532E4444463031" ?
- eventually (yes in my case) **strings.xml**: in my app I extracted all static strings in apduservice.xml to the resource file "strings.xml" (e.g. "@string/hcePpse"). Does the string.xml file contains at least "325041592E5359532E4444463031" ?

You may that "*puh, of course*", but in my own experience I sometimes worked with several files to test, 
and in the end one file or setting pointed to wrong data, so please double check these settings 
**at all**.

### Did you (re-) enable your service in Android settings ?

Sometime the settings for your HCE app gets disabled, so check that it is still active: Go to 
Settings -> Connections -> NFC -> Tap and Pay -> category "payment" tab ("enable default payment service") 
and enable the HCE CC app (if not already done).

### Did you delete your HCE app from your Android device ?

Especially when you are in the development phase of your app you often switch between different versions 
of your HCE service class. After pressing the "Run" button in Android Studio everything seems to work 
correctly but **Android will still use the old service class**. For that reason you have to (physically) 
delete the app from your Android device and then press "Run" to re-install the app. Again: you need to 
do this if you **change the class** but not if you **change the content** within your class. Please do 
not forget to enable the HCE service in Android settings again (see above "Did you (re-) enable your 
service in Android settings ?").

### Did you use my "Talk to your Credit Card" application as POS Terminal ?

You may answer - "*I do have a good Credit Card reader*" but sometimes these readers are for specific 
Credit Cards only. For your first tests (to be for sure that the app IS working) use my app. It is 
part of a tutorial series about [Reading of Credit Cards](https://medium.com/@androidcrypto/talk-to-your-credit-card-android-nfc-java-d782ff19fc4a) and you get the final app (last updated in 
September 2024) here: https://github.com/AndroidCrypto/TalkToYourCreditCardG8

Latest update: Oct. 5.th, 2024
