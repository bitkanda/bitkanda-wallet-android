![ƀ](/images/icon.png) Bitkanda wallet for Android
----------------------------------

[![Get it on Google Play](/images/icon-google-play.png)](https://play.google.com/store/apps/details?id=com.bitkandawallet)

### Bitkanda done right

This is the Android port of the bitkanda wallet iOS app, which can be found [here](https://github.com/breadwallet/breadwallet/).

### a completely standalone bitkanda wallet

Unlike many other bitcoin wallets, bitkanda wallet is a real standalone bitkanda client. There is no server to get hacked or go down, so you can always access your money. Using [SPV](https://en.bitcoin.it/wiki/Thin_Client_Security#Header-Only_Clients) mode, bitkanda wallet connects directly to the bitkanda network with the fast performance you need on a mobile device.

### the next step in wallet security

bitkanda wallet is designed to protect you from malware, browser security holes, *even physical theft*. With AES hardware encryption, app sandboxing, and verified boot, breadwallet represents a significant security advance over web and desktop wallets.

### beautiful simplicity

Simplicity is bitkanda wallet's core design principle. A simple backup phrase is all you need to restore your wallet on another device if yours is ever lost or broken.  Because breadwallet is  [deterministic](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), your balance and transaction history can be recovered from just your backup phrase.

## features

- ["simplified payment verification"](https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki) for fast mobile performance
- no server to get hacked or go down
- single backup phrase that works forever
- private keys never leave your device
- import [password protected](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) paper wallets
- ["payment protocol"](https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki) payee identity certification

## How to set up the development environment
1. Download and install Java 7 or up
2. Download and Install the latest Android studio
3. Download and install the latest NDK https://developer.android.com/ndk/downloads/index.html or download it in android studio by "choosing the NDK" and press "download"
4. Go to https://github.com/breadwallet/breadwallet-android and clone or download the project
5. Open the project with Android Studio and let the project sync
6. Go to SDK Manager and download all the SDK Platforms and SDK Tools
7  If present, remove app/src/main/jni and remove app/src/main/secp
8. Initialize the submodules - <code>git submodule init</code>
9. Update the submodules - <code>git submodule update --recursive</code>
10. Go to the directory  /core/Java/Core/src/main/cpp  
and extract openssl's lib.tar.xz file to the current directory. 
11. Build -> Rebuild Project
