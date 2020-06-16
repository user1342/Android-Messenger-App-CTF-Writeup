# Android Messenger CTF Writeup
A CTF challenge created for Android by [Mason CC](https://competitivecyber.club/).
- [GitHub](https://github.com/tlamb96/kgb_messenger) repo with resources and challenges
- [CTF writeup](https://medium.com/bugbountywriteup/android-ctf-kgb-messenger-d9069f4cedf8) by [Harshit Maheshwari](https://twitter.com/fake_batman_).

## FOSS Tools
- [Jadx-Gui](https://github.com/skylot/jadx) - For analyzing decompiled Java.
- [Frida](https://github.com/frida/frida/releases) - For hooking the Android application.
- [APKTool](https://ibotpeaches.github.io/Apktool/) - For patching the application
- [Android Studio](https://developer.android.com/studio) - Running Java samples.

## Challenge 1.0:
**Challenge: "The app keeps giving us these pesky alerts when we start the app. We should investigate."**

<img align="right" width="200" src="/images/integrity.jpg">
<br>

There is an integrity / tamper-detection check when the application is first run. This primarily utilizes two lines of Java in the ```onCreate``` method in the ```MainActivity``` class.

```java
String property = System.getProperty("user.home");
String str = System.getenv("USER");
if (property == null || property.isEmpty() || !property.equals("Russia")) {
    a("Integrity Error", "This app can only run on Russian devices.");
} else if (str == null || str.isEmpty() || !str.equals(getResources().getString(R.string.User))) {
    a("Integrity Error", "Must be on the user whitelist.");
} else {
    a.a(this);
    startActivity(new Intent(this, LoginActivity.class));
}
```

This code checks two system properties and if the expected value is not returned the application throws an error message and exits. The first of these values that it compares is with the string ```Russia``` the second is with a string in the ```strings.xml``` res file with the key ```User``` and value ```RkxBR3s1N0VSTDFOR180UkNIM1J9Cg==```. Using PowerShell (Or any other tool) we can decode this Base64 encoded string.

```shell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RkxBR3s1N0VSTDFOR180UkNIM1J9Cg=="))
```

This returns the first flag, however, we still need to get past this check to continue to the rest of the application.

One approach for this is to simply remove this code from the application. To do this we're going to use APKtool and patch the Smali.

```shell
apktool d kgb-messenger.apk
```

After opening the folder this has created you can use the ```AndroidManifest.xml``` file to find the entrypoint of the application. We know this to be ```MainActivity```. Traverse the SMALI to find this class and inside of it go to it's onCreate method. Inside of this method is the aformentioned code block. As we don't want to use this code block we're simply going to remove the condition and replace it with the code that was inside of the branch of the condition that we wanted to run.

```smali
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3

    invoke-super {p0, p1}, Landroid/support/v7/app/c;->onCreate(Landroid/os/Bundle;)V

    invoke-static {p0}, La/a/a/a/a;->a(Landroid/content/Context;)V

    new-instance v0, Landroid/content/Intent;

    const-class v1, Lcom/tlamb96/kgbmessenger/LoginActivity;

    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-virtual {p0, v0}, Lcom/tlamb96/kgbmessenger/MainActivity;->startActivity(Landroid/content/Intent;)V

    return-void
.end method
```

After we've done this we're going to need to go back to the directory with the starting apk in and run the below which will re-assemble our SMALI to a dalvik executable and APK.

```shell
apktool b kgb-messenger
```

Now go to the ```dist``` folder inside of the ```kgb-messenger``` folder and you'll have your assembled apk. Next you'll need to sign and align it.

```shell
keytool -genkey -v -keystore custom.keystore -alias mykeyaliasname -keyalg RSA -keysize 2048 -validity 10000
```
```shell
jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore custom.keystore -storepass password *.apk mykeyaliasname
```
```shell
zipalign 4 .\kgb-messenger.apk repackaged-final.apk
```

**FLAG:** FLAG{57ERL1NG_4RCH3R}

## Challenge 2.0
**Challenge: "This is a recon challenge. All characters in the password are lowercase."**

<img align="right" width="200" src="/images/login.jpg">
<br>

This challenge involves circumventing the login screen in ```LoginActivity.class```. The below code in the ```onLogin``` method is called when the ```LOGIN``` button is pressed.

```java
if (!this.n.equals(getResources().getString(R.string.username))) {
             Toast.makeText(this, "User not recognized.", 0).show();
             editText.setText("");
             editText2.setText("");
         } else if (!j()) {
             Toast.makeText(this, "Incorrect password.", 0).show();
             editText.setText("");
             editText2.setText("");
         } else {
             i();
             startActivity(new Intent(this, MessengerActivity.class));
         }
```

This shows that the username is first checked against a username in the ```strings.xml``` resource file. After viewing this file it can be seen that this specific string is ```codenameduchess```.

The ```j()``` method also checks the password provided and returns true if it is a match.

```java
private void i() {
    char[] cArr = {'(', 'W', 'D', ')', 'T', 'P', ':', '#', '?', 'T'};
    cArr[0] = (char) (cArr[0] ^ this.n.charAt(1));
    cArr[1] = (char) (cArr[1] ^ this.o.charAt(0));
    cArr[2] = (char) (cArr[2] ^ this.o.charAt(4));
    cArr[3] = (char) (cArr[3] ^ this.n.charAt(4));
    cArr[4] = (char) (cArr[4] ^ this.n.charAt(7));
    cArr[5] = (char) (cArr[5] ^ this.n.charAt(0));
    cArr[6] = (char) (cArr[6] ^ this.o.charAt(2));
    cArr[7] = (char) (cArr[7] ^ this.o.charAt(3));
    cArr[8] = (char) (cArr[8] ^ this.n.charAt(6));
    cArr[9] = (char) (cArr[9] ^ this.n.charAt(8));
    Toast.makeText(this, "FLAG{" + new String(cArr) + "}", 1).show();
}

private boolean j() {
    String str = "";
    for (byte b : this.m.digest(this.o.getBytes())) {
        str = str + String.format("%x", new Object[]{Byte.valueOf(b)});
    }
    return str.equals(getResources().getString(R.string.password));
}
```

Because this method returns ```true``` if the provided password matches the required password we're going to use Frida to make this method return true when called.

```shell
frida -U "com.tlamb96.spetsnazmessenger" -l .\challenge1.3.js --no-pause
```

```javascript
Java.perform(function(){
	Java.use("com.tlamb96.kgbmessenger.LoginActivity").j.overload().implementation=function(){
	return true
	}
})
```

Now when we use the username ```codenameduchess``` and any password while our Frida script is hooking the ```j()``` method we are allowed past. Then the flag will be disaplayed as a Toast message.

**FLAG:** FLAG{G4*G13^FR0}


## Challenge 3.0
**Challenge: "It looks like someone is bad at keeping secrets. They're probably susceptible to social engineering... what should I say?"**

<img align="right" width="200" src="/images/messenger.jpg">
<br>

This challenge is broken down into two parts which boil down to two strings that need to be entered into the chat dialogue.

```java
if (a(obj.toString()).equals(this.p)) {
    Log.d("MessengerActivity", "Successfully asked Boris for the password.");
    this.q = obj.toString();
    this.o.add(new com.tlamb96.kgbmessenger.b.a(R.string.boris, "Only if you ask nicely", j(), true));
    this.n.c();
}
if (b(obj.toString()).equals(this.r)) {
    Log.d("MessengerActivity", "Successfully asked Boris nicely for the password.");
    this.s = obj.toString();
    this.o.add(new com.tlamb96.kgbmessenger.b.a(R.string.boris, "Wow, no one has ever been so nice to me! Here you go friend: FLAG{" + i() + "}", j(), true));
    this.n.c();
}
```

The above method is called when a message is sent and there are two main methods here that check the validity of the message. The first is the ```a()``` method which checks the validity of the first message. Followed by ```b()``` which checks the validity of the second message. Both of these messages need to be entered correctly in one session (without skipping the former) to allow for the key to be displayed.



### Challenge 3.1

The ```a``` method XORs the provided values, see below

```java
private String a(String str) {
    char[] charArray = str.toCharArray();
    for (int i = 0; i < charArray.length / 2; i++) {
        char c = charArray[i];
        charArray[i] = (char) (charArray[(charArray.length - i) - 1] ^ '2');
        charArray[(charArray.length - i) - 1] = (char) (c ^ 'A');
    }
    return new String(charArray);
}
```
If we take the hardcoded value (```"V@]EAASB\u0012WZF\u0012e,a$7(&am2(3.\u0003";```) that the previous method's output is compared against and enter it into a function that does an inverse of the previous method we should be able to get the required string.

If you make a quick Android application and Log the output of the below method when the above string is entered into it you'll be returned another string (```Boris, give me the password```) which should be entered into the messenger application message diologue.

```java
private String a(String str) {
    char[] charArray = str.toCharArray();
    for (int i = 0; i < charArray.length / 2; i++) {
        char c = charArray[i];
        charArray[i] = (char) (charArray[(charArray.length - i) - 1] ^ 'A'); //switched a and 2
        charArray[(charArray.length - i) - 1] = (char) (c ^ '2');
    }
    return new String(charArray);
}
```

### Challenge 3.2
TBC
