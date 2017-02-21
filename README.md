# ![Logo](https://raw.githubusercontent.com/RobThree/TwoFactorAuth.Net/master/logo.png) .Net library for Two Factor Authentication

[![Build status](https://ci.appveyor.com/api/projects/status/0nmbbew6keeuo4j9)](https://ci.appveyor.com/project/RobIII/twofactorauth-net) [![NuGet version](http://img.shields.io/nuget/v/TwoFactorAuth.Net.svg?style=flat-square)](https://www.nuget.org/packages/TwoFactorAuth.Net/) [![License](https://img.shields.io/packagist/l/robthree/twofactorauth.svg?style=flat-square)](LICENSE) [![PayPal donate button](http://img.shields.io/badge/paypal-donate-orange.svg?style=flat-square)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=6MB5M2SQLP636 "Keep me off the streets")

.Net library, available as [NuGet package](https://www.nuget.org/packages/TwoFactorAuth.Net/), for [two-factor (or multi-factor) authentication](https://en.wikipedia.org/wiki/Multi-factor_authentication) using [TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm) and [QR-codes](https://en.wikipedia.org/wiki/QR_code). This is a .Net port of the [PHP TwoFactorAuth library](https://github.com/RobThree/TwoFactorAuth) (staying as close as possible to the PHP implementation, but using .Net conventions and codestyles).

<p align="center">
    <img src="https://raw.githubusercontent.com/RobThree/TwoFactorAuth.Net/master/TwoFactorAuth.Net.Documentation/media/multifactorauthforeveryone.png">
</p>

## Requirements
* [.NET Framework 4.5](https://www.microsoft.com/en-us/download/details.aspx?id=17851)
* Access to internet may be required if you use a [QrCodeProvider](https://github.com/RobThree/TwoFactorAuth.Net/tree/master/TwoFactorAuth.Net/Providers/Qr) that retrieves data/images from the web. 

## Installation
To install TwoFactorAuth.Net, run the following command in the [Package Manager Console](https://docs.nuget.org/docs/start-here/using-the-package-manager-console)

```powershell
PM> Install-Package TwoFactorAuth.Net
```

## Quickstart / Demo
If you want to hit the ground running then have a look at the [demo project](TwoFactorAuth.Net.Demo). It's very simple and easy! Also, if you're already familiar with the well known [TwoFactorAuth](https://github.com/RobThree/TwoFactorAuth) library for PHP then you should have no problem switching / using this .Net port. 

## Getting started

### Step 1: Set up secret shared key

When a user wants to setup two-factor auth (or, more correctly, multi-factor auth) you need to create a `secret`. This will be your **shared secret**. This `secret` will need to be entered by the user in their app. This can be done manually, in which case you simply display the `secret` and have the user type it in the app: 

```c#
var tfa = new TwoFactorAuth("MyCompany");
var secret = tfa.CreateSecret();
```

The `CreateSecret()` method accepts two arguments: `bits` (default: `80`) and `cryptoSecureRequirement` (default: `RequireSecure`). The former is the number of bits generated for the shared secret. Make sure this argument is a multiple of 8 and, again, keep in mind that not all combinations may be supported by all apps. Google Authenticator seems happy with 80 and 160, the default is set to 80 because that's what most sites (that I know of) currently use. The latter is used to ensure that the secret is cryptographically secure; if you don't care very much for cryptographically secure secrets you can specify `AllowInsecure` and use a non-cryptographically secure RNG provider. 

```c#
// Display shared secret
<p>Please enter the following secret in your app: @secret</p>
```

This results in: 

```cmd
Please enter the following secret in your app: XANIK3POC23RCRYN
```

Another, more user-friendly, way to get the shared secret into the app is to generate a [QR-code](https://en.wikipedia.org/wiki/QR_code) which can be scanned by the app. To generate these QR codes you can use any one of the built-in QRProvider classes: 

* [GoogleQrCodeProvider](TwoFactorAuth.Net/Providers/Qr/GoogleQrCodeProvider.cs) (Default) 
* [QrServerQrCodeProvider](TwoFactorAuth.Net/Providers/Qr/QrServerQrCodeProvider.cs)
* [QRicketQrCodeProvider](TwoFactorAuth.Net/Providers/Qr/QRicketQrCodeProvider.cs)

...or [implement your own QR Code provider](https://github.com/RobThree/TwoFactorAuth.Net/wiki/How-to-implement-your-own-QR-Code-provider). To implement your own provider all you need to do is implement the [IQrCodeProvider](TwoFactorAuth.Net/Providers/Qr/IQrCodeProvider.cs) interface. You can use the built-in providers mentioned before to serve as an example or read the next chapter in this file. The built-in classes all use a 3rd (e.g. external) party (Google, QRServer and QRicket) for the hard work of generating QR-codes (note: each of these services might at some point not be available or impose limitations to the number of codes generated per day, hour etc.). You could, however, easily use [any library](https://www.nuget.org/packages?q=qr) to generate your QR-codes without depending on external sources. See [HowTo: Implement your own QR Code provider](https://github.com/RobThree/TwoFactorAuth.Net/wiki/How-to-implement-your-own-QR-Code-provider) on how to do this. 

The built-in providers all have some provider-specific 'tweaks' you can 'apply'. Some provide support for different colors, others may let you specify the desired image-format etc. What they all have in common is that they return a QR-code as binary blob which, in turn, will be turned into a [data URI](https://en.wikipedia.org/wiki/Data_URI_scheme) by the [TwoFactorAuth](TwoFactorAuth.Net/TwoFactorAuth.cs) class. This makes it easy for you to display the image without requiring extra 'roundtrips' from browser to server and vice versa. 

```c#
// Display QR code to user
<p>Scan the following image with your app:</p>
<p><img src="@tfa.GetQrCodeImageAsDataUri("Bob Ross", secret)"></p>
```

This results in: 

```cmd
Scan the following image with your app:
```
<p align="center">
    <img src="https://raw.githubusercontent.com/RobThree/TwoFactorAuth.Net/master/TwoFactorAuth.Net.Documentation/media/qr.png">
</p>

### Step 2: Verify secret shared key

When the shared secret is added to the app, the app will be ready to start generating codes which 'expire' each `period` number of seconds. To make sure the secret was entered, or scanned, correctly you need to verify this by having the user enter a generated code. To check if the generated code is valid you call the `VerifyCode()` method: 

```c#
// Verify code
tfa.VerifyCode((string)Session["secret"], code);
```

`VerifyCode()` will return either `true` (the code was valid) or `false` (the code was invalid; no points for you!). You may need to store `secret` in a session or other persistent storage between requests. The `VerifyCode()` accepts, aside from `secret` and `code`, two more arguments. The first being `discrepancy`. Since TOTP codes are based on time("slices") it is very important that the server (but also client) have a correct date/time. But because the two may differ a bit we usually allow a certain amount of leeway. Because generated codes are valid for a specific `period` (remember the `period` argument in the TwoFactorAuth's constructor?) we usually check the `period` directly before and the period directly after the current time when validating codes. So when the current time is `14:34:21`, which results in a 'current timeslice' of `14:34:00` to `14:34:30` we also calculate / verify the codes for `14:33:30` to `14:34:00` and for `14:34:30` to `14:35:00`. This gives us a 'window' of `14:33:30` to `14:35:00`. The `discrepancy` argument specifies how many periods (or: timeslices) we check in either direction of the current time. The default `discrepancy` of 1 results in (max.) 3 period checks: -1, current and +1 period. A `discrepancy` of 4 would result in a larger window (or: bigger time difference between client and server) of -4, -3, -2, -1, current, +1, +2, +3 and +4 periods. 

The second argument `dateTime` or `timestamp` (depending on which overload you use) allows you to check a code for a specific point in time. This argument has no real practical use but can be handy for unittesting etc. Unless specified `TwoFactorAuth` uses the current time. 

### Step 3: Store secret with user

Ok, so now the code has been verified and found to be correct. Now we can store the secret with our user in our database (or elsewhere) and whenever the user begins a new session, after logging in, we ask for a code generated by the authentication app of their choice. All we need to do is call `VerifyCode()` again with the shared `secret` we stored with the user and the entered code and we'll know if the user is legit or not. 

Simple as 1-2-3!

## See also

* [How to implement your own QR Code provider](https://github.com/RobThree/TwoFactorAuth.Net/wiki/How-to-implement-your-own-QR-Code-provider)
* [How to implement your own RNG provider](https://github.com/RobThree/TwoFactorAuth.Net/wiki/How-to-implement-your-own-RNG-provider)
* [PHP version of this library](https://github.com/RobThree/TwoFactorAuth)

## Building TwoFactorAuth.Net

You'll need to have [Sandcastle Help File Builder (SHFB)](https://github.com/EWSoftware/SHFB/releases) installed if you want to build the helpfile. Other than that you only need Visual Studio 2015 (or higher).

## License

Licensed under MIT license. See [LICENSE](https://raw.githubusercontent.com/RobThree/TwoFactorAuth.Net/master/LICENSE) for details.

[Logo / icon](http://www.iconmay.com/Simple/Travel_and_Tourism_Part_2/luggage_lock_safety_baggage_keys_cylinder_lock_hotel_travel_tourism_luggage_lock_icon_465) under  CC0 1.0 Universal (CC0 1.0) Public Domain Dedication ([Archived page](http://riii.nl/tm7ap))
