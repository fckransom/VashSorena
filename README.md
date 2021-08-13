# LICENSE 


    Vash Sorena Ransomware decryption tool
    Copyright (C) 2021 FckRansom

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see https://www.gnu.org/licenses/.

# Vash Sorena Decryption tool

## Introduction

Have you been attacked with the Vash Sorena Ransomware? Have you gotten a message similar to this one on your environment?

```
++++++++++++++++++++++++++++++++ Hack For Mandatory Security ++++++++++++++++++++++++++++++++
All Your Files Has Been Locked!
If you think you can decrypt the files we would be happy :)
But all your files are protected by strong encryption with AES RSA 256 using military-grade encryption algorithm
Video Decrypt: Due to the deletion of video on video sharing sites
You can download and watch the video from the link below:
++++++++
https://drive.google.com/file/d/1QAhLOX-sQuyjk31LPPpseRlhaLKEZ_t7/view
++++++++
What does this mean ?
This means that the structure and data within your files have been irrevocably changed,
you will not be able to work with them, read them or see them,
it is the same thing as losing them forever, but with our help, you can restore them.
You Can Send some Files that not Contains Valuable Data To make Sure That Your Files Can be Back with our Tool
Your unique Id : <A RANDOM VALUE>
Contact : <AN E-MAIL ADDRESS> or <A Telegraph URL>
What are the guarantees that I can decrypt my files after paying the ransom?
Your main guarantee is the ability to decrypt test files.
This means that we can decrypt all your files after paying the ransom.
We have no reason to deceive you after receiving the ransom, since we are not barbarians and moreover it will harm our business.
You Have 2days to Decide to Pay
after 2 Days Decryption Price will Be Double
And after 1 week it will be triple Try to Contact late and You will know
Therefore, we recommend that you make payment within a few hours.
Do not rename encrypted files.
Do not try to decrypt your data using third party software, it may cause permanent data loss.
Again, we emphasize that no one can decrypt files, so don't be a victim of fraud.
It's just a business
Warning : If you email us late You may miss the Decrypt program Because our emails are blocked quickly So it is better as soon as they read email Email us ;)
You can buy bitcoins from the following sites
https://crypto.com
https://www.binance.com
https://www.coinbase.com/
https://localbitcoins.com/buy_bitcoins
https://www.coindesk.com/information/how-can-i-buy-bitcoins
++++++++++++++++++++++++++++++++ Hack For Mandatory Security ++++++++++++++++++++++++++++++++
```

In addition you have files that looks similar to ```<Original filename>.Email=[<AN E-MAIL ADDRESS>]ID=[<A RANDOM VALUE>].encrypt``` 
(the extension may be various, encrypted, Encrypted, covid are some examples).

Then you have most likley been victim of a Vash Sorena ransomware attack, but don't worry. This repository contains both code and applications that easily decrypts all files for you.

## SO, what is this?

Well as said; this is a small application that enables you to decrypt files that has been encrypted with Vash Sorena ransomware. It is a very simple application that doesn't do much else. 
It doesn't restore the computer anymore than just decrypting files.

In the GNU General Public License spirit it is free to use and the source code is open source free to use as long as both is done under the acknowledgement of the GNU General Public License.

### WHY ARE YOU DOING THIS FOR FREE?

Well, **NOONE** shall benefit from ransom in any situation. PERIOD. Attackers should not be paid and so-called "security" companies should not take lots of money to aid you in such simple task as 
decrypting the Vash Sorena ransomware. 

That's the reason. No more, no less.

Of course, if you want to donate either to show gratitude of getting help or to aid creating decryption tools for other ransomware attacks you are welcome to do this. Look at the Donations section below.

## How to use

### Getting the tool

The easiest way to use is to download the zipped version from [Releases](https://github.com/fckransom/VashSorena/releases/) that matches your operating system environment and use that. 

The following operating systems are supported:
* Windows x64
* Linux x64
* MacOS x64

If you want to use the tool on other operating systems or have problems using it, try to build it yourself or contact us for help.

### Decryption mode

Decryption mode decrypts all files from the source and places the decrypted files in the same folder structure as the source. Decryption mode is the default mode for the application. 

*It is recommended to run the application as administrator to gain access to files that isn't accessible as a normal user.*

The command line for decryption mode is:

	VashSorena --Source <The folder with encrypted files> --Destination <Destination folder where decrypted files is placed> [--DecryptConcurrency <concurrent decryptions>]

#### Arguments
- --Source (-s)
  - The source where the encrypted files exists
- --Destination (-d)
  - The destination for the decrypted files
  - **NOTE** The source and destination cannot be the same to avoid tampering with the attacked surface
  - **NOTE** Existings files will be overridden!
- --DecryptionConcurrency (-dc)
  - The number of files that will be decrypted at the same time
  - Default: 10
  - Please note that more concurrency will decrease the speed but increase the load, less concurrency will decrease the speed but generate less concurrent load.

### Detection mode

While the application contains the decryption configuration for a various of known versions of the application (see below) it can probably decrypt other versions as well. This can be detected by 
running the application in detection mode.

The dection mode requires you to provide a filename of an encrypted file that you can open the decrypted version of to verify if the decryption succeeded. The application will guide you through this process. 
When you have confirmed that the source file is decrypted. The configuration will be stored in the ```decryptionsettings.json``` file and you can run the decryption mode to decrypt your files.

The command line for detection mode is:

    VashSorena --Operation Detect --Source <The file to run detection on> --Destination <The destination folder of the decrypted file>

#### Arguments
- --Operation (-d) Detect
  - Enables the detection mode
- --Source (-s)
  - The filename of an encrypted file (it is a requirement to use the filename as is from the attacker)
- --Destination (-d)
  - The destination for the decrypted file
  - **NOTE** Existings file will be overridden each run!

## Currently detected versions

Versions of Vash Sorena is detected by the attackers e-mail. Which one that is currently detected is:
* decrypt8070<span>@</span>gmail.com
* decrypt8090<span>@</span>gmail.com
* decryptiontool01<span>@</span>gmail.com
* russiawolf09<span>@</span>gmail.com
* warning7077<span>@</span>gmail.com

If your attacker isn't one of these, use the detection operation to identify the configuration for your attacker. When you have found one, please post an issue 
or by sending us an e-mail (see below for both) with the content of ```decryptionsetting.json``` and we will update the detection tool with the latest information for others to use.

## Issues

If you find any issues with the application, please feel free to report them in issue. But, before you report an issue please check that noone else has reported it before to avoid duplicates. 

Do **NOT** post links to files in the issue, if you have files that can help with the issue, write that in the issue and we can discuss how to deliver those to us.

## I can't decrypt my files!

Well, we think that it's better to contact us by e-mail, then we can set up direct contact where we can aid you with the issue. The e-mail is [fckransom@outlook.com](mailto:fckransom@outlook.com).

## I have been attacked with ransomware, but it isn't Vash Sorena. Can you help me?

Please send an e-mail to [fckransom@outlook.com](mailto:fckransom@outlook.com) and we see what we can do!

# DONATIONS

It is important (and we can't stress this enough), that this application is licensed under GNU General Public License. So it does NOT cost anything and never shall.

But, if you feel that you want to give something back, we'll do that the same way as the attackers want to be paid. By crypto currency. 

By donating you can help improving this decryption tool and create decryption tools for other ransomwares as well.

[![Donate](https://pngimg.com/uploads/donate/donate_PNG35.png)](https://commerce.coinbase.com/checkout/f3c33747-4c25-4c09-b9f4-f98b53f3bdc7)

