# Examples 
To start with the tool you need to first have an account. 


```node hammer --help``` - leads you to all avaiable commands

``` node hammer <command> --help``` - this will give you information about all the different options of the command you want to use. 

The first thing the user has to do is create a new account. This is done by the command **new**. This command is going to create user's identity and put it into a file. The parameters needed for the command are two - the name of the file and the password for that identity. 

#### new
```node hammer new <filename> -e <encryption password>```
```node hammer new user -e 123```

_Example output _ - _Recovery phrase: shown use nodal twain burton chute demur hue gg bode culpa least_ and a file user.re, containing the key pairs, adress and recovery phrase. 

**THE RECOVERY PHRASE SHOULD BE KEPT SOMEWHERE SAFE, IF YOU LOSE IT NO ONE CAN RESTORE YOUR BLOCKCHAIN IDENTITY**

Now that you have your identity you can continue using the rest of the commands. 

#### reveal 

First thing you should do, if you already have not, is to **write down your recovery phrase on a paper or somewhere else where it will be safe from outsiders**.

```node hammer reveal -i <yourKeysFile.re> -p <yourPassword>```
_returns_
- public address - this is also your blockchain ID
- public signing key 
- public encryption key 

```node hammer reveal -i <yourKeysFile.re> -p <yourPassword> -k```
_returns_
- public address
- public signing key
- private signing key  
- public encryption key
- private encryption key  

```node hammer reveal -i <yourKeysFile.re> -p <yourPassword> -r```
_returns_
- public address
- public signing key
- public encryption key
- Recovery phrase: <12 words> - **keep them somewhere safe**

If you put both -r and -k options, you will receive the whole info about your key pairs. 

#### password 

Setting new password to your keys. 

```node hammer password <new password> -i yourKeysFile.re -p <password>```

#### sign-message 

Signes a text or file.

```node hammer sign-message -i user-eth-1234.re -p 1234 message```

_returns_ hash with the signature. 
_Signature: 0xdfc6f3a406f168eab0b6e0e7ec0bed942ee1b81f78d77a23738deb25390d42293e45f6243b648d140d0eba9a10419f3244b1847152858bb58c07be419c56f67e1c_


#### verify-message

It checks the message signature. This function asks for the message/file that has been signed, the signature hash and the public key of the person who signed it. The user can choose to use their file with pair keys instead. 

```node hammer verify-message LICENSE 0xdfc6f3a406f168eab0b6e0e7ec0bed942ee1b81f78d77a23738deb25390d42293e45f6243b648d140d0eba9a10419f3244b1847152858bb58c07be419c56f67e1c -i user-eth-1234.re -p 1234```

_Returns_
_Public key not defined. Will use user specified identity._
_Message is signed with public address 0xAc9d0B1242c0233ff5Cf40d84578140400f35DbA_

#### recover

Restores the account from the recovery phrase. **This is the only way to restore your lost key pairs!**

```node hammer recover <yourNewFileName> -e <yourNewPassword> -r <"your recovery phrase of 12 words">```

```node hammer recover user -e 1234 -r "shown use nodal twain burton chute demur hue gg bode culpa least"```
_returns_
_Account recovered 7c0a37cee147b31a86175780b65d10777a157d8ab2075566bba4ab277c799cc18ad9b7b157d6a23ff61805ae74d253a68e1ed42243b20404a191febe81f3ba8e_

#### login / get Token 
This command allows you to log into the blockchain and more importantly to receive a **token** that you are going to use for communication with the server. 

```node hammer login -i <yourKeysFile.re> -p <yourPassword>```

```node hammer login -i user-eth-1234.re -p 1234```

_Returns_
Example - _f47533d6-b7b1-4b00-b136-ed501897456b_ - the token needed for communication with the server.


#### put - upload a file on the blockchain

This command uploads the document on the blockchain. Keep in mind which blockchain network you are using. At the moment our service supports _Ethereum_ and _AEternity_. It is easy to distinguish them with _node hammer reveal_, as the aethernity adress and public sign key starts with ak_..., whereas the eth address starts with 0x...

```node hammer put <file> -i <yourKeysFile.re> -p <yourPassword>```

_Example_
```node hammer put LICENSE -i user-eth-1234.re -p 1234```
_Returns_
_Name of the file_ and _their hash on the blockchain_
_LICENSE   0x80783e8c67d06e66d45219fcff329f63dba475d5ceb930d74ccf1b1a19397274_

#### get - download a file from the blockchain

The get command gives a lot of options, because you may want different things from file that is already on the chain. 
```
Options:
  -s, --save-file               store result in local file
  -o, --output-file <file>      specify output file
  -r, --request-tx-receipt      get tx receipt
  -t, --tx-receipt-file <file>  specify tx receipt file
  -n, --disable-print           no print in stdio, used with --request-tx-receipt
  -h, --help                    output usage information
```
_Examples_
- command -s --save-file
  ```node hammer get -s 0x80783e8c67d06e66d45219fcff329f63dba475d5ceb930d74ccf1b1a19397274 -i user-eth-1234.re -p 1234```

  _Returns_ - downloads the file into the local folder. 
- command -o --output-file < file > 
  Downloads the file which is on the blockchain as bytes that will be put in a specified file by the user.
   
  ```node hammer get -o "example.txt" 0x80783e8c67d06e66d45219fcff329f63dba475d5ceb930d74ccf1b1a19397274 -i user-eth-1234.re -p 1234```

  _Returns_ - downloads the bytes of the file into specified file by the user, in this case - example.txt is the file being outputted. 

- r --request-tx-receipt
  Outputs the transaction receipt. 

  ```node hammer get -r 0x80783e8c67d06e66d45219fcff329f63dba475d5ceb930d74ccf1b1a19397274 -i user-eth-1234.re -p 1234```

  _Returns_ - a file with the tx and the tx in the console
  _TUlUIExpY2Vuc2UKCkNvcHlyaWdodCAoYykgMjAyMCBSZUNoZWNrCgpQZXJtaXNzaW9uIGlzIGhlcmVieSBncmFudGVkLCBmcmVlIG9mIGNoYXJnZSwgdG8gYW55IHBlcnNvbiBvYnRhaW5pbmcgYSBjb3B5Cm9mIHRoaXMgc29mdHdhcmUgYW5kIGFzc29jaWF0ZWQgZG9jdW1lbnRhdGlvbiBmaWxlcyAodGhlICJTb2Z0d2FyZSIpLCB0byBkZWFsCmluIHRoZSBTb2Z0d2FyZSB3aXRob3V0IHJlc3RyaWN0aW9uLCBpbmNsdWRpbmcgd2l0aG91dCBsaW1pdGF0aW9uIHRoZSByaWdodHMKdG8gdXNlLCBjb3B5LCBtb2RpZnksIG1lcmdlLCBwdWJsaXNoLCBkaXN0cmlidXRlLCBzdWJsaWNlbnNlLCBhbmQvb3Igc2VsbApjb3BpZXMgb2YgdGhlIFNvZnR3YXJlLCBhbmQgdG8gcGVybWl0IHBlcnNvbnMgdG8gd2hvbSB0aGUgU29mdHdhcmUgaXMKZnVybmlzaGVkIHRvIGRvIHNvLCBzdWJqZWN0IHRvIHRoZSBmb2xsb3dpbmcgY29uZGl0aW9uczoKClRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIHNoYWxsIGJlIGluY2x1ZGVkIGluIGFsbApjb3BpZXMgb3Igc3Vic3RhbnRpYWwgcG9ydGlvbnMgb2YgdGhlIFNvZnR3YXJlLgoKVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEICJBUyBJUyIsIFdJVEhPVVQgV0FSUkFOVFkgT0YgQU5ZIEtJTkQsIEVYUFJFU1MgT1IKSU1QTElFRCwgSU5DTFVESU5HIEJVVCBOT1QgTElNSVRFRCBUTyBUSEUgV0FSUkFOVElFUyBPRiBNRVJDSEFOVEFCSUxJVFksCkZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFIEFORCBOT05JTkZSSU5HRU1FTlQuIElOIE5PIEVWRU5UIFNIQUxMIFRIRQpBVVRIT1JTIE9SIENPUFlSSUdIVCBIT0xERVJTIEJFIExJQUJMRSBGT1IgQU5ZIENMQUlNLCBEQU1BR0VTIE9SIE9USEVSCkxJQUJJTElUWSwgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIFRPUlQgT1IgT1RIRVJXSVNFLCBBUklTSU5HIEZST00sCk9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFNPRlRXQVJFIE9SIFRIRSBVU0UgT1IgT1RIRVIgREVBTElOR1MgSU4gVEhFClNPRlRXQVJFLgo=_

- t --tx-receipt-file < file >
  Outputs the transaction receipt in the console and saves it in the user specified file. 

  ```node hammer get -t tx.txt 0x80783e8c67d06e66d45219fcff329f63dba475d5ceb930d74ccf1b1a19397274 -i user-eth-1234.re -p 1234```
 
  _Returns_ - the transaction receipt in tx.txt 

- n --disable-print 
  
  With this command you will not get the tx-receipt in the console, only in the file.

  ```node hammer get -t tx.txt 0x80783e8c67d06e66d45219fcff329f63dba475d5ceb930d74ccf1b1a19397274 -i user-eth-1234.re -p 1234 -n```

#### share
Shares a file with other users in the system. Can share to as many as the user wants

```node hammer share <fileChainID> <recipientUserChainID> <anotherRecipientUserChainID> -i user-eth-1234.re -p 1234```

#### verify 

#### register-hash

#### check-hash

#### exec 