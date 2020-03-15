# hammerJS
A Command line tool (CLI) that utilizes recheck-clientjs-library. You can connect and do various things on a blockchain. 

Usage: ```hammer [options] [command]```

Options:

```
  -V, --version                                         output the version number
  -i, --identity-file <file>                            specify identity file
  -p, --password <identityPass>                         specify identity password
  -u, --host-url <hostUrl>                              specify api url, default is http://localhost:3000
  -h, --help                                            output usage information
```

Commands:
```
  new [options] <identity-name>                         create a new account
  password <new-password>                               set new account password
  sign-message <message>                                sign a message
  verify-message [options] <message> <signature>        check a message signature
  recover [options] <identity-name>                     restore an account from seed phrase
  reveal [options]                                      display account details
  login [options]                                       obtain an API token
  put <file-name>                                       stores file securely and timestamps it
  get [options] <file-id>                               securely fetch and decrypt a file
  share <file-id> <recipient-id> [moreRecipientIds...]  share securely a file with multiple recipients
  verify <file-id> <file-name>                          verify the file identifier against the content file
  register-hash [options] <file-id>                     register file identifier
  check-hash [options] <file-id>                        check the file identifier and retrieve tx info
  exec [options] <selection-hash>                       execute command on a selection
```

### [Examples](Examples.md)

All of the different examples in using the tool.

```node hammer --help``` - leads you to all avaiable commands

``` node hammer <command> --help``` - this will give you information about all the different options of the command you want to use. 

The first thing the user has to do is create a new account. This is done by the command **new**. This command is going to create user's identity and put it into a file. The parameters needed for the command are two - the name of the file and the password for that identity. 

##### new
```node hammer new <filename> -e <encryption password>```
```node hammer new user -e 123```

_Example output _ - _Recovery phrase: shown use nodal twain burton chute demur hue gg bode culpa least_ and a file user.re, containing the key pairs, adress and recovery phrase. 

**THE RECOVERY PHRASE SHOULD BE KEPT SOMEWHERE SAFE, IF YOU LOSE IT NO ONE CAN RESTORE YOUR BLOCKCHAIN IDENTITY**

Now that you have your identity you can continue using the rest of the commands. 

##### reveal 

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

##### password 

Setting new password to your keys. 

```node hammer password <new password> -i yourKeysFile.re -p <password>```

##### sign-message 

Signes a text or file.

```node hammer sign-message -i user-eth-1234.re -p 1234 message```

_returns_ hash with the signature. 
_Signature: 0xdfc6f3a406f168eab0b6e0e7ec0bed942ee1b81f78d77a23738deb25390d42293e45f6243b648d140d0eba9a10419f3244b1847152858bb58c07be419c56f67e1c_


##### verify-message

It checks the message signature. This function asks for the message/file that has been signed, the signature hash and the public key of the person who signed it. The user can choose to use their file with pair keys instead. 

```node hammer verify-message LICENSE 0xdfc6f3a406f168eab0b6e0e7ec0bed942ee1b81f78d77a23738deb25390d42293e45f6243b648d140d0eba9a10419f3244b1847152858bb58c07be419c56f67e1c -i user-eth-1234.re -p 1234```

_Returns_
_Public key not defined. Will use user specified identity._
_Message is signed with public address 0xAc9d0B1242c0233ff5Cf40d84578140400f35DbA_

##### recover

Restores the account from the recovery phrase. **This is the only way to restore your lost key pairs!**

```node hammer recover <yourNewFileName> -e <yourNewPassword> -r <"your recovery phrase of 12 words">```

```node hammer recover user -e 1234 -r "shown use nodal twain burton chute demur hue gg bode culpa least"```
_returns_
_Account recovered 7c0a37cee147b31a86175780b65d10777a157d8ab2075566bba4ab277c799cc18ad9b7b157d6a23ff61805ae74d253a68e1ed42243b20404a191febe81f3ba8e_