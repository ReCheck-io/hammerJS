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
