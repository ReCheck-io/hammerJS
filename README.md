[![Website recheck.io](https://img.shields.io/badge/Website-recheck.io-brightgreen.svg)](https://recheck.io/) [![npm version](https://badge.fury.io/js/recheck-hammerjs.svg)](https://badge.fury.io/js/recheck-hammerjs)

# hammerJS
A Command line tool (CLI) that utilizes recheck-clientjs-library. You can connect to the blockchain and upload, download, share and sign files. 

You can find the **npm package [here](https://www.npmjs.com/package/recheck-hammerjs)**.

You can find the **the documentation [here](docs/index.md)**

## Requirements

- npm version 8.15 or above 
- ```npm i recheck-hammerjs ```


## Getting started 

### The first step 

To work on our test environment, you will have to remember to always put ```-u https://beta.recheck.io login``` as one of the parameters when you are calling commands from hammer.  create your identity (account/wallet, containing your keys that connect you to the blockchain).

```node hammer -u https://beta.recheck.io new -i <yourChosenIdentityName> -e <yourChosenPassword>```

This command will create a file, in the current folder, containing your identity. Then you can just request for a token with the login command, or have the hash from the QR Code to login into the web GUI (right click on the QR then click inspect and you will have the content in text format). 

``` node hammer -u https://beta.recheck.io login -i daka-123.re -p 123 -c 0x3612053066ad3df8d6c2266d845c912ab89d2e717e57f92e11d346099506615a ```

For more examples look at the documentation or click [here](docs/Examples.md).
