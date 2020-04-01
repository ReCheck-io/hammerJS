[![Website recheck.io](https://img.shields.io/badge/Website-recheck.io-brightgreen.svg)](https://recheck.io/) [![npm version](https://badge.fury.io/js/recheck-hammerjs.svg)](https://badge.fury.io/js/recheck-hammerjs)

# hammerJS
A Command line tool (CLI) that utilizes recheck-clientjs-library. You can connect to the blockchain and upload, download, share and sign files. 

You can find the **npm package [here](https://www.npmjs.com/package/recheck-hammerjs)**.

You can find the **the documentation [here](docs/index.md)**

## Requirements

- npm version 8.15 or above 
- ```npm i recheck-hammerjs ```


## Getting started 


### workaround
At least for now, to connect to our public server (beta.recheck.io), you will have to click on __recheck__ dependancy 
```
const recheck = require('recheck-clientjs-library');
```
inside you will have to change the base url 
```
// let baseUrl = 'http://localhost:3000';
let baseUrl = 'https://beta.recheck.io'
```
and comment the body of the init function

```
function init(sourceBaseUrl, sourceToken, sourceNetwork = network) {
    // baseUrl = sourceBaseUrl;

    // if (!isNullAny(sourceToken)) {
    //     token = sourceToken;
    // }

    // if (!isNullAny(sourceNetwork)) {
    //     network = sourceNetwork;
    // }
}
```

This workaround is because the client is made to work with the server as a whole, but when separated, the init function is creating bugs from time to time. Just to be safe, while still the project is in development, we recommend this little tweak. 

### The first step 

After you are done with the little tweak and changed the server to beta.recheck you have to create your identity (account/wallet, containing your keys that connect you to the blockchain).

```node hammer new -i <yourChosenIdentityName> -e <yourChosenPassword>```

This command will create a file, in the current folder, containing your identity. Then you can just request for a token with the login command, or have the hash from the QR Code to login into the web GUI (right click on the QR then click inspect and you will have the content in text format). 

``` node hammer login -i daka-123.re -p 123 -c 0x3612053066ad3df8d6c2266d845c912ab89d2e717e57f92e11d346099506615a ```

For more examples look at the documentation or click [here](docs/Examples.md).
