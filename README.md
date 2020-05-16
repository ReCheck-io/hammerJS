[![Website recheck.io](https://img.shields.io/badge/Website-recheck.io-brightgreen.svg)](https://recheck.io/) [![npm version](https://badge.fury.io/js/recheck-hammerjs.svg)](https://badge.fury.io/js/recheck-hammerjs) <a href="https://discord.gg/3KwFw72"><img src="https://img.shields.io/discord/675683560673509386?logo=discord" alt="chat on Discord"></a>
# hammerJS
A Command line tool (CLI) that utilizes recheck-clientjs-library. You can connect to the blockchain and upload, download, share and sign files. 

You can find the **npm package [here](https://www.npmjs.com/package/recheck-hammerjs)**.

You can find the **the documentation [here](docs/index.md)**

## Requirements

- npm version 8.15 or above 
- ```npm i recheck-hammerjs ```


## Getting started 

### The first step 

To work on our test environment, you will have to remember to always put ```-u https://beta.recheck.io ``` as one of the parameters when you are calling commands from hammer. 

##### new blockchain identity
Create your identity (account/wallet, containing your keys that connect you to the blockchain).

```node hammer -u https://beta.recheck.io new -i <yourChosenIdentityFileName> -e <yourChosenPassword>```

This command will create a file, in the current folder, containing your identity. 

##### login into the system (requesting for a token)

Next you can login and requesting a token by executing the following command. 

``` node hammer -u https://beta.recheck.io login -i <yourChosenIdentityFileName>.re -p <yourChosenPassword> ```

If you want to enter the GUI, you can provide the parameter -c following the hash from the QR you are seeing on the first page. 
_Example_
``` node hammer -u https://beta.recheck.io login -i daka-123.re -p 123 -c 0x3612053066ad3df8d6c2266d845c912ab89d2e717e57f92e11d346099506615a ```

##### upload a file

The next two key features you can do even without using the GUI are to upload and to download a file. __Keep in mind that at this moment you can upload a file that is with a size of up to 5 MB!__ 

To upload the command is: 

```node hammer -u https://beta.recheck.io put <file> -i <yourKeysFile.re> -p <yourPassword>```

_Example_
```node hammer -u https://beta.recheck.io put LICENSE.txt -i daka-123.re -p 123```
_Returns_
_Name of the file_ and _their hash on the blockchain_
_LICENSE.txt   0x80783e8c67d06e66d45219fcff329f63dba475d5ceb930d74ccf1b1a19397274_

##### download a file 
To download the command is :
```node hammer -u https://beta.recheck.io get -s 0x...hash of the file... -i <yourKeysFile.re> -p <yourPassword>```

_Example_
command -s --save-file
  ```node hammer -u https://beta.recheck.io get -s 0x80783e8c67d06e66d45219fcff329f63dba475d5ceb930d74ccf1b1a19397274 -i user-eth-1234.re -p 1234```

  _Returns_ - downloads the file into the local folder. 

##### share, open one or several files at once and sign a file
For these commands you will need to be logged into the GUI service. To be executed, you will be provided with a hash, that has to be executed with the __exec__ command

```node hammer.js https://beta.recheck.io -i <yourKeysFile.re> -p <yourPassword> exec <action>:0x...hash...```
four actions to execute this command: 

##### open
    node hammer.js -i test-users/user1-ae-123.re -p 123 exec re:0x077dd4f4933cf86a8df127612e6426527c4804fac2c5eac57fccd4979fc241c0

_returns_
```
[ { dataId: '0xcf125467d079fb85562ced7fa1ad3456d08184492e82e13aacd8553af604aaf4',
    data: 
     { dataId: '0xcf125467d079fb85562ced7fa1ad3456d08184492e82e13aacd8553af604aaf4',
       userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' } } ]
```

##### share
node hammer.js -i test-users/user1-ae-123.re -p 123 exec sh:0x776e8cbb4db9fc290a1fb08bf7fcaf91b5913b4bae32085568f8ebd6a15086ed

_returns_

```
[ { dataId: '0xcf125467d079fb85562ced7fa1ad3456d08184492e82e13aacd8553af604aaf4',
    data: 
     { dataId: '0xcf125467d079fb85562ced7fa1ad3456d08184492e82e13aacd8553af604aaf4',
       userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
       notification: 'notoken' } } ]
```
##### sign
node hammer.js -i test-users/user1-ae-123.re -p 123 exec sg:0xf49c1f9cceb016ca2e5bbcd57f24a3b65d3c210c64c747f95fa3365e30a3f1e6

_returns_

```
[ { dataId: '0x1f4c0d873724a5017a15db3c20784da16c0585682bc42a0140f358619def6c22',
    data: 
     { dataId: '0x1f4c0d873724a5017a15db3c20784da16c0585682bc42a0140f358619def6c22',
       userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' } } ]
```

For more examples look at the documentation or click [here](docs/Examples.md).
