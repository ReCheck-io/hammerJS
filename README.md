[![Website recheck.io](https://img.shields.io/badge/Website-recheck.io-brightgreen.svg)](https://recheck.io/) [![npm version](https://badge.fury.io/js/recheck-hammerjs.svg)](https://badge.fury.io/js/recheck-hammerjs) 
# hammerJS
A Command line tool (CLI) that utilizes recheck-clientjs-library. You can connect to the blockchain and upload, download, share and sign files. 

You can find the **npm package [here](https://www.npmjs.com/package/recheck-hammerjs)**.

You can find the **the documentation [here](docs/index.md)**

## Requirements

- npm version 8.15 or above 
- ```git clone https://github.com/ReCheck-io/hammerJS.git```
- ```cd hammerJS```
- ```npm install ```


## Getting started 
This is a CLI(command line tool) program, so you have to type all the commands in the terminal (UNIX) or via cmd/cygwin/bash terminal in Windows.  

### The first step 

To work on our test environment, you will have to remember to always put ```-u https://beta.recheck.io ``` as one of the parameters when you are calling commands from hammer. 

##### new blockchain identity
Create your identity (account/wallet, containing your keys that connect you to the blockchain).

```node hammer new <yourChosenIdentityFileName> -e <yourChosenPassword>```

This command will create a file, in the current folder, containing your identity. 

##### login into the system (requesting for a token)

Next you can login and requesting a token by executing the following command. 

``` node hammer -u https://beta.recheck.io -i <yourChosenIdentityFileName>.re -p <yourChosenPassword> login ```

If you want to enter the GUI, you can provide the parameter -c following the hash from the QR you are seeing on the first page. 
_Example_
``` node hammer -u https://beta.recheck.io -i daka-123.re -p 123 login -c 0x3612053066ad3df8d6c2266d845c912ab89d2e717e57f92e11d346099506615a ```

##### upload a file

The next two key features you can do even without using the GUI are to upload and to download a file. __Keep in mind that at this moment you can upload a file that is with a size of up to 5 MB!__ 

To upload the command is: 

```node hammer -u https://beta.recheck.io -i <yourKeysFile.re> -p <yourPassword> put <file> ```

_Example_
```node hammer -u https://beta.recheck.io -i daka-123.re -p 123 put LICENSE.txt ```
_Returns_
_Name of the file_ and _their hash on the blockchain_
_LICENSE.txt   0x80783e8c67d06e66d45219fcff329f63dba475d5ceb930d74ccf1b1a19397274_

##### download a file 
To download the command is :
```node hammer -u https://beta.recheck.io -i <yourKeysFile.re> -p <yourPassword> get -s 0x...hash of the file...```

_Example_
command -s --save-file
  ```node hammer -u https://beta.recheck.io -i user-eth-1234.re -p 1234 get -s 0x80783e8c67d06e66d45219fcff329f63dba475d5ceb930d74ccf1b1a19397274 ```

  _Returns_ - downloads the file into the local folder. 

##### share

To share a file you will need to provide the file's blockchain ID, and the user id of the user(s) you want to share it with. 

```node hammer.js -u https://beta.recheck.io -i <yourKeysFile.re> -p <yourPassword> share 0x..file'sId.. re_..user'sID```

_Example_

```
node hammer.js -u https://beta.recheck.io -i test-users/user1-ae-123.re -p 123 share 0x41d58ed8cce4933acb55cf00c1ba5a4bb2b7047a96678ef168662cb379c55498 re_2LLq3V4iWKipTEZfhAEEckv2H3nLfrn8WwhKkAt1UkFkt69AVh
```
_returns_
```
0x41d58ed8cce4933acb55cf00c1ba5a4bb2b7047a96678ef168662cb379c55498 -> re_2LLq3V4iWKipTEZfhAEEckv2H3nLfrn8WwhKkAt1UkFkt69AVh OK
```

##### sign 

The signature is a transaction that represents user's valiidation of the selected file.

```node hammer.js -u https://beta.recheck.io -i <yourKeysFile.re> -p <yourPassword> sign 0x..file'sId..```

_Example_
```
node hammer.js -u https://beta.recheck.io -i test-users/user1-ae-123.re -p 123 sign 0x41d58ed8cce4933acb55cf00c1ba5a4bb2b7047a96678ef168662cb379c55498 
```

_returns_
```
{ dataId: '0x41d58ed8cce4933acb55cf00c1ba5a4bb2b7047a96678ef168662cb379c55498',
  userId: 're_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' }
```

##### share, open one or several files at once and sign a file with exec command
For these commands you will need to be logged into the GUI service. To execute one of these actions, you will need generate a hash by pushing one of the GUI buttons - share/open/sign. Afterwards this hash has to be executed with the __exec__ command in hammer.

```node hammer.js -u https://beta.recheck.io -i <yourKeysFile.re> -p <yourPassword> exec <action>:0x...hash...```
four actions to execute this command: 

##### open - re:  

This command will re encrypt and reconstruct the contents of the file to the current user. It is being used to reencrypt on the browser and show decrypted contents in the GUI.

```node hammer.js -u https://beta.recheck.io -i test-users/user1-ae-123.re -p 123 exec re:0x077dd4f4933cf86a8df127612e6426527c4804fac2c5eac57fccd4979fc241c0```

_returns_
```
[ { dataId: '0xcf125467d079fb85562ced7fa1ad3456d08184492e82e13aacd8553af604aaf4',
    data: 
     { dataId: '0xcf125467d079fb85562ced7fa1ad3456d08184492e82e13aacd8553af604aaf4',
       userId: 're_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' } } ]
```
##### open - op:

This command will return the contents of the file as bytes to be reconstructed on in however way the user decides afterwards. 


```node hammer.js -u https://beta.recheck.io -i test-users/user1-ae-123.re -p 123 exec op:0x74c53970ea29015e9e5e27ab2db74e80882cb547a5ea499427db9fa21ee74716```

```
[ 
  { dataId: '0x9a3d7242d4b66d1a2533e1c17524a0dd1a3607d235b4500406efaa9150175f8d',
    data: 
     { dataId: '0x9a3d7242d4b66d1a2533e1c17524a0dd1a3607d235b4500406efaa9150175f8d',
       ownerId: 're_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
       dataOriginalHash: '0x0f68807a5a86704ecdd6a2f84a8e0425b877b7688e7f2448685f306053ffa22d',
       dataName: 'Screenshot 2020-05-13 at 10.00.21',
       dataExtension: '.png',
       dateCreated: '2020-05-15T08:43:05.000Z',
       dateUpdated: '2020-05-15T08:43:05.000Z',
       category: 'PERSONAL',
       keywords: 'test',
       userId: 're_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
       payload: 'iVBORw0KGgoAAAANSUhEUgAAB4AAAAQ4CAYAAADo08FDAAAKw2lDQ1BJQ0MgUHJvZmlsZQAASImVlwdUU+kSgP970xstAQEpoYYivYOU0EPvzUZIAgklxoQgYlfEFVwLKiKgruiiiIKrUsSGWLAtCkqxbpBFRV0XC6Ci8i7w...,}
  }
]
```

##### share

Before using this command in the GUI you have to select the person and the file you want to share. It will then generate the QR code to execute it like in the following example. 

```node hammer.js -u https://beta.recheck.io -i test-users/user1-ae-123.re -p 123 exec sh:0x776e8cbb4db9fc290a1fb08bf7fcaf91b5913b4bae32085568f8ebd6a15086ed```

_returns_

```
[ { dataId: '0xcf125467d079fb85562ced7fa1ad3456d08184492e82e13aacd8553af604aaf4',
    data: 
     { dataId: '0xcf125467d079fb85562ced7fa1ad3456d08184492e82e13aacd8553af604aaf4',
       userId: 're_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
       notification: 'notoken' } } ]
```
##### sign

In the GUI you will have to select the file and click the Sign button to generate the hash. 

```node hammer.js -u https://beta.recheck.io -i test-users/user1-ae-123.re -p 123 exec sg:0xf49c1f9cceb016ca2e5bbcd57f24a3b65d3c210c64c747f95fa3365e30a3f1e6```

_returns_

```
[ { dataId: '0x1f4c0d873724a5017a15db3c20784da16c0585682bc42a0140f358619def6c22',
    data: 
     { dataId: '0x1f4c0d873724a5017a15db3c20784da16c0585682bc42a0140f358619def6c22',
       userId: 're_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' } } ]
```

For more examples look at the documentation or click [here](docs/Examples.md).
