#!/usr/bin/env node

const recheck = require('./recheck-client');

const program = require('commander');
const fs = require('fs');
const path = require('path');
const aes256 = require('aes256');
const btoa = require('btoa');
const atob = require('atob');

let hammerNetwork = "ae";
let hammerBaseUrl = "http://localhost:3000";
// let hammerBaseUrl = "https://docs.recheck.io";

recheck.debug(false);

recheck.init(hammerBaseUrl, null, hammerNetwork);


function isNullAny(...args) {
    for (let i = 0; i < args.length; i++) {
        let current = args[i];

        if (current == null //element == null covers element === undefined
            || (current.hasOwnProperty('length') && current.length === 0) // has length and it's zero
            || (current.constructor === Object && Object.keys(current).length === 0) // is an Object and has no keys
            || current.toString().toLowerCase() === 'null'
            || current.toString().toLowerCase() === 'undefined') {

            return true;
        }
    }
    return false;
}

function addReExtension(fileName) {
    return fileName.endsWith(".re") ? fileName : `${fileName}.re`;
}

async function readBinaryFile(fileName) {
    try {
        let binary = fs.readFileSync(fileName, "binary").toString("binary");
        return {name: path.basename(fileName), binary: binary}
    } catch (error) {
        console.error("Unable to read input file.");
        console.error(error);
        process.exit(1);
    }
}

function writeBinaryFile(fileName, data) {
    try {
        return fs.writeFileSync(fileName, data, "binary");
    } catch (error) {
        console.error("Unable to write file.");
        process.exit(1);
    }
}

function processHostUrl(hostUrl) {
    if (hostUrl) {
        if (!hostUrl.startsWith("http://") && !hostUrl.startsWith("https://")) {
            hostUrl = `http://${hostUrl}`;
        }
        recheck.init(hostUrl, undefined, hammerNetwork);
    }
}

async function requireAccountOption(fileName, password, login) {
    if (!fileName) {
        console.error("Account name not specified.");
        process.exit(1);
    }

    if (!password) {
        console.error("Account password not specified.");
        process.exit(1);
    }
    let loginAccount;
    try {
        fileName = addReExtension(fileName);
        let accountEncrypted = await readBinaryFile(fileName);
        let accountDecrypted = aes256.decrypt(password, accountEncrypted.binary);
        let account = JSON.parse(accountDecrypted);
        if (!account) process.exit(1);
        if (!account.publicKey || !account.secretKey) {
            console.error("Specified file does not provide public and secret keys.");
            process.exit(1);
        }
        loginAccount = account;
    } catch (error) {
        console.error("Unable to read account file. Did you supply the correct password?");
        process.exit(1);
    }
    try {
        if (login)
            await recheck.login(loginAccount);
        return loginAccount;
    } catch (loginError) {
        console.log(loginError)
        console.error("Unable to login with provided identity.");
        process.exit(1);
    }

}

function requireFileName(fileName) {
    if (!fileName) {
        console.error("File name is required.");
        process.exit(1);
    }
}

function manageReceipt(cmdObj, saveName, openResult) {
    if (cmdObj.requestTxReceipt) {
        let receiptName = `${saveName}.receipt`;
        if (cmdObj.txReceiptFile) {
            receiptName = cmdObj.txReceiptFile;
            if (receiptName === saveName)
                receiptName = `${receiptName}.receipt`;
        }
        writeBinaryFile(receiptName, openResult.receipt);
    }
}

program.version('0.1.0');

program
    .option('-i, --identity-file <file>', 'specify identity file')
    .option('-p, --password <identityPass>', 'specify identity password')
    .option('-u, --host-url <hostUrl>', 'specify api url, default is http://localhost:3000');

program
    .command('new <identity-name>')
    .description('create a new account')
    .option('-e, --encrypt-pass <encryptionPass>', 'specify encryption password')
    .action(async function (identityName, cmdObj) {
        try {
            if (!cmdObj.encryptPass) {
                console.error("Encryption password is required. Please specify with -e option");
                process.exit(1);
            }
            let newAccount = await recheck.newKeyPair(null);
            identityName = addReExtension(identityName);

            if (fs.existsSync(identityName)) {
                console.error("Account file with that name already exists.");
                process.exit(1);
            }
            let accountStr = JSON.stringify(newAccount);
            let encryptedAccount = aes256.encrypt(cmdObj.encryptPass, accountStr);
            let bytesWritten = writeBinaryFile(identityName, encryptedAccount);
            if (bytesWritten < 1) {
                throw new Error("Unable to write account data.");
            } else {
                console.log("Recovery phrase:", newAccount.phrase);
            }
        } catch (error) {
            console.error(error);
        }
    });

program
    .command('password <new-password>')
    .description('set new account password')
    .action(async function (newPassword) {
        try {
            if (!newPassword) {
                console.error("Password is required.");
                process.exit(1);
            }
            let account = await requireAccountOption(program.identityFile, program.password, false);
            let accountStr = JSON.stringify(account);
            let encryptedAccount = aes256.encrypt(newPassword, accountStr);
            let accountFile = addReExtension(program.identityFile);
            let bytesWritten = writeBinaryFile(accountFile, encryptedAccount);
            if (bytesWritten < 1) {
                throw new Error("Unable to write account data.");
            } else {
                console.log("Account password changed successfully.");
            }
        } catch (error) {
            console.error(error);
        }
    });

program
    .command('sign-message <message>')
    .description('sign a message')
    .action(async function (message) {
        try {
            if (!message) {
                console.error("Message is required.");
                process.exit(1);
            }
            let account = await requireAccountOption(program.identityFile, program.password, false);
            let signature = recheck.signMessage(message, account.secretKey);
            console.log("Signature:", signature);
        } catch (error) {
            console.error(error);
        }
    });

program
    .command('verify-message <message> <signature>')
    .description('check a message signature')
    .option('-k, --public-key <publicKey>', 'specify public key')
    .action(async function (message, signature, cmdObj) {
        try {
            if (!message) {
                console.error("Message is required.");
                process.exit(1);
            }
            if (!signature) {
                console.error("Signature is required.");
                process.exit(1);
            }
            let publicKey = cmdObj.publicKey;
            if (!publicKey) {
                console.log("Public key not defined. Will use user specified identity.");
                let account = await requireAccountOption(program.identityFile, program.password, false);
                if (hammerNetwork === "eth") {
                    publicKey = account.address;
                } else {
                    publicKey = account.publicKey;
                }
            }
            let pubKey = recheck.verifyMessage(message, signature, publicKey);
            if (pubKey === publicKey) {
                console.log("Message is signed with public address", pubKey);
            } else {
                console.log("Provided signature does not match the public key for the provided message.");
            }
        } catch (error) {
            console.error(error);
        }
    });


program
    .command('recover <identity-name>')
    .description('restore an account from seed phrase')
    .option('-e, --encrypt-pass <password>', 'specify encryption password')
    .option('-r, --recovery-phrase <phrase>', 'specify recovery phrase')
    .action(async function (identityName, cmdObj) {
        try {
            if (!cmdObj.encryptPass) {
                console.error("Password is required.");
                process.exit(1);
            }
            if (!cmdObj.recoveryPhrase) {
                console.error("Recovery phrase is required.");
                process.exit(1);
            }
            let newAccount = await recheck.newKeyPair(cmdObj.recoveryPhrase);

            identityName = addReExtension(identityName);

            if (fs.existsSync(identityName)) {
                console.error("Account file with that name already exists.");
                process.exit(1);
            }
            let accountStr = JSON.stringify(newAccount);
            let encryptedAccount = aes256.encrypt(cmdObj.encryptPass, accountStr);
            let bytesWritten = writeBinaryFile(identityName, encryptedAccount);
            if (bytesWritten < 1) {
                throw new Error("Unable to write account data.");
            } else {
                console.log("Account recovered", newAccount.publicKey);
            }
        } catch (error) {
            console.error(error);
        }
    });

program
    .command('reveal')
    .description('display account details')
    .option('-k, --private', 'display private keys')
    .option('-r, --recovery-phrase', 'display private keys')
    .action(async function (cmdObj) {
        try {
            let account = await requireAccountOption(program.identityFile, program.password, false);
            if (account.address) {
                console.log("Public address:", account.address);
            }
            console.log("Public signing key:", account.publicKey);
            if (cmdObj.private)
                console.log("Private signing key:", account.secretKey);
            console.log("Public encryption key:", account.publicEncKey);
            if (cmdObj.private)
                console.log("Private encryption key:", account.secretEncKey);
            if (cmdObj.recoveryPhrase)
                console.log("Recovery phrase:", account.phrase);
        } catch (error) {
            console.error(error);
        }
    });

program
    .command('login')
    .description('obtain an API token')
    .option('-c, --challenge <challenge>', 'specify login challenge')
    .action(async function (cmdObj) {
        processHostUrl(program.hostUrl);
        let account = await requireAccountOption(program.identityFile, program.password, false);
        try {
            let token;
            if (cmdObj.challenge) {
                token = await recheck.loginWithChallenge(cmdObj.challenge, account);
            } else {
                token = await recheck.login(account);
            }
            console.log(token);
        } catch (error) {
            console.error("Login failed.", error);
        }
    });

program
    .command('put <file-name>',)
    .description('stores file securely and timestamps it')
    .action(async function (fileName) {
        try {
            processHostUrl(program.hostUrl);
            let account = await requireAccountOption(program.identityFile, program.password, true);
            requireFileName(fileName);

            let file = await readBinaryFile(fileName);
            let fileA = btoa(file.binary);

            let nameExtensionObj = getFileNameAndExtension(file.name);

            let uploadResult = await recheck.store({
                dataName: nameExtensionObj.dataName,
                dataExtension: nameExtensionObj.dataExtension,
                payload: fileA
            }, account.address, account.publicEncKey);

            if (isNullAny(uploadResult)) {
                console.error("Error: status", uploadResult.status,
                    "code", uploadResult.code, "message", uploadResult.message);
            } else {
                if (uploadResult.dataId) {
                    console.log(`${file.name}   ${uploadResult.dataId}`);
                } else {
                    // TODO - return the file id at the check case
                    console.log(uploadResult);
                }
            }
        } catch (error) {
            console.error("Error: failed to upload file. Details:", error);
        }

        function getFileNameAndExtension(fileName) {
            let extension = '.unknown';
            let extensionDotIndex = fileName.lastIndexOf('.');

            if (extensionDotIndex > 0) {
                extension = fileName.substring(extensionDotIndex);
                fileName = fileName.substring(0, extensionDotIndex);
            }

            return {
                dataName: fileName,
                dataExtension: extension
            };
        }
    });

program
    .command('get <file-id>')
    .description('securely fetch and decrypt a file')
    .option('-s, --save-file', 'store result in local file')
    .option('-o, --output-file <file>', 'specify output file')
    .option('-r, --request-tx-receipt', 'get tx receipt')
    .option('-t, --tx-receipt-file <file>', 'specify tx receipt file')
    .option('-n, --disable-print', 'no print in stdio, used with --request-tx-receipt')
    .action(async function (fileId, cmdObj) {
        try {
            processHostUrl(program.hostUrl);
            let account = await requireAccountOption(program.identityFile, program.password, true);

            let openResult = await recheck.open(fileId, account.publicKey, account);

            if (isNullAny(openResult)) {
                console.error("Unable to decrypt or verify file");
            } else {
                if (openResult.dataId) {
                    let saveName = openResult.dataName + openResult.dataExtension;
                    if (cmdObj.outputFile) saveName = cmdObj.outputFile;
                    try {
                        manageReceipt(cmdObj, saveName, openResult);
                    } catch (rError) {
                        console.error("Unable to write receipt. Proceeding with file writing..");
                    }
                    if (cmdObj.saveFile || cmdObj.outputFile) {
                        writeBinaryFile(saveName, atob(openResult.payload));
                    } else if (!cmdObj.disablePrint) {
                        console.log(openResult.payload);
                    }
                } else {
                    console.error("The requested file could not be retrieved.");
                }
            }
        } catch (error) {
            console.error("Error: failed to retrieve file. Details:", error);
        }
    });

program
    .command('share <file-id> <recipient-id> [moreRecipientIds...]')
    .description('share securely a file with multiple recipients')
    .action(async function (fileId, recipientId, moreRecipientIds) {
        processHostUrl(program.hostUrl);
        let account = await requireAccountOption(program.identityFile, program.password, true);
        moreRecipientIds.push(recipientId);
        if (moreRecipientIds.length > 0) {
            for (let i = 0; i < moreRecipientIds.length; i++) {
                try {
                    let nextShareResult = await recheck.share(fileId, moreRecipientIds[i], account);
                    if (nextShareResult.status !== "ERROR") {
                        console.log(fileId, "->", moreRecipientIds[i], "OK");
                    } else {
                        console.error(fileId, "->", moreRecipientIds[i], nextShareResult.status, nextShareResult.code);
                    }
                } catch (shareError) {
                    console.error(fileId, "->", moreRecipientIds[i], "ERROR", shareError);
                }
            }
        }
    });

program
    .command('verify <file-id> <file-name>')
    .description('verify the file identifier against the content file')
    .action(async function (fileId, fileName) {
        try {
            let account = await requireAccountOption(program.identityFile, program.password, true);
            let data = await readBinaryFile(fileName);
            let validateResult = await recheck.validate(data.binary, account.publicKey, fileId);

            if (validateResult.status !== "OK"
                && validateResult.dataId === fileId
                && validateResult.userId === account.publicKey) {
                console.log("OK");
            } else {
                console.log("NOK");
            }
        } catch (error) {
            console.error("File verification failed. Error details", error);
        }
    });

program
    .command('register-hash <file-id>')
    .description('register file identifier')
    .option('-l, --poll', 'poll for tx receipt')
    .action(async function (fileId, cmdObj) {
        processHostUrl(program.hostUrl);

        try {
            let poll = !!cmdObj.poll;
            let account = await requireAccountOption(program.identityFile, program.password, true);
            //TODO fix ipo_filing
            let result = await recheck.registerHash(fileId, 'ipo_filing', account.address, account, poll);
            console.log(result);
        } catch (error) {
            console.error("File verification failed. Error details", error);
        }
    });

program
    .command('check-hash <file-id>')
    .description('check the file identifier and retrieve tx info')
    .option('-r, --request-id <request-id>', 'filter result by request id')
    .action(async function (fileId, cmdObj) {
        processHostUrl(program.hostUrl);
        try {
            let account = await requireAccountOption(program.identityFile, program.password, true);
            let requestId = cmdObj.requestId;
            let result = await recheck.verifyHash(fileId, account.address, requestId);
            console.log(result);
        } catch (error) {
            console.error("File verification failed. Error details", error);
        }
    });


program
    .command('exec <selection-hash>')
    .description('execute command on a selection')
    .option('-a, --authorize-open', 'authorize a browser to decrypt and open files')
    .option('-s, --authorize-share', 'authorizes a browser to share files')
    .action(async function (selectionHash, cmdObj) {
        try {
            processHostUrl(program.hostUrl);

            let account = await requireAccountOption(program.identityFile, program.password, true);

            if (!selectionHash.startsWith("o:")
                && !selectionHash.startsWith("s:")
                && !selectionHash.startsWith("mo:")) {

                let commandOption;
                if (cmdObj.authorizeOpen) {
                    commandOption = "o";
                }

                if (cmdObj.authorizeShare) {
                    if (commandOption) {
                        console.error("You can specify only either open or share");
                        process.exit(1);
                    } else {
                        commandOption = "s";
                    }
                }

                if (!commandOption) {
                    console.error("Explicit command option needed.");
                    process.exit(1);
                }

                selectionHash = `${commandOption}:${selectionHash}`;
            }

            let execResult = await recheck.execSelection(selectionHash, account);

            if (execResult.status === "ERROR") {
                console.error("Error: status", execResult.status, "code", execResult.code);
            } else {
                console.log(execResult);
            }
        } catch (error) {
            console.error("Error: failed to execute selection command. Details:", error);
        }
    });

program.parse(process.argv);

if (!process.argv.slice(2).length) {
    program.outputHelp();
}
