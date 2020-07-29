#!/usr/bin/env node

let recheck;
try {
    recheck = require('../recheck-clientjs-library');
} catch (ignored) {
    recheck = require('recheck-clientjs-library');
}

const program = require('commander');
const fs = require('fs');
const path = require('path');
const aes256 = require('aes256');
const btoa = require('btoa');
const atob = require('atob');

let hammerNetwork = "ae";
let hammerBaseUrl = "http://localhost:3000";

recheck.debug(false);
recheck.setDefaultRequestId('ReCheckHAMMER');
recheck.init(hammerBaseUrl, hammerNetwork);


const isNullAny = (...elements) => recheck.isNullAny(...elements);

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
        recheck.init(hostUrl, hammerNetwork);
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
        console.log(loginError);
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
        if (cmdObj.receiptFile) {
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
    .command('info')
    .description('obtain API version and blockchain type')
    .action(async function () {
        processHostUrl(program.hostUrl);
        try {
            let info = await recheck.getServerInfo();
            console.log(info);
        } catch (error) {
            console.error("Obtain server info failed.", error);
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
    .command('put <file-name>')
    .description('stores file securely and timestamps it')
    .option('-x, --external <external-id>', 'register external id for file')
    .option('-e, --extra <extra>', 'provide JSON.stringify([array of values]) for creation of trail hash')
    .option('-t, --tx-poll', 'poll for tx receipt')
    .action(async function (fileName, cmdObj) {
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
            }, account.address, account.publicEncKey, cmdObj.external, cmdObj.txPoll, cmdObj.extra);

            if (isNullAny(uploadResult)) {
                console.error("Error: status", uploadResult.status,
                    "code", uploadResult.code, "message", uploadResult.message);
            } else {
                if (uploadResult.dataId) {
                    console.log(`${file.name} ${uploadResult.dataId}`);
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
    .option('-r, --request-tx-receipt', 'get tx receipt')//TODO remove because of txPoll
    .option('-f, --receipt-file <file>', 'specify tx receipt file')//TODO remove or fix recheck.open so it returns file + receipt
    .option('-n, --disable-print', 'no print in stdio, used with --request-tx-receipt')
    .option('-x, --external', 'provided identifier is external')
    .option('-e, --extra <extra>', 'provide JSON.stringify([array of values]) for creation of trail hash')
    .option('-t, --tx-poll', 'poll for tx receipt')
    .action(async function (fileId, cmdObj) {
        try {
            processHostUrl(program.hostUrl);
            let account = await requireAccountOption(program.identityFile, program.password, true);

            let openResult = await recheck.open(fileId, account.publicKey, account, cmdObj.external, cmdObj.txPoll, cmdObj.extra);

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
    .command('verify <file-id> <file-name>')
    .description('verify the file identifier against the content file')
    .option('-x, --external', 'provided identifier is external')
    .option('-e, --extra <extra>', 'provide JSON.stringify([array of values]) for verification of trail hash')
    .option('-t, --tx-poll', 'poll for tx receipt')
    .action(async function (fileId, fileName, cmdObj) {
        try {
            let account = await requireAccountOption(program.identityFile, program.password, true);

            let data = await readBinaryFile(fileName);
            let validateResult = await recheck.validate(data.binary, account.publicKey, fileId, cmdObj.external, cmdObj.txPoll, cmdObj.extra);

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
    .command('share <file-id> <recipient-id> [moreRecipientIds...]')
    .description('share securely a file with multiple recipients')
    .option('-x, --external', 'provided identifier is external')
    .option('-e, --extra <extra>', 'provide JSON.stringify([array of values]) for creation of trail hash')
    .option('-t, --tx-poll', 'poll for tx receipt')
    .action(async function (fileId, recipientId, moreRecipientIds, cmdObj) {
        processHostUrl(program.hostUrl);
        let account = await requireAccountOption(program.identityFile, program.password, true);

        moreRecipientIds.push(recipientId);
        if (moreRecipientIds.length > 0) {
            for (let i = 0; i < moreRecipientIds.length; i++) {
                try {
                    let nextShareResult = await recheck.share(fileId, moreRecipientIds[i], account, cmdObj.external, cmdObj.txPoll, cmdObj.extra);
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
    .command('sign <file-id>')
    .description('sign file')
    .option('-x, --external', 'provided identifier is external')
    .option('-e, --extra <extra>', 'provide JSON.stringify([array of values]) for creation of trail hash')
    .option('-t, --tx-poll', 'poll for tx receipt')
    .action(async function (fileId, cmdObj) {
        processHostUrl(program.hostUrl);

        try {
            let account = await requireAccountOption(program.identityFile, program.password, true);

            let result = await recheck.sign(fileId, account.address, account, cmdObj.external, cmdObj.txPoll, cmdObj.extra);
            console.log(result);
        } catch (error) {
            console.error("File signing failed. Error details", error);
        }
    });

program
    .command('register-hash <file-id> [extraTrailHashes...]')
    .description('register file identifier')
    //TODO restrict request types because of txManager
    .option('-y, --request-type <type>', 'select supported trail hash request type register is default')
    .option('-r, --request-id <id>', 'provide request id for additional check-hash filter')
    .option('-e, --extra <extra>', 'provide JSON.stringify([array of values]) for creation of trail hash')
    .option('-t, --tx-poll', 'poll for tx receipt')
    .action(async function (fileId, extraTrailHashes, cmdObj) {
        processHostUrl(program.hostUrl);

        try {
            let account = await requireAccountOption(program.identityFile, program.password, true);

            if (isNullAny(extraTrailHashes)) {
                extraTrailHashes = [];
            }

            let result = await recheck.registerHash(fileId, cmdObj.requestType, account.address, account, cmdObj.requestId, extraTrailHashes, cmdObj.txPoll, cmdObj.extra);
            console.log(result);
        } catch (error) {
            console.error("File verification failed. Error details", error);
        }
    });

program
    .command('check-hash <file-id>')
    .description('check the file identifier and retrieve tx info')
    .option('-r, --request-id <request-id>', 'filter result by request id')
    .option('-x, --external', 'provided identifier is external')
    .action(async function (fileId, cmdObj) {
        processHostUrl(program.hostUrl);
        try {
            let account = await requireAccountOption(program.identityFile, program.password, true);

            let result = await recheck.checkHash(fileId, account.address, cmdObj.requestId, cmdObj.external);
            console.log(result);
        } catch (error) {
            console.error("File verification failed. Error details", error);
        }
    });

program
    .command('external-put <external-id>')
    .description('register external id for file identifier')
    .option('-h, --hash <hash>', 'provide optional file original hash')
    .action(async function (externalId, cmdObj) {
        processHostUrl(program.hostUrl);

        try {
            let hash = cmdObj.hash;

            if (isNullAny(hash)) {
                hash = null;
            }

            let account = await requireAccountOption(program.identityFile, program.password, true);

            let result = await recheck.saveExternalId(externalId, account.address, hash);
            console.log(result);
        } catch (error) {
            console.error("External id registration failed. Error details", error);
        }
    });

program
    .command('external-get <external-id>')
    .description('obtain file identifier from external id')
    .action(async function (externalId) {
        processHostUrl(program.hostUrl);
        try {
            let account = await requireAccountOption(program.identityFile, program.password, true);
            let result = await recheck.convertExternalId(externalId, account.address);
            console.log(result);
        } catch (error) {
            console.error("File id conversion failed. Error details", error);
        }
    });

program
    .command('exec <selection-hash>')
    .description('execute command on a selection')
    .option('-a, --authorize-open', 'authorize a browser to decrypt and open files')
    .option('-s, --authorize-share', 'authorizes a browser to share files')
    .option('-u, --authorize-email', 'authorizes a browser to share files via url')
    .option('-w, --authorize-sign', 'authorizes a browser to sign files')
    .option('-o, --open', 'receive decrypted file payload')
    .option('-e, --extra <extra>', 'provide JSON.stringify([array of values]) for creation of trail hash')
    .option('-t, --tx-poll', 'poll for tx receipt')
    .action(async function (selectionHash, cmdObj) {
        try {
            processHostUrl(program.hostUrl);

            let account = await requireAccountOption(program.identityFile, program.password, true);

            let selectionHashCmd = selectionHash.substr(0, 3);
            if (!["op:", "re:", "sh:", "se:", "sg:"].includes(selectionHashCmd)) {

                let authorizeOpen = cmdObj.authorizeOpen;
                let authorizeShare = cmdObj.authorizeShare;
                let authorizeEmail = cmdObj.authorizeEmail;
                let authorizeSign = cmdObj.authorizeSign;

                let optionsArray = [authorizeOpen, authorizeShare, authorizeSign];
                let firstTrueValueIndex = optionsArray.indexOf(true);
                let lastTrueValueIndex = optionsArray.lastIndexOf(true);

                if (firstTrueValueIndex !== lastTrueValueIndex) {
                    console.error("You can specify only one of open or share or sign");
                    process.exit(1);
                } else if (firstTrueValueIndex < 0) {
                    console.error("Explicit command option needed.");
                    process.exit(1);
                }

                let commandOption;
                if (authorizeOpen) {
                    commandOption = "re";
                } else if (authorizeShare) {
                    commandOption = "sh";
                } else if (authorizeEmail) {
                    commandOption = "se";
                } else if (authorizeSign) {
                    commandOption = "sg";
                } else if (open) {
                    commandOption = "op";
                }

                selectionHash = `${commandOption}:${selectionHash}`;
            }

            let execResult = await recheck.execSelection(selectionHash, account, cmdObj.txPoll, cmdObj.extra);

            console.log(JSON.stringify(execResult, null, 4));
        } catch (error) {
            console.error("Error: failed to execute selection command. Details:", JSON.stringify(error));
        }
    });

program.parse(process.argv);

if (!process.argv.slice(2).length) {
    program.outputHelp();
}
