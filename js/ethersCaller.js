const args = require('yargs').argv;
const ethers = require('ethers');

const network = 'https://eth-mainnet.g.alchemy.com/v2/WZ-pZ1vZYVolgc8E7sKMvdWCJqXfKrvW';
// this would be passed by a config (that is .gitignore'd) and kept out of version control in ACTUAL production
// for ease of demo, it was kept in

const provider = ethers.getDefaultProvider(network);

function generateSignerFromSeed(seed) {
    const signer = _generateSignerFromSeed(seed);
    console.log(signer.address); // DEBUG
    // TODO encode address and pass to stdout lol
}

function _generateSignerFromSeed(seed) {
    const mnemonic = ethers.Mnemonic.fromEntropy(ethers.hashMessage(seed));
    return ethers.HDNodeWallet.fromMnemonic(mnemonic);
}

async function signMessage(seed, message) {
    const signedMessage = await _signMessage(seed, message);
    console.log(signedMessage);
    // TODO encode signedMessage and pass to stdout lol
}

function _signMessage(seed, message) {
    // note: all security formatting of message is handled by the lens functions of the commitoor smart contract
    const signer = _generateSignerFromSeed(seed);
    checkMessageFormat(message);
    message = '0x'+message;
    return signer.signMessage(message);
}

function checkMessageFormat(message) {
    const msgCopy = (' ' + message).slice(1);
    if (msgCopy.replaceAll(/[0-9]/g, "").replaceAll(/[a-f]/g, "").length > 0) {
        console.log("message must be hexString without '0x' prefix"); 
        // since yargs likes to parse 0x prefixed hexstrings
        process.exit(1);
    }
}

const action = args.action;
checkArg(action, "action");

if (action === "generateSignerFromSeed") {
    const seed = args.seed;
    checkArg(seed, "seed");
    generateSignerFromSeed(seed);
} else if (action === "signMessage") {
    const seed = args.seed;
    checkArg(seed, 'seed');
    const message = args.message;
    checkArg(message, 'message');
    signMessage(seed, message);
}

function checkArg(arg, argName) {
    if (arg === undefined || arg === true) {
        console.log(`must include '--${argName}' arg`);
        process.exit(1);
    }
}
