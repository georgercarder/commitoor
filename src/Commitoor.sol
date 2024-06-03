// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {BitMaps} from "lib/openzeppelin-contracts/contracts/utils/structs/BitMaps.sol";

import {ECDSA} from "lib/solady/src/utils/ECDSA.sol";

contract Commitoor {
    error CommitmentExistsError();
    error LengthMismatchError();
    error PartiesOutOfOrderError();
    error NonceUsedError();
    error InvalidSignatureError();
    error CallerNotCommitoorError();
    error CommitmentDNEError();

    string public version;
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public immutable COMMITMENT_TYPEHASH;

    mapping(bytes32 => bool) public commitments;

    mapping(address => BitMaps.BitMap) private _nonces;

    event NewCommitment(bytes32 commitment);

    event SecretRevealed(bytes32 commitment, address revealer, uint256 commitmentBlock, bytes plaintext);

    struct Commitment {
        uint256 commitmentBlock;
        bytes32 plaintextShadow;
        uint256 nonce;
    }

    constructor() {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        version = "0.0.1";
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Commitoor")),
                keccak256(bytes(version)),
                chainId,
                address(this)
            )
        );
        COMMITMENT_TYPEHASH = keccak256("Commitment(uint256 commitmentBlock,bytes32 plaintextShadow,uint256 nonce)");
    }

    // lens functions, in order of setup-phase workflow

    function nonceUsed(address account, uint256 nonce) external view returns (bool) {
        return BitMaps.get(_nonces[account], nonce);
    }

    function hashPlaintext(bytes calldata plaintext) external pure returns (bytes32 plaintextShadow) {
        return _hashPlaintext(plaintext);
    }

    function getSecretDigest(uint256 commitmentBlock, bytes32 plaintextShadow, uint256 nonce)
        external
        view
        returns (bytes32)
    {
        return _getSecretDigest(commitmentBlock, plaintextShadow, nonce);
    }

    /*
       The array of signatures must be ordered with respect to the canonical ordering of the 
       signers.
       It's on the caller to have performed this ordering as it'll be cumbersome (requiring a 
       trie) to do in contract.
    **/
    function getCommitment(bytes[] calldata signatures) external pure returns (bytes32) {
        /*
           note: It is likely the case that the signers will pick predictable nonces 
           (succession etc.). Fortunately an ECDSA signature on known data cannot be predicted 
           by an outside party, so there's no candidate signature array for an adversary to 
           compare to commitments.
        **/
        return _getCommitment(signatures);
    }

    // mutating functions in order of workflow

    /*
      Can be called by anyone, so the privvy commitoor would make this tx using a burner 
      address so as to not leak data of whom is involved.
      **/
    function setCommitment(bytes32 commitment) external {
        if (commitments[commitment]) revert CommitmentExistsError();
        commitments[commitment] = true;

        emit NewCommitment(commitment);
    }

    /* 
       The caller must be one of the entries of the `parties` parameter.
       All array parameters must be ordered with respect to the canonical ordering of the 
       parties.
       note: the commitmentBlock is the "time signifier", doesn't necessarily need to be block. 
       Can be any time signifier that signers agree to and is up to interpretation by the 
       client.
       **/
    function revealSecret(
        address[] calldata parties,
        uint256[] calldata nonces,
        uint256 commitmentBlock,
        bytes calldata plaintext,
        bytes[] calldata signatures
    ) external {
        uint256 orderBound = parties.length - 1;
        if (parties.length != signatures.length) revert LengthMismatchError();
        /* 
           Check above prevents signatures.length from being larger than parties.. which would 
           make the commitment not actually reflect the signatures.
        **/
        bytes32 plaintextShadow = _hashPlaintext(plaintext);
        address party;
        bool partyInvolved;
        unchecked {
            for (uint256 i; i < parties.length; ++i) {
                party = parties[i];
                if (msg.sender == party) partyInvolved = true;

                if (i < orderBound && !(party < parties[i + 1])) revert PartiesOutOfOrderError();

                _checkSignature(nonces[i], party, commitmentBlock, plaintextShadow, signatures[i]);
            }
        } //uc
        if (!partyInvolved) revert CallerNotCommitoorError();
        bytes32 commitment = _getCommitment(signatures);
        if (!commitments[commitment]) revert CommitmentDNEError();
        commitments[commitment] = false;
        /*
           note: It is not necessary to store the commitment as being committed in the past 
           for the sake of future commitments.
           This is because the nonces can only be used once and the commitments are a hash
           which cannot be recovered with any change in a well-formed preimage.
           So any subsequent setCommitment call with a former commitment would just be a 
           single "noisy" (event) occurrence that can never be revealed.
        **/

        emit SecretRevealed(commitment, msg.sender, commitmentBlock, plaintext);
    }

    // private functions

    function _hashPlaintext(bytes calldata plaintext) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(plaintext));
    }

    function _getSecretDigest(uint256 commitmentBlock, bytes32 plaintextShadow, uint256 nonce)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    keccak256(abi.encode(COMMITMENT_TYPEHASH, commitmentBlock, plaintextShadow, nonce))
                )
            )
        );
    }

    function _checkSignature(
        uint256 nonce,
        address account,
        uint256 commitmentBlock,
        bytes32 plaintextShadow,
        bytes calldata signature
    ) private {
        BitMaps.BitMap storage bm = _nonces[account];
        if (BitMaps.get(bm, nonce)) revert NonceUsedError();
        BitMaps.set(bm, nonce);

        bytes32 digest = ECDSA.toEthSignedMessageHash(_getSecretDigest(commitmentBlock, plaintextShadow, nonce));
        if (ECDSA.recoverCalldata(digest, signature) != account) revert InvalidSignatureError();
    }

    function _getCommitment(bytes[] calldata signatures) private pure returns (bytes32) {
        return keccak256(abi.encode(signatures));
    }
}
