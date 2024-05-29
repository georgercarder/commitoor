// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {BitMaps} from "lib/openzeppelin-contracts/contracts/utils/structs/BitMaps.sol";

import {ECDSA} from "lib/solady/src/utils/ECDSA.sol";

contract Commitoor {
    error CommitmentExistsError();
    error PartiesOutOfOrderError();
    error NonceUsedError();
    error InvalidSignatureError();
    error CallerNotCommitoorError();

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

    function hashPlaintext(bytes calldata plaintext) external pure returns (bytes32) {
        return _hashPlaintext(plaintext);
    }

    function getSecretDigest(uint256 commitmentBlock, bytes32 plaintextShadow, uint256 nonce)
        external
        view
        returns (bytes32)
    {
        return _getSecretDigest(commitmentBlock, plaintextShadow, nonce);
    }

    // the array of signatures must be ordered with respect to the canonical ordering of the signers 
    // it's on the caller to have performed this ordering as it'll be cumbersome (requiring a trie) to do in contract
    function getCommitment(bytes[] calldata signatures) external pure returns (bytes32) {
        // note: since the signatures are formed with arbitrary choice of nonce by signers, there is no need for additional salt
        return _getCommitment(signatures);
    }

    // mutating functions in order of workflow

    // can be called by anyone
    function setCommitment(bytes32 commitment) external {
        if (commitments[commitment]) revert CommitmentExistsError();
        commitments[commitment] = true;

        emit NewCommitment(commitment);
    }

    // the caller must be one of the entries of the `parties` parameter
    // the array parameters must be ordered with respect to the canonical ordering of the parties
    function revealSecret(
        address[] calldata parties,
        uint256[] calldata nonces,
        uint256 commitmentBlock,
        bytes calldata plaintext,
        bytes[] calldata signatures
    ) external {
        uint256 orderBound = parties.length - 1;
        bytes32 plaintextShadow = _hashPlaintext(plaintext);
        address party;
        bool partyInvolved;
        unchecked{
        for (uint256 i; i < parties.length; ++i) {
            party = parties[i];
            if (msg.sender == party) partyInvolved = true;

            if (i < orderBound && !(party < parties[i + 1])) revert PartiesOutOfOrderError();

            _checkSignature(nonces[i], party, commitmentBlock, plaintextShadow, signatures[i]);
        }
        }//uc
        if (!partyInvolved) revert CallerNotCommitoorError();
        bytes32 commitment = _getCommitment(signatures);
        commitments[commitment] = false;
        // note it is not necessary to store the commitment as being committed in the past for the sake of future commitments
        // this is because the nonces can only be used once and the commitments are a hash
        // which cannot be recovered with any change in a well-formed preimage

        emit SecretRevealed(commitment, msg.sender, commitmentBlock, plaintext);
    }

    // private functions

    function _hashPlaintext(bytes calldata plaintext) private pure returns (bytes32) {
        return keccak256(abi.encode(plaintext)); // TODO make lower level
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
