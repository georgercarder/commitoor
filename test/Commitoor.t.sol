// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Commitoor} from "../src/Commitoor.sol";

import {Strings} from "lib/openzeppelin-contracts/contracts/utils/Strings.sol";

contract CommitoorTest is Test {
    Commitoor commitoor;

    function setUp() public {
        commitoor = new Commitoor();
    }

    function test_flow_2_commitoors() public {
        uint256 numPlayers = 2;
        string[] memory seeds = new string[](numPlayers);
        seeds[0] = "hakuna";
        seeds[1] = "matata";
        address[] memory signers = new address[](numPlayers);
        {

        address[] memory expectedSigners = new address[](numPlayers);
        expectedSigners[0] = 0x7Aba92146ef309bc32ebb48584D526401FFc3dA6;
        expectedSigners[1] = 0xbB86A0d281e4700ec33Ae7C8D32A214266348D70;
        for (uint256 i; i < seeds.length; ++i) {
            signers[i] = _generateSignerFromSeed(seeds[i]); 
            assertEq(signers[i], expectedSigners[i]);
        }
        }

        string memory plainText = "eat at Don's";

        uint256[] memory noncesToUse = new uint256[](numPlayers);
        noncesToUse[0] = 420;
        noncesToUse[1] = 69;
        for (uint256 i; i < noncesToUse.length; ++i) {
            assertEq(commitoor.nonceUsed(signers[i], noncesToUse[i]), false); 
        }
        bytes32 plaintextShadow = commitoor.hashPlaintext(bytes(plainText));
        assertEq(plaintextShadow != bytes32(0x0), true); // checking for dumb impl mistakes

        uint256 commitmentBlock = block.number;
        bytes[] memory signatures = new bytes[](numPlayers);
        for (uint256 i; i < signers.length; ++i) {
            bytes32 secretDigest = commitoor.getSecretDigest(commitmentBlock, plaintextShadow, noncesToUse[i]);
            assertEq(secretDigest != bytes32(0x0), true); // checking for dumb impl mistakes

            signatures[i] = _signMessage(seeds[i], secretDigest);
        }
        bytes32 commitment = commitoor.getCommitment(signatures);
        assertEq(commitment != bytes32(0x0), true); // checking for dumb impl mistakes


        address anyone = address(123);

        vm.prank(anyone); // can even go as far as to not leak ANY info about this secret or even whom is involved!!
        commitoor.setCommitment(commitment);

        // TODO revealSecret in this flow
    }

    function _signMessage(string memory seed, bytes32 secretDigest) private returns(bytes memory ret) {
        string[] memory inputs = new string[](8); 

        inputs[0] = "node";
        inputs[1] = "js/ethersCaller.js";
        inputs[2] = "--action";
        inputs[3] = "signMessage";
        inputs[4] = "--seed";
        inputs[5] = seed;

        inputs[6] = "--message";
        bytes memory bHexString = bytes(Strings.toHexString(uint256(secretDigest), 32));
        bytes memory bHexStringSans0x = new bytes(bHexString.length-2);
        for (uint256 i = 2; i < bHexString.length; ++i) {
            bHexStringSans0x[i-2] = bHexString[i]; 
        }
        inputs[7] = string(bHexStringSans0x);

        
        bytes memory res = vm.ffi(inputs); 
        

        (ret) = abi.decode(res, (bytes));
    }

    function _generateSignerFromSeed(string memory seed) private returns(address ret) {
        string[] memory inputs = new string[](6); 

        inputs[0] = "node";
        inputs[1] = "js/ethersCaller.js";
        inputs[2] = "--action";
        inputs[3] = "generateSignerFromSeed";
        inputs[4] = "--seed";
        inputs[5] = seed;

        bytes memory res = vm.ffi(inputs); 

        (ret) = abi.decode(res, (address));
    }
}
