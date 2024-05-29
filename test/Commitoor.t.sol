// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Commitoor} from "../src/Commitoor.sol";

contract CommitoorTest is Test {
    Commitoor commitoor;

    function setUp() public {
        commitoor = new Commitoor();
    }

    function test_flow_2_commitoors() public {
        string[] memory seeds = new string[](2);
        seeds[0] = "hakuna";
        seeds[1] = "matata";

        address[] memory signers = new address[](seeds.length);
        address[] memory expectedSigners = new address[](seeds.length);
        expectedSigners[0] = 0x7Aba92146ef309bc32ebb48584D526401FFc3dA6;
        expectedSigners[1] = 0xbB86A0d281e4700ec33Ae7C8D32A214266348D70;
        for (uint256 i; i < seeds.length; ++i) {
            signers[i] = _generateSignerFromSeed(seeds[i]); 
            assertEq(signers[i], expectedSigners[i]);
        }
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
