// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {BitMaps} from "lib/openzeppelin-contracts/contracts/utils/structs/BitMaps.sol";

contract Commitoor {

    mapping(address => BitMaps.BitMap) private _nonces;


    function nonceUsed(address account, uint256 nonce) external view returns(bool) {
        return BitMaps.get(_nonces[account], nonce);
    }
}
