// SPDX-License-Identifier: MIT
// zk-audit scanner fixture: an OpenZeppelin-style base in a Foundry lib/.
pragma solidity ^0.8.20;

abstract contract Ownable {
    address private _owner;

    constructor(address initialOwner) {
        _owner = initialOwner;
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function owner() public view virtual returns (address) {
        return _owner;
    }

    function _checkOwner() internal view virtual {
        require(owner() == msg.sender, "not owner");
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        _owner = newOwner;
    }
}
