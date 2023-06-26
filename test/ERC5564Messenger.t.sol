// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/ERC5564Messenger.sol";

contract CounterTest is Test {
    ERC5564Messenger public erc5564Messenger;

    //  Address: 0x3498B6C91680a0079E365e5C43dCa8f9e33aa4a5
    //  PrivateKey: 0x8dea547d647088d01cb6cf1a1fdefe721c60d5aac987f1ccba317a6ea93e1d66

    //  Address: 0xDB45228dA324fb9A832c2a1C8Edf08D6820Ccc9C
    //  PrivateKey: 0x3b39fbaa609ba4ebe0db1fee8bb9d78bdb681044ab19418dc819fbb458496b59
    function setUp() public {
        erc5564Messenger = new ERC5564Messenger();
    }

    function testIncrement() view public {
        // st:eth:0x<spendingKey><viewingKey>
        // => EthereumAddress + PrivateKey
        bytes memory spendingKey = "0x8dea547d647088d01cb6cf1a1fdefe721c60d5aac987f1ccba317a6ea93e1d66";
        bytes memory viewingKey = "0x3b39fbaa609ba4ebe0db1fee8bb9d78bdb681044ab19418dc819fbb458496b59";
        bytes memory stealthMetaAddress = "0x3498B6C91680a0079E365e5C43dCa8f9e33aa4a53b39fbaa609ba4ebe0db1fee8bb9d78bdb681044ab19418dc819fbb458496b59";
        (address stealthAddress, bytes memory ephemeralPubKey, bytes1 viewTag) = erc5564Messenger.generateStealthAddress(stealthMetaAddress);
        console.log("address %s", stealthAddress);
        console.logBytes(ephemeralPubKey);
        console.logBytes1(viewTag);

        bytes memory ephemeralPriKey = erc5564Messenger.computeStealthKey(
            stealthAddress,
            ephemeralPubKey,
            spendingKey,
            viewingKey
        );
        console.log("private key is");
        console.logBytes(ephemeralPriKey);
    }

    

}

// 0x5d3525136e098510d8e1edba544d297fe56af4b139192776942ef3297e339c34