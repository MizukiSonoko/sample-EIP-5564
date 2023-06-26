// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/ERC5564Messenger.sol";

contract CounterTest is Test {
    ERC5564Messenger public erc5564Messenger;

    // https://github.com/witnet/elliptic-curve-solidity/blob/master/examples/Secp256k1.sol#L12
    uint256 public constant SECP256K1_GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant SECP256K1_GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant SECP256K1_A = 0;
    uint256 public constant SECP256K1_B = 7;
    uint256 public constant SECP256K1_PP =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;


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
        address recoverdPubKey = derivePublicKey(toBytes32(ephemeralPriKey));
        console.log("recovered address %s", recoverdPubKey);
    }

    function derivePublicKey(bytes32 privateKey) internal pure returns (address) {
      (uint256 gx, uint256 gy) = EllipticCurve.ecMul(uint256(privateKey), SECP256K1_GX, SECP256K1_GY, SECP256K1_A, SECP256K1_PP);
      return address(uint160(uint256(keccak256(abi.encodePacked(gx, gy)))));
    }


    function toBytes32(bytes memory source) public pure returns (bytes32 result) {
      if (source.length == 0) {
          return 0x0;
      }

      assembly {
          result := mload(add(source, 32))
      }
    }

}

// 0x5d3525136e098510d8e1edba544d297fe56af4b139192776942ef3297e339c34