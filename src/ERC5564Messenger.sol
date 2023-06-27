// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./interfaces/IERC5564Messenger.sol";
import "elliptic-curve-solidity/contracts/EllipticCurve.sol";
import "forge-std/console.sol";

contract ERC5564Messenger is IERC5564Messenger {

    // https://github.com/witnet/elliptic-curve-solidity/blob/master/examples/Secp256k1.sol#L12
    uint256 public constant SECP256K1_GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant SECP256K1_GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant SECP256K1_A = 0;
    uint256 public constant SECP256K1_B = 7;
    uint256 public constant SECP256K1_PP =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Helper function to parse the spending and viewing public keys
    function parsePublicKey(bytes memory publicKey) internal pure returns (uint256, uint256) {
        // console.log("publicKey %d", publicKey.length);
        require(publicKey.length == 64, "Invalid public key length");
        uint256 x;
        uint256 y;
        assembly {
            x := mload(add(4, add(publicKey, 32)))
            y := mload(add(4, add(publicKey, 64)))
        }
        return (x, y);
    }

    // Helper function to parse the spending and viewing public keys
    function parseStealthMetaAddress(bytes memory stealthMetaAddress) internal pure returns (bytes32, bytes memory) {
      // console.log("stealthMetaAddress %d", stealthMetaAddress.length);
      require(stealthMetaAddress.length >= 106, "Input should be at least 128 bytes long");
      bytes32 first;
      assembly {
          first := mload(add(stealthMetaAddress, 32))
      }
      bytes memory second = new bytes(64);
      for (uint i = 0; i < 64; i++) {
          second[i] = stealthMetaAddress[i+32];
      }
      return (first, second);
    }
    
    function derivePublicKey(bytes32 privateKey) internal pure returns (bytes memory) {
      (uint256 gx, uint256 gy) = EllipticCurve.ecMul(uint256(privateKey), SECP256K1_GX, SECP256K1_GY, SECP256K1_A, SECP256K1_PP);
      return abi.encodePacked(gx, gy);
    }

    function toBytes32(bytes memory source) public pure returns (bytes32 result) {
      if (source.length == 0) {
          return 0x0;
      }

      assembly {
          result := mload(add(source, 32))
      }
    }

    function deriveStealthAddress(
      bytes32 spendingPubKeyBytes32,
      uint256 Sx, 
      uint256 Sy
    ) internal view returns (address) {
      (uint256 P_stealth_x, uint256 P_stealth_y) = EllipticCurve.ecAdd(uint256(spendingPubKeyBytes32), Sx, uint256(spendingPubKeyBytes32), Sy, SECP256K1_A, SECP256K1_PP);
      return address(uint160(uint256(keccak256(abi.encodePacked(P_stealth_x, P_stealth_y)))));
    }


    /// @notice Generates a stealth address from a stealth meta address.
    /// @param stealthMetaAddress The recipient's stealth meta-address.
    /// @return stealthAddress The recipient's stealth address.
    /// @return ephemeralPubKey The ephemeral public key used to generate the stealth address.
    /// @return viewTag The view tag derived from the shared secret.
    function generateStealthAddress(bytes calldata stealthMetaAddress)
      external
      view
      returns (address stealthAddress, bytes memory ephemeralPubKey, bytes1 viewTag)
    {

      // The generateStealthAddress function performs the following computations:
      //    Generate a random 32-byte entropy ephemeral private key p_ephemeral.
      bytes32 p_ephemeral = bytes32(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender)));
      //    Derive the ephemeral public P_ephemeral key from p_ephemeral.
      //    P_ephemeral = p_ephemeral * G
      ephemeralPubKey = derivePublicKey(p_ephemeral);

      //    Parse the spending and viewing public keys, P_spend and P_view, from the stealth meta-address.
      (bytes32 P_spend, bytes memory P_view) = parseStealthMetaAddress(stealthMetaAddress);

      //    A shared secret s is computed as p_ephemeral * P_view.
      //    - Parse public key to (x,y)
      //    - S = p_ephemeral * (x,y)
      (uint256 vx, uint256 vy) = parsePublicKey(abi.encodePacked(P_view));
      (uint256 sx, uint256 sy) = EllipticCurve.ecMul(uint256(p_ephemeral), vx, vy, SECP256K1_A, SECP256K1_PP);
      //    The secret is hashed s_h = h(s).
      bytes32 s_h = keccak256(abi.encodePacked(sx, sy));
      //    The view tag v is extracted by taking the most significant byte s_h[0],
      viewTag = bytes1(s_h[0]);
      //    Multiply the hashed shared secret with the generator point S_h = s_h * G.
      (uint256 Sx, uint256 Sy) = EllipticCurve.ecMul(uint256(s_h), SECP256K1_GX, SECP256K1_GY, SECP256K1_A, SECP256K1_PP);
      //    The recipient’s stealth public key is computed as P_stealth = P_spend + S_h.
      (uint256 P_stealth_x, uint256 P_stealth_y) = EllipticCurve.ecAdd(uint256(P_spend), Sx, uint256(P_spend), Sy, SECP256K1_A, SECP256K1_PP);
      //    The recipient’s stealth address a_stealth is computed as publicToAddress(P_stealth).
      stealthAddress = address(uint160(uint256(keccak256(abi.encodePacked(P_stealth_x, P_stealth_y)))));
      //    The function returns the stealth address a_stealth, the ephemeral public key P_ephemeral, and the view tag v
    }

    /// @notice Returns true if funds sent to a stealth address belong to the recipient who controls
    /// the corresponding spending key.
    /// @param stealthAddress The recipient's stealth address.
    /// @param ephemeralPubKey The ephemeral public key used to generate the stealth address.
    /// @param viewingKey The recipient's viewing private key.
    /// @param spendingPubKey The recipient's spending public key.
    /// @return True if funds sent to the stealth address belong to the recipient.
    /*
    ToDo: Fix
      Error: 
      Compiler run failed:
      Error: Compiler error (../codegen/LValue.cpp:56):Stack too deep.
      Try compiling with `--via-ir` (cli) or the equivalent `viaIR: true` (standard JSON) 
      while enabling the optimizer. Otherwise, try removing local variables.
        --> src/ERC5564Messenger.sol:142:39:
          |
      142 |       return derivedStealthAddress == stealthAddress;
          |                                       ^^^^^^^^^^^^^^
    function checkStealthAddress(
      address stealthAddress,
      bytes calldata ephemeralPubKey,
      bytes calldata viewingKey,
      bytes calldata spendingPubKey
    ) external view returns (bool) {
      //    Shared secret s is computed by multiplying the viewing private key with the ephemeral public key of the announcement. p_ephemeral * P_view.
      bytes32 viewingKeyBytes32 = toBytes32(viewingKey);
      (uint256 ePx, uint256 ePy) = parsePublicKey(ephemeralPubKey);
      (uint256 sx, uint256 sy) = EllipticCurve.ecMul(uint256(viewingKeyBytes32), ePx, ePy, SECP256K1_A, SECP256K1_PP);
      
      //    The secret is hashed s_h = h(s).
      bytes32 s_h = keccak256(abi.encodePacked(sx, sy));
      // The view tag is extracted by taking the most significant byte 
      //  and can be compared to the given view tag. 
      // If the view tags do not match, this Announcement is not for the user and the remaining steps can be skipped. If the view tags match, continue on.
      // bytes1 viewTag = bytes1(s_h[0]);
      //    Multiply the hashed shared secret with the generator point S_h = s_h * G.
      (uint256 Sx, uint256 Sy) = EllipticCurve.ecMul(uint256(s_h), SECP256K1_GX, SECP256K1_GY, SECP256K1_A, SECP256K1_PP);
      //    The recipient’s stealth public key is computed as P_stealth = P_spend + S_h.
      bytes32 spendingPubKeyBytes32 = toBytes32(spendingPubKey);
      //    The recipient’s stealth address a_stealth is computed as publicToAddress(P_stealth).
      address derivedStealthAddress = deriveStealthAddress(spendingPubKeyBytes32, Sx, Sy);
      return derivedStealthAddress == stealthAddress;
    }
    */    

    /// @notice Computes the stealth private key for a stealth address.
    /// @param stealthAddress The expected stealth address.
    /// @param ephemeralPubKey The ephemeral public key used to generate the stealth address.
    /// @param spendingKey The recipient's spending private key.
    /// @param viewingKey mistery
    /// @return stealthKey The stealth private key corresponding to the stealth address.
    /// @dev The stealth address input is not strictly necessary, but it is included so the method
    /// can validate that the stealth private key was generated correctly.
    function computeStealthKey(
      address stealthAddress,
      bytes calldata ephemeralPubKey,
      bytes calldata spendingKey,
      bytes calldata viewingKey
    ) external view returns (bytes memory) {
      bytes32 viewingKeyBytes32 = toBytes32(viewingKey);
      (uint256 ePx, uint256 ePy) = parsePublicKey(ephemeralPubKey);
      // Shared secret s is computed by multiplying the viewing private key 
      // with the ephemeral public key of the announcement 
      // s = p_view * P_ephemeral
      (uint256 sx, uint256 sy) = EllipticCurve.ecMul(uint256(viewingKeyBytes32), ePx, ePy, SECP256K1_A, SECP256K1_PP);
      // The secret is hashed s_h = hash(s)
      bytes32 spendingKeyBytes32 = toBytes32(spendingKey);
      // The stealth private key is computed as p_stealth = p_spend + s_h
      (uint256 P_stealth_x, uint256 P_stealth_y) = EllipticCurve.ecAdd(
        uint256(spendingKeyBytes32), sx, uint256(spendingKeyBytes32), sy, SECP256K1_A, SECP256K1_PP);
      return abi.encodePacked(uint256(keccak256(abi.encodePacked(P_stealth_x, P_stealth_y))));
   }
}