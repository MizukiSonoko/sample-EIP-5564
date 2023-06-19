// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.5.0;

import "./interfaces/IERC5564Messenger.sol";

import "elliptic-curve-solidity/contracts/EllipticCurve.sol";

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
    function parsePublicKey(bytes memory publicKey) internal pure returns (bytes32, bytes32) {
        bytes32 spendKey;
        bytes32 viewKey;
        assembly {
            spendKey := mload(add(publicKey, 32))
            viewKey := mload(add(publicKey, 64))
        }
        return (spendKey, viewKey);
    }

    /// @notice Generates a stealth address from a stealth meta address.
    /// @param stealthMetaAddress The recipient's stealth meta-address.
    /// @return stealthAddress The recipient's stealth address.
    /// @return ephemeralPubKey The ephemeral public key used to generate the stealth address.
    /// @return viewTag The view tag derived from the shared secret.
    function generateStealthAddress(bytes calldata stealthMetaAddress)
      external
      view
      returns (address stealthAddress, bytes memory ephemeralPubKey, bytes1 viewTag) {

      // The generateStealthAddress function performs the following computations:
      //    Generate a random 32-byte entropy ephemeral private key p_ephemeral.
      bytes32 p_ephemeral = bytes32(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender)));
      //    Derive the ephemeral public P_ephemeral key from p_ephemeral.
      uint256 p_ephemeral_uint = uint256(p_ephemeral);
      (uint256 gx, uint256 gy) = EllipticCurve.ecMul(p_ephemeral_uint, SECP256K1_GX, SECP256K1_GY, SECP256K1_A, SECP256K1_PP);
      ephemeralPubKey = abi.encodePacked(gx, gy);
      //    Parse the spending and viewing public keys, P_spend and P_view, from the stealth meta-address.
      (bytes32 P_spend, bytes32 P_view) = parsePublicKey(stealthMetaAddress);

      //    A shared secret s is computed as p_ephemeral * P_view.
      bytes32 s = bytes32(p_ephemeral_uint * uint256(P_view));
      //    The secret is hashed s_h = h(s).
      bytes32 s_h = keccak256(abi.encodePacked(s));
      //    The view tag v is extracted by taking the most significant byte s_h[0],
      viewTag = bytes1(s_h[0]);
      //    Multiply the hashed shared secret with the generator point S_h = s_h * G.
      (uint256 Sx, uint256 Sy) = EllipticCurve.ecMul(uint256(p_ephemeral), SECP256K1_GX, SECP256K1_GY, SECP256K1_A, SECP256K1_PP);
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
    function checkStealthAddress(
      address stealthAddress,
      bytes calldata ephemeralPubKey,
      bytes calldata viewingKey,
      bytes calldata spendingPubKey
    ) external view returns (bool) {

    }
    */

    /// @notice Computes the stealth private key for a stealth address.
    /// @param stealthAddress The expected stealth address.
    /// @param ephemeralPubKey The ephemeral public key used to generate the stealth address.
    /// @param spendingKey The recipient's spending private key.
    /// @return stealthKey The stealth private key corresponding to the stealth address.
    /// @dev The stealth address input is not strictly necessary, but it is included so the method
    /// can validate that the stealth private key was generated correctly.
    /*
    function computeStealthKey(
      address stealthAddress,
      bytes calldata ephemeralPubKey,
      bytes calldata spendingKey
    ) external view returns (bytes memory) {

    }
    */

}