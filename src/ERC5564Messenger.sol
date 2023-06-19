// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./interfaces/IERC5564Messenger.sol";

contract ERC5564Messenger is IERC5564Messenger {
    /// @dev Called by integrators to emit an `Announcement` event.
    /// @dev `ephemeralPubKey` represents the ephemeral public key used by the sender.
    /// @dev `stealthRecipientAndViewTag` contains the stealth address (20 bytes) and the view tag (12
    /// bytes).
    /// @dev `metadata` is an arbitrary field that the sender can use however they like, but the below
    /// guidelines are recommended:
    ///   - When sending ERC-20 tokens, the metadata SHOULD include the token address as the first 20
    ///     bytes, and the amount being sent as the following 32 bytes.
    ///   - When sending ERC-721 tokens, the metadata SHOULD include the token address as the first 20
    ///     bytes, and the token ID being sent as the following 32 bytes.
    function announce(bytes memory ephemeralPubKey, bytes32 stealthRecipientAndViewTag, bytes32 metadata) external {
        emit Announcement(ephemeralPubKey, stealthRecipientAndViewTag, metadata);
    }

    /// @notice Generates a stealth address from a stealth meta address.
    /// @param stealthMetaAddress The recipient's stealth meta-address.
    /// @return stealthAddress The recipient's stealth address.
    /// @return ephemeralPubKey The ephemeral public key used to generate the stealth address.
    /// @return viewTag The view tag derived from the shared secret.
    function generateStealthAddress(bytes memory stealthMetaAddress)
      external
      view
      returns (address stealthAddress, bytes memory ephemeralPubKey, bytes1 viewTag) {

      // The generateStealthAddress function performs the following computations:
      //    Generate a random 32-byte entropy ephemeral private key p_ephemeral.
      bytes32 p_ephemeral = bytes32(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender)));
      //    Derive the ephemeral public P_ephemeral key from p_ephemeral.
      (uint256 gx, uint256 gy) = EllipticCurve.ecMul(p_ephemeral, EllipticCurve.SECP256K1_GX, EllipticCurve.SECP256K1_GY, EllipticCurve.SECP256K1_A, EllipticCurve.SECP256K1_B, EllipticCurve.SECP256K1_PP);
      ephemeralPubKey = abi.encodePacked(gx, gy);
      //    Parse the spending and viewing public keys, P_spend and P_view, from the stealth meta-address.
      bytes32 P_spend = abi.decode(stealthMetaAddress[:32], (bytes32));
      bytes32 P_view = abi.decode(stealthMetaAddress[32:], (bytes32));

      //    A shared secret s is computed as p_ephemeral * P_view.
      bytes32 s = p_ephemeral * P_view;
      //    The secret is hashed s_h = h(s).
       bytes32 s_h = keccak256(abi.encodePacked(s));
      //    The view tag v is extracted by taking the most significant byte s_h[0],
      viewTag = bytes1(s_h[0]);
      //    Multiply the hashed shared secret with the generator point S_h = s_h * G.
      (uint256 Sx, uint256 Sy) = EllipticCurve.ecMul(s_h, EllipticCurve.SECP256K1_GX, EllipticCurve.SECP256K1_GY, EllipticCurve.SECP256K1_A, EllipticCurve.SECP256K1_B, EllipticCurve.SECP256K1_PP);
      //    The recipient’s stealth public key is computed as P_stealth = P_spend + S_h.
      (uint256 P_stealth_x, uint256 P_stealth_y) = EllipticCurve.ecAdd(P_spend, Sx, P_spend, Sy, EllipticCurve.SECP256K1_A, EllipticCurve.SECP256K1_B, EllipticCurve.SECP256K1_PP);
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
    function checkStealthAddress(
      address stealthAddress,
      bytes memory ephemeralPubKey,
      bytes memory viewingKey,
      bytes memory spendingPubKey
    ) external view returns (bool) {

    }

    /// @notice Computes the stealth private key for a stealth address.
    /// @param stealthAddress The expected stealth address.
    /// @param ephemeralPubKey The ephemeral public key used to generate the stealth address.
    /// @param spendingKey The recipient's spending private key.
    /// @return stealthKey The stealth private key corresponding to the stealth address.
    /// @dev The stealth address input is not strictly necessary, but it is included so the method
    /// can validate that the stealth private key was generated correctly.
    function computeStealthKey(
      address stealthAddress,
      bytes memory ephemeralPubKey,
      bytes memory spendingKey
    ) external view returns (bytes memory) {

    }

}