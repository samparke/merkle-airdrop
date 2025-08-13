//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AirdropToken} from "./AirdropToken.sol";
import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MerkleAirdrop is EIP712 {
    using SafeERC20 for IERC20;

    error MerkleAirdrop__InvalidProof();
    error MerkleAirdrop__AlreadyClaimed();
    error MerkleAirdrop__InvalidSignature();

    IERC20 private immutable i_airdropToken;
    bytes32 private immutable i_merkleRoot;
    mapping(address claimer => bool claimed) private s_hasClaimed;

    bytes32 private constant MESSAGE_TYPEHASH = keccak256("AirdropClaim(address account, uint256 amount)");

    struct AirdropClaim {
        address account;
        uint256 amount;
    }

    event Claim(address account, uint256 amount);

    /**
     *
     * @param merkleRoot // The merkle root is calculated off chain (output.json) from a list of account: amount pairs. It is stored in the contract upon initalisation.
     * To verify a users claim, the contract:
     * - Recomputes the hash for the account and amount passed into claim.
     * - Hashes with the proofs, up the tree, to reconstruct the root
     * - If the recalculated root matches the root stored in this contract, the user's claim is deemed to be true
     * @param airdropToken the token we are airdropping to the users
     */
    constructor(bytes32 merkleRoot, IERC20 airdropToken) EIP712("MerkleAirdrop", "1") {
        i_airdropToken = airdropToken;
        i_merkleRoot = merkleRoot;
    }

    /**
     * @notice allows users to claim airdrop tokens
     * @param account the account we are claiming airdrop tokens to
     * @param amount the amount being claimed
     * @param merkleProof the merkle proofs allowing reconstruction of the merkle root
     * three integers below make up an ECDSA signature. Together, they allow us to identify the recover the signers
     * public key from a message hash.
     * @param v for a given r (x coordinate), there are two possible points - the positive point on the curve, and the negative point.
     * @param r the x coordinate on the elliptic curve, found when signing
     * @param s a alue derived from the message hash, the private key and r
     */
    function claim(address account, uint256 amount, bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s)
        external
    {
        // checks if the account has claimed
        if (s_hasClaimed[account]) {
            revert MerkleAirdrop__AlreadyClaimed();
        }
        // compare the signature with the signature computed from the message hash
        if (!_isValidSignature(account, getMessageHash(account, amount), v, r, s)) {
            revert MerkleAirdrop__InvalidSignature();
        }
        // hash twice to avoid collusion
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(account, amount))));
        if (!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)) {
            revert MerkleAirdrop__InvalidProof();
        }
        s_hasClaimed[account] = true;
        emit Claim(account, amount);
        i_airdropToken.safeTransfer(account, amount);
    }

    /**
     * @notice constructs the EIP-712 message digest - the highly readable message format seen when signing the metamask transaction
     * @param account the address elligble to claim
     * @param amount the number of tokens to claim
     */
    function getMessageHash(address account, uint256 amount) public view returns (bytes32 digest) {
        return
        // we pass the structHash - which is the hash of the struct type (struct AirdropClaim {address account; uint256 amount;})
        // and the actual values.
        // _hashTypedDataV4 - combines the EIP712 domain separator (our constructor: EIP712("MerkleAirdrop", "1"), the chainId,
        // and the address of this contract), with the structHash.
        // The output follows this structure: keccak256("\x19\x01" | domain separator | structHash)
        // the domain separator ensures that the signature can only be used for this purpose, and not some other contract with the same structHash
        // this prevents cross-contract replay attacks
        _hashTypedDataV4(keccak256(abi.encode(MESSAGE_TYPEHASH, AirdropClaim({account: account, amount: amount}))));
    }

    /**
     *
     * @param account the account attempting to claim in the claim function
     * @param digest the EIP-712 hash derived from getMessageHash
     * we recover the actual signer (the Ethereum address derived from the public key) from the v, r and s (the signature)
     * and the EIP-712 digest from the _hashTypedDataV4, and compare to the account trying to claim
     * if these addresses match, the signature is valid
     */
    function _isValidSignature(address account, bytes32 digest, uint8 v, bytes32 r, bytes32 s)
        internal
        pure
        returns (bool)
    {
        (address actualSigner,,) = ECDSA.tryRecover(digest, v, r, s);
        return actualSigner == account;
    }

    /**
     * @return the merkle root stored within the contract
     */
    function getMerkleRoot() external view returns (bytes32) {
        return i_merkleRoot;
    }

    /**
     * @return the airdrop token we are distributing to the claimants
     */
    function getAirdropToken() external view returns (IERC20) {
        return i_airdropToken;
    }
}
