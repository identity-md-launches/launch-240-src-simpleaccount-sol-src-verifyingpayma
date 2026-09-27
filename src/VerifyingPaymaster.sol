// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.24;

import {PackedUserOperation, IEntryPoint} from "./SimpleAccount.sol";

interface IPaymaster {
    enum PostOpMode {
        opSucceeded,
        opReverted,
        postOpReverted
    }

    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        returns (bytes memory context, uint256 validationData);

    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        external;
}

/// @notice Sponsors operations authorized by an EIP-191 signature over the v0.7 paymaster hash.
contract VerifyingPaymaster is IPaymaster {
    IEntryPoint public immutable entryPoint;
    address public immutable owner;
    address public verifyingSigner;

    event VerifyingSignerChanged(address indexed previousSigner, address indexed newSigner);

    constructor(address anEntryPoint, address aVerifyingSigner, address anOwner) {
        require(anEntryPoint != address(0) && aVerifyingSigner != address(0) && anOwner != address(0), "zero address");
        entryPoint = IEntryPoint(anEntryPoint);
        verifyingSigner = aVerifyingSigner;
        owner = anOwner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), "only EntryPoint");
        _;
    }

    function getHash(PackedUserOperation calldata userOp, uint48 validUntil, uint48 validAfter)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.accountGasLimits,
                uint256(bytes32(userOp.paymasterAndData[20:52])),
                userOp.preVerificationGas,
                userOp.gasFees,
                block.chainid,
                address(this),
                validUntil,
                validAfter
            )
        );
    }

    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32, uint256)
        external
        view
        override
        onlyEntryPoint
        returns (bytes memory context, uint256 validationData)
    {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) =
            parsePaymasterAndData(userOp.paymasterAndData);
        bytes32 digest =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", getHash(userOp, validUntil, validAfter)));
        uint256 sigFailed = _recover(digest, signature) == verifyingSigner ? 0 : 1;
        // Zero validUntil means no expiry. The EntryPoint enforces this time window.
        validationData = sigFailed | (uint256(validUntil) << 160) | (uint256(validAfter) << 208);
        return ("", validationData);
    }

    function parsePaymasterAndData(bytes calldata paymasterAndData)
        public
        pure
        returns (uint48 validUntil, uint48 validAfter, bytes calldata signature)
    {
        // 20-byte address, two 16-byte gas limits, two ABI words, then a 64/65-byte signature.
        require(paymasterAndData.length == 180 || paymasterAndData.length == 181, "invalid paymasterAndData length");
        (validUntil, validAfter) = abi.decode(paymasterAndData[52:116], (uint48, uint48));
        signature = paymasterAndData[116:];
    }

    /// @dev Empty validation context tells the EntryPoint that no post-operation callback is needed.
    function postOp(PostOpMode, bytes calldata, uint256, uint256) external view override onlyEntryPoint {}

    function setVerifyingSigner(address newSigner) external onlyOwner {
        require(newSigner != address(0), "zero address");
        emit VerifyingSignerChanged(verifyingSigner, newSigner);
        verifyingSigner = newSigner;
    }

    function deposit() external payable onlyOwner {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    function getDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    function withdrawTo(address payable withdrawAddress, uint256 amount) external onlyOwner {
        entryPoint.withdrawTo(withdrawAddress, amount);
    }

    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        entryPoint.addStake{value: msg.value}(unstakeDelaySec);
    }

    function unlockStake() external onlyOwner {
        entryPoint.unlockStake();
    }

    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        entryPoint.withdrawStake(withdrawAddress);
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        // Length was checked before slicing. Accept EIP-2098 compact signatures as well.
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
        }
        if (signature.length == 64) {
            v = uint8((uint256(s) >> 255) + 27);
            s = bytes32(uint256(s) & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        } else {
            assembly ("memory-safe") {
                v := byte(0, calldataload(add(signature.offset, 64)))
            }
        }
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0 || (v != 27 && v != 28)) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }
}
