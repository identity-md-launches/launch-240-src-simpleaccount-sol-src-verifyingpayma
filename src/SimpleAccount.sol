// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.24;

struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

interface IAccount {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData);
}

/// @dev The deposit and stake subset of the ERC-4337 v0.7 EntryPoint interface.
interface IEntryPoint {
    function balanceOf(address account) external view returns (uint256);
    function depositTo(address account) external payable;
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;
    function addStake(uint32 unstakeDelaySec) external payable;
    function unlockStake() external;
    function withdrawStake(address payable withdrawAddress) external;
}

/// @notice A fixed-owner account whose nonce and user-operation domain are managed by its EntryPoint.
contract SimpleAccount is IAccount {
    IEntryPoint public immutable entryPoint;
    address public immutable owner;

    constructor(address anEntryPoint, address anOwner) {
        require(anEntryPoint != address(0) && anOwner != address(0), "zero address");
        entryPoint = IEntryPoint(anEntryPoint);
        owner = anOwner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    modifier onlyEntryPointOrOwner() {
        require(msg.sender == address(entryPoint) || msg.sender == owner, "only EntryPoint or owner");
        _;
    }

    receive() external payable {}

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        override
        returns (uint256 validationData)
    {
        require(msg.sender == address(entryPoint), "only EntryPoint");
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        validationData = _recover(digest, userOp.signature) == owner ? 0 : 1;

        if (missingAccountFunds != 0) {
            // As in BaseAccount v0.7, the EntryPoint checks whether the prefund arrived.
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (success);
        }
    }

    function execute(address dest, uint256 value, bytes calldata func) external onlyEntryPointOrOwner {
        _call(dest, value, func);
    }

    function executeBatch(address[] calldata dest, uint256[] calldata value, bytes[] calldata func)
        external
        onlyEntryPointOrOwner
    {
        require(dest.length == func.length && (value.length == 0 || value.length == dest.length), "wrong array lengths");
        for (uint256 i; i < dest.length; ++i) {
            _call(dest[i], value.length == 0 ? 0 : value[i], func[i]);
        }
    }

    function addDeposit() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    function getDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) external onlyOwner {
        entryPoint.withdrawTo(withdrawAddress, amount);
    }

    function _call(address dest, uint256 value, bytes calldata func) private {
        (bool success, bytes memory result) = dest.call{value: value}(func);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        // Only canonical, low-s signatures are accepted; malformed signatures return failure.
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0 || (v != 27 && v != 28)) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }
}
