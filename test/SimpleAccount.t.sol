// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.24;

import {SimpleAccount, PackedUserOperation, IAccount, IEntryPoint} from "../src/SimpleAccount.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function deal(address account, uint256 balance) external;
    function warp(uint256 timestamp) external;
    function chainId(uint256 newChainId) external;
    function getChainId() external view returns (uint256);
    function expectRevert() external;
    function expectRevert(bytes calldata revertData) external;
    function expectEmit(bool topic1, bool topic2, bool topic3, bool data, address emitter) external;
}

interface TestPaymaster {
    function validatePaymasterUserOp(PackedUserOperation calldata op, bytes32 hash, uint256 maxCost)
        external
        returns (bytes memory context, uint256 validationData);
}

/// @dev A single-op harness, not a production EntryPoint. Uses the v0.7 hash and
/// validation windows, but fixed charges instead of gas metering. No deployment,
/// aggregation, keyed nonces, or nonempty postOp contexts are supported.
contract TestEntryPoint is IEntryPoint {
    uint256 public constant PREFUND = 0.01 ether;
    uint256 public constant ACTUAL_COST = 0.003 ether;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public stakes;
    mapping(address => uint32) public delays;
    mapping(address => uint256) public withdrawTimes;
    uint256 public collected;
    uint256 public lastMissingAccountFunds;
    uint8 public phase; // 1 account validation, 2 paymaster validation, 3 call, 4 refund

    receive() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function depositTo(address account) external payable {
        balanceOf[account] += msg.value;
    }

    function withdrawTo(address payable recipient, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient deposit");
        balanceOf[msg.sender] -= amount;
        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "deposit transfer failed");
    }

    function addStake(uint32 delay) external payable {
        require(delay != 0 && delay >= delays[msg.sender], "invalid stake delay");
        require(stakes[msg.sender] + msg.value != 0, "empty stake");
        stakes[msg.sender] += msg.value;
        delays[msg.sender] = delay;
        withdrawTimes[msg.sender] = 0;
    }

    function unlockStake() external {
        require(stakes[msg.sender] != 0 && withdrawTimes[msg.sender] == 0, "stake not locked");
        withdrawTimes[msg.sender] = block.timestamp + delays[msg.sender];
    }

    function withdrawStake(address payable recipient) external {
        uint256 when = withdrawTimes[msg.sender];
        require(when != 0 && block.timestamp >= when, "stake locked");
        uint256 amount = stakes[msg.sender];
        delete stakes[msg.sender];
        delete delays[msg.sender];
        delete withdrawTimes[msg.sender];
        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "stake transfer failed");
    }

    function getUserOpHash(PackedUserOperation calldata op) public view returns (bytes32) {
        bytes32 packedHash = keccak256(
            abi.encode(
                op.sender,
                op.nonce,
                keccak256(op.initCode),
                keccak256(op.callData),
                op.accountGasLimits,
                op.preVerificationGas,
                op.gasFees,
                keccak256(op.paymasterAndData)
            )
        );
        return keccak256(abi.encode(packedHash, address(this), block.chainid));
    }

    function handleOp(PackedUserOperation calldata op) external returns (bool success, bytes memory result) {
        require(phase == 0, "reentrant operation");
        require(op.initCode.length == 0, "deployment unsupported");
        require(op.sender.code.length != 0, "sender has no code");
        require(op.nonce == nonces[op.sender], "invalid nonce");
        address paymaster;
        if (op.paymasterAndData.length != 0) {
            require(op.paymasterAndData.length >= 52, "short paymaster header");
            paymaster = address(bytes20(op.paymasterAndData[:20]));
            require(paymaster.code.length != 0, "paymaster has no code");
        }
        bytes32 hash = getUserOpHash(op);
        uint256 missing = paymaster == address(0) && balanceOf[op.sender] < PREFUND ? PREFUND - balanceOf[op.sender] : 0;
        lastMissingAccountFunds = missing;
        phase = 1;
        _checkValidation(IAccount(op.sender).validateUserOp(op, hash, missing));
        nonces[op.sender]++;
        address payer = paymaster == address(0) ? op.sender : paymaster;
        require(balanceOf[payer] >= PREFUND, "insufficient prefund");
        balanceOf[payer] -= PREFUND;
        if (paymaster != address(0)) {
            phase = 2;
            (bytes memory context, uint256 data) = TestPaymaster(paymaster).validatePaymasterUserOp(op, hash, PREFUND);
            _checkValidation(data);
            require(context.length == 0, "postOp context unsupported");
        }
        phase = 3;
        (success, result) = op.sender.call(op.callData);
        // A reverted execution still consumes the nonce and pays for gas.
        phase = 4;
        balanceOf[payer] += PREFUND - ACTUAL_COST;
        collected += ACTUAL_COST;
        phase = 0;
    }

    function _checkValidation(uint256 data) private view {
        require(uint160(data) == 0, "signature failed");
        uint48 validUntil = uint48(data >> 160);
        uint48 validAfter = uint48(data >> 208);
        require(block.timestamp >= validAfter, "not yet valid");
        require(validUntil == 0 || block.timestamp <= validUntil, "expired");
    }
}

contract CallTarget {
    error TargetFailure(uint256 code);
    uint256 public count;
    uint256 public received;
    address public lastCaller;

    function increment(uint256 amount) external payable {
        count += amount;
        received += msg.value;
        lastCaller = msg.sender;
    }

    function fail(uint256 code) external payable {
        revert TargetFailure(code);
    }
}

contract RejectEther {
    receive() external payable {
        revert("no ether");
    }
}

abstract contract InlineTestBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant OWNER_KEY = 0xA11CE;
    uint256 internal constant OTHER_KEY = 0xBAD;
    uint256 internal constant CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    TestEntryPoint internal ep;
    SimpleAccount internal account;
    CallTarget internal target;
    address internal owner;
    address internal stranger;

    function _setUpAccount() internal {
        owner = vm.addr(OWNER_KEY);
        stranger = vm.addr(OTHER_KEY);
        ep = new TestEntryPoint();
        account = new SimpleAccount(address(ep), owner);
        target = new CallTarget();
        vm.deal(address(this), 100 ether);
        vm.deal(owner, 100 ether);
        vm.deal(stranger, 100 ether);
        vm.deal(address(account), 2 ether);
        vm.warp(1000);
    }

    function _op() internal view returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.nonce = ep.nonces(address(account));
        op.callData =
            abi.encodeCall(SimpleAccount.execute, (address(target), 0, abi.encodeCall(CallTarget.increment, (1))));
        op.accountGasLimits = bytes32((uint256(300_000) << 128) | 500_000);
        op.preVerificationGas = 50_000;
        op.gasFees = bytes32((uint256(1 gwei) << 128) | 2 gwei);
    }

    function _ethHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function _sign(uint256 key, bytes32 hash) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, _ethHash(hash));
        return abi.encodePacked(r, s, v);
    }

    function _signAccount(PackedUserOperation memory op) internal returns (PackedUserOperation memory) {
        op.signature = _sign(OWNER_KEY, ep.getUserOpHash(op));
        return op;
    }

    function _error(string memory reason) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("Error(string)", reason);
    }
}

contract SimpleAccountTest is InlineTestBase {
    function setUp() public {
        _setUpAccount();
    }

    function _validate(PackedUserOperation memory op, bytes32 hash, uint256 missing) internal returns (uint256) {
        vm.prank(address(ep));
        return account.validateUserOp(op, hash, missing);
    }

    function testConstructorAndZeroAddresses() public {
        require(account.owner() == owner, "owner");
        require(address(account.entryPoint()) == address(ep), "entryPoint");
        vm.expectRevert();
        new SimpleAccount(address(0), owner);
        vm.expectRevert();
        new SimpleAccount(address(ep), address(0));
    }

    function testOwnerSignatureReturnsZeroWithoutUsingNonce() public {
        PackedUserOperation memory op = _signAccount(_op());
        bytes32 hash = ep.getUserOpHash(op);
        require(_validate(op, hash, 0) == 0, "valid signature rejected");
        require(_validate(op, hash, 0) == 0, "account owns nonce");
        require(ep.nonces(address(account)) == 0, "validation consumed nonce");
    }

    function testWrongSignerReturnsOne() public {
        PackedUserOperation memory op = _op();
        bytes32 hash = ep.getUserOpHash(op);
        op.signature = _sign(OTHER_KEY, hash);
        require(_validate(op, hash, 0) == 1, "wrong signer accepted");
    }

    function testRawHashSignatureReturnsOne() public {
        PackedUserOperation memory op = _op();
        bytes32 hash = ep.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, hash);
        op.signature = abi.encodePacked(r, s, v);
        require(_validate(op, hash, 0) == 1, "EIP-191 prefix omitted");
    }

    function testFuzzWrongSignatureLengthsReturnOne(uint16 seed) public {
        uint256 length = uint256(seed) % 513;
        if (length == 65) length = 66;
        PackedUserOperation memory op = _op();
        op.signature = new bytes(length);
        require(_validate(op, ep.getUserOpHash(op), 0) == 1, "malformed signature accepted");
    }

    function testCompactAccountSignatureReturnsOne() public {
        PackedUserOperation memory op = _op();
        bytes32 hash = ep.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, _ethHash(hash));
        op.signature = abi.encodePacked(r, bytes32(uint256(s) | (uint256(v - 27) << 255)));
        require(_validate(op, hash, 0) == 1, "compact account signature accepted");
    }

    function testHighSInvalidVAndZeroRecoveryReturnOne() public {
        PackedUserOperation memory op = _op();
        bytes32 hash = ep.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, _ethHash(hash));
        op.signature = abi.encodePacked(r, bytes32(CURVE_ORDER - uint256(s)), uint8(v == 27 ? 28 : 27));
        require(_validate(op, hash, 0) == 1, "high s accepted");
        op.signature = abi.encodePacked(r, s, uint8(0));
        require(_validate(op, hash, 0) == 1, "invalid v accepted");
        op.signature = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        require(_validate(op, hash, 0) == 1, "zero recovery accepted");
    }

    function testValidateRejectsOwnerAndStranger() public {
        PackedUserOperation memory op = _signAccount(_op());
        bytes32 hash = ep.getUserOpHash(op);
        vm.prank(owner);
        vm.expectRevert();
        account.validateUserOp(op, hash, 0);
        vm.prank(stranger);
        vm.expectRevert();
        account.validateUserOp(op, hash, 1 ether);
        require(address(account).balance == 2 ether, "unauthorized prefund");
    }

    function testFuzzMissingFundsPaidExactly(uint96 seed) public {
        uint256 missing = uint256(seed) % (2 ether + 1);
        PackedUserOperation memory op = _signAccount(_op());
        require(_validate(op, ep.getUserOpHash(op), missing) == 0, "validation");
        require(address(account).balance == 2 ether - missing, "wrong debit");
        require(address(ep).balance == missing, "wrong recipient");
        require(ep.balanceOf(address(account)) == missing, "prefund not credited");
    }

    function testBadSignatureStillAttemptsMissingFundsPayment() public {
        PackedUserOperation memory op = _op();
        require(_validate(op, ep.getUserOpHash(op), 0.1 ether) == 1, "bad signature");
        require(ep.balanceOf(address(account)) == 0.1 ether, "missing payment skipped");
    }

    function testUnsuccessfulMissingFundsPaymentDoesNotRevertValidation() public {
        PackedUserOperation memory op = _signAccount(_op());
        require(_validate(op, ep.getUserOpHash(op), 3 ether) == 0, "insufficient funds reverted");
        require(ep.balanceOf(address(account)) == 0, "unfunded deposit");
        RejectEther rejector = new RejectEther();
        SimpleAccount rejected = new SimpleAccount(address(rejector), owner);
        vm.deal(address(rejected), 1 ether);
        bytes32 hash = keccak256("rejecting entry point");
        op.signature = _sign(OWNER_KEY, hash);
        vm.prank(address(rejector));
        require(rejected.validateUserOp(op, hash, 0.1 ether) == 0, "recipient failure reverted");
        require(address(rejected).balance == 1 ether, "failed transfer debited");
    }

    function testUnsponsoredOperationFundsOnlyShortfallAndRefunds() public {
        account.addDeposit{value: 0.004 ether}();
        PackedUserOperation memory op = _signAccount(_op());
        (bool ok,) = ep.handleOp(op);
        require(ok && target.count() == 1, "execution");
        require(ep.lastMissingAccountFunds() == 0.006 ether, "wrong shortfall");
        require(address(account).balance == 1.994 ether, "wrong prefund");
        require(account.getDeposit() == ep.PREFUND() - ep.ACTUAL_COST(), "wrong refund");
        require(ep.nonces(address(account)) == 1, "nonce not advanced");
    }

    function testPrefundedOperationDoesNotTransferAccountEther() public {
        account.addDeposit{value: 1 ether}();
        PackedUserOperation memory op = _signAccount(_op());
        (bool ok,) = ep.handleOp(op);
        require(ok && ep.lastMissingAccountFunds() == 0, "prefunded validation");
        require(address(account).balance == 2 ether, "unnecessary prefund");
        require(account.getDeposit() == 1 ether - ep.ACTUAL_COST(), "deposit debit");
    }

    function testInvalidSignatureAndInsufficientPrefundRollback() public {
        PackedUserOperation memory op = _op();
        vm.expectRevert(_error("signature failed"));
        ep.handleOp(op);
        require(address(account).balance == 2 ether && account.getDeposit() == 0, "prefund not rolled back");
        vm.deal(address(account), 0);
        op = _signAccount(op);
        vm.expectRevert(_error("insufficient prefund"));
        ep.handleOp(op);
        require(ep.nonces(address(account)) == 0 && target.count() == 0, "failed validation had effects");
    }

    function testReplayFailsOnEntryPointNonce() public {
        PackedUserOperation memory op = _signAccount(_op());
        (bool ok,) = ep.handleOp(op);
        require(ok, "initial op");
        uint256 deposit = account.getDeposit();
        vm.expectRevert(_error("invalid nonce"));
        ep.handleOp(op);
        require(target.count() == 1 && account.getDeposit() == deposit, "replay had effects");
    }

    function testAccountSignatureCannotReplayAcrossChainOrEntryPoint() public {
        PackedUserOperation memory op = _signAccount(_op());
        uint256 chain = vm.getChainId();
        vm.chainId(chain + 1);
        require(_validate(op, ep.getUserOpHash(op), 0) == 1, "cross-chain replay");
        vm.chainId(chain);
        TestEntryPoint otherEP = new TestEntryPoint();
        require(_validate(op, otherEP.getUserOpHash(op), 0) == 1, "cross-EntryPoint replay");
    }

    function testUserOpHashMatchesPackedV07FieldsAndExcludesSignature() public view {
        PackedUserOperation memory op = _op();
        op.initCode = hex"aabbcc";
        op.paymasterAndData = hex"11223344";
        bytes32 expected = keccak256(
            abi.encode(
                keccak256(
                    abi.encode(
                        op.sender,
                        op.nonce,
                        keccak256(op.initCode),
                        keccak256(op.callData),
                        op.accountGasLimits,
                        op.preVerificationGas,
                        op.gasFees,
                        keccak256(op.paymasterAndData)
                    )
                ),
                address(ep),
                block.chainid
            )
        );
        require(ep.getUserOpHash(op) == expected, "v0.7 hash");
        op.signature = hex"abcdef";
        require(ep.getUserOpHash(op) == expected, "signature included in hash");
    }

    function testFuzzEveryPackedFieldIsBoundByAccountSignature(uint8 seed) public {
        PackedUserOperation memory op = _signAccount(_op());
        uint256 field = uint256(seed) % 8;
        if (field == 0) op.sender = stranger;
        else if (field == 1) op.nonce++;
        else if (field == 2) op.initCode = hex"01";
        else if (field == 3) op.callData = hex"02";
        else if (field == 4) op.accountGasLimits = bytes32(uint256(op.accountGasLimits) ^ 1);
        else if (field == 5) op.preVerificationGas++;
        else if (field == 6) op.gasFees = bytes32(uint256(op.gasFees) ^ 1);
        else op.paymasterAndData = hex"03";
        require(_validate(op, ep.getUserOpHash(op), 0) == 1, "unsigned mutation accepted");
    }

    function testOwnerAndEntryPointCanExecuteWithValue() public {
        vm.prank(owner);
        account.execute(address(target), 0.2 ether, abi.encodeCall(CallTarget.increment, (3)));
        vm.prank(address(ep));
        account.execute(address(target), 0.1 ether, abi.encodeCall(CallTarget.increment, (4)));
        require(target.count() == 7 && target.received() == 0.3 ether, "execution values");
        require(target.lastCaller() == address(account), "wrong caller");
    }

    function testStrangerCannotExecuteOrExecuteBatch() public {
        vm.prank(stranger);
        vm.expectRevert();
        account.execute(stranger, 1 ether, "");
        vm.prank(stranger);
        vm.expectRevert();
        account.executeBatch(new address[](0), new uint256[](0), new bytes[](0));
        require(address(account).balance == 2 ether, "unauthorized execution");
    }

    function testExecuteBubblesExactRevertData() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(CallTarget.TargetFailure.selector, 42));
        account.execute(address(target), 0.2 ether, abi.encodeCall(CallTarget.fail, (42)));
        require(address(account).balance == 2 ether, "reverted value retained");
    }

    function _batch() internal view returns (address[] memory dest, bytes[] memory data) {
        dest = new address[](2);
        data = new bytes[](2);
        dest[0] = address(target);
        dest[1] = address(target);
        data[0] = abi.encodeCall(CallTarget.increment, (2));
        data[1] = abi.encodeCall(CallTarget.increment, (3));
    }

    function testBatchEmptyValueArrayMeansZeroAndEmptyBatchSucceeds() public {
        (address[] memory dest, bytes[] memory data) = _batch();
        vm.prank(owner);
        account.executeBatch(dest, new uint256[](0), data);
        vm.prank(address(ep));
        account.executeBatch(new address[](0), new uint256[](0), new bytes[](0));
        require(target.count() == 5 && target.received() == 0, "zero-value batch");
    }

    function testEntryPointBatchForwardsEachValue() public {
        (address[] memory dest, bytes[] memory data) = _batch();
        uint256[] memory values = new uint256[](2);
        values[0] = 0.1 ether;
        values[1] = 0.2 ether;
        vm.prank(address(ep));
        account.executeBatch(dest, values, data);
        require(target.count() == 5 && target.received() == 0.3 ether, "batch values");
        require(address(account).balance == 1.7 ether, "batch debit");
    }

    function testBatchMismatchedLengthsRevertBeforeAnyCall() public {
        (address[] memory dest, bytes[] memory data) = _batch();
        vm.prank(owner);
        vm.expectRevert();
        account.executeBatch(dest, new uint256[](1), data);
        vm.prank(owner);
        vm.expectRevert();
        account.executeBatch(dest, new uint256[](3), data);
        vm.prank(owner);
        vm.expectRevert();
        account.executeBatch(dest, new uint256[](0), new bytes[](1));
        vm.prank(owner);
        vm.expectRevert();
        account.executeBatch(new address[](0), new uint256[](1), new bytes[](0));
        require(target.count() == 0, "partial mismatched batch");
    }

    function testBatchRevertsAllStateAndValueAndBubblesReason() public {
        (address[] memory dest, bytes[] memory data) = _batch();
        uint256[] memory values = new uint256[](2);
        values[0] = 0.1 ether;
        values[1] = 0.2 ether;
        data[1] = abi.encodeCall(CallTarget.fail, (99));
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(CallTarget.TargetFailure.selector, 99));
        account.executeBatch(dest, values, data);
        require(target.count() == 0 && address(target).balance == 0, "partial batch committed");
        require(address(account).balance == 2 ether, "batch value not restored");
    }

    function testAnyoneCanReceiveAndDepositButOnlyOwnerWithdraws() public {
        vm.prank(stranger);
        (bool ok,) = address(account).call{value: 0.5 ether}("");
        require(ok && address(account).balance == 2.5 ether, "receive");
        vm.prank(stranger);
        account.addDeposit{value: 0.4 ether}();
        require(account.getDeposit() == 0.4 ether && address(account).balance == 2.5 ether, "deposit");
        vm.prank(stranger);
        vm.expectRevert();
        account.withdrawDepositTo(payable(stranger), 0.1 ether);
        vm.prank(address(ep));
        vm.expectRevert();
        account.withdrawDepositTo(payable(stranger), 0.1 ether);
        uint256 beforeBalance = stranger.balance;
        vm.prank(owner);
        account.withdrawDepositTo(payable(stranger), 0.1 ether);
        require(stranger.balance == beforeBalance + 0.1 ether && account.getDeposit() == 0.3 ether, "withdraw");
        vm.prank(owner);
        vm.expectRevert();
        account.withdrawDepositTo(payable(stranger), 0.4 ether);
        RejectEther rejector = new RejectEther();
        vm.prank(owner);
        vm.expectRevert();
        account.withdrawDepositTo(payable(address(rejector)), 0.1 ether);
        require(account.getDeposit() == 0.3 ether, "failed withdrawal lost deposit");
    }
}
