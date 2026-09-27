// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.24;

import {VerifyingPaymaster, IPaymaster} from "../src/VerifyingPaymaster.sol";
import {SimpleAccount, PackedUserOperation} from "../src/SimpleAccount.sol";
import {TestEntryPoint, InlineTestBase, CallTarget, RejectEther} from "./SimpleAccount.t.sol";

contract RefundObserver {
    uint256 public calls;

    function observe(TestEntryPoint ep, address payer, uint256 expectedDeposit, address sender) external {
        require(ep.phase() == 3, "call before validation");
        require(ep.nonces(sender) == 1, "nonce not consumed before call");
        require(ep.balanceOf(payer) == expectedDeposit, "refund preceded call");
        require(ep.lastMissingAccountFunds() == 0, "sponsored account prefunded");
        calls++;
    }
}

contract VerifyingPaymasterTest is InlineTestBase {
    uint256 internal constant SIGNER_KEY = 0xCAFE;
    uint256 internal constant PM_OWNER_KEY = 0xB0B;
    uint128 internal constant VERIFICATION_GAS = 123_456;
    uint128 internal constant POST_OP_GAS = 654_321;
    VerifyingPaymaster internal paymaster;
    address internal signer;
    address internal paymasterOwner;

    event VerifyingSignerChanged(address indexed previousSigner, address indexed newSigner);

    function setUp() public {
        _setUpAccount();
        signer = vm.addr(SIGNER_KEY);
        paymasterOwner = vm.addr(PM_OWNER_KEY);
        vm.deal(paymasterOwner, 100 ether);
        paymaster = new VerifyingPaymaster(address(ep), signer, paymasterOwner);
        vm.prank(paymasterOwner);
        paymaster.deposit{value: 1 ether}();
    }

    function _header(address sponsor, uint48 until, uint48 afterTime) internal pure returns (bytes memory) {
        return abi.encodePacked(sponsor, VERIFICATION_GAS, POST_OP_GAS, abi.encode(until, afterTime));
    }

    // Independent signing oracle: deliberately never uses the implementation's getHash.
    function _expectedHash(PackedUserOperation memory op, address sponsor, uint48 until, uint48 afterTime)
        internal
        view
        returns (bytes32)
    {
        bytes memory data = op.paymasterAndData;
        bytes32 gasWord;
        assembly ("memory-safe") { gasWord := mload(add(data, 52)) }
        return keccak256(
            abi.encode(
                op.sender,
                op.nonce,
                keccak256(op.initCode),
                keccak256(op.callData),
                op.accountGasLimits,
                uint256(gasWord),
                op.preVerificationGas,
                op.gasFees,
                block.chainid,
                sponsor,
                until,
                afterTime
            )
        );
    }

    function _sponsor(
        PackedUserOperation memory op,
        address sponsor,
        uint48 until,
        uint48 afterTime,
        uint256 key,
        bool compact
    ) internal returns (PackedUserOperation memory) {
        op.paymasterAndData = _header(sponsor, until, afterTime);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, _ethHash(_expectedHash(op, sponsor, until, afterTime)));
        bytes memory signature =
            compact ? abi.encodePacked(r, bytes32(uint256(s) | (uint256(v - 27) << 255))) : abi.encodePacked(r, s, v);
        op.paymasterAndData = bytes.concat(op.paymasterAndData, signature);
        return _signAccount(op);
    }

    function _sponsored(uint48 until, uint48 afterTime, bool compact) internal returns (PackedUserOperation memory) {
        return _sponsor(_op(), address(paymaster), until, afterTime, SIGNER_KEY, compact);
    }

    function _validation(PackedUserOperation memory op) internal returns (bytes memory, uint256) {
        bytes32 hash = ep.getUserOpHash(op);
        uint256 cost = ep.PREFUND();
        vm.prank(address(ep));
        return paymaster.validatePaymasterUserOp(op, hash, cost);
    }

    function _assertValidation(PackedUserOperation memory op, uint256 expected) internal {
        (bytes memory context, uint256 data) = _validation(op);
        require(context.length == 0, "nonempty context");
        require(data == expected, "wrong validation data");
    }

    function _window(uint48 until, uint48 afterTime) internal pure returns (uint256) {
        return (uint256(until) << 160) | (uint256(afterTime) << 208);
    }

    function _assertRejectedUnchanged(PackedUserOperation memory op, string memory reason) internal {
        uint256 deposit = paymaster.getDeposit();
        uint256 nonce = ep.nonces(op.sender);
        uint256 senderBalance = op.sender.balance;
        uint256 epBalance = address(ep).balance;
        uint256 count = target.count();
        uint256 fees = ep.collected();
        vm.expectRevert(_error(reason));
        ep.handleOp(op);
        require(paymaster.getDeposit() == deposit, "invalid op spent sponsor deposit");
        require(ep.nonces(op.sender) == nonce, "invalid op consumed nonce");
        require(op.sender.balance == senderBalance && address(ep).balance == epBalance, "invalid op moved ether");
        require(target.count() == count && ep.collected() == fees, "invalid op had effects");
    }

    function testConstructorAndZeroAddresses() public {
        require(address(paymaster.entryPoint()) == address(ep), "entryPoint");
        require(paymaster.owner() == paymasterOwner && paymaster.verifyingSigner() == signer, "roles");
        vm.expectRevert();
        new VerifyingPaymaster(address(0), signer, paymasterOwner);
        vm.expectRevert();
        new VerifyingPaymaster(address(ep), address(0), paymasterOwner);
        vm.expectRevert();
        new VerifyingPaymaster(address(ep), signer, address(0));
    }

    function testSponsoredOperationEndToEndWithUnfundedAccount() public {
        vm.deal(address(account), 0);
        PackedUserOperation memory op = _sponsored(2000, 900, false);
        _assertValidation(op, _window(2000, 900));
        (bool ok, bytes memory result) = ep.handleOp(op);
        require(ok && result.length == 0 && target.count() == 1, "sponsored execution");
        require(target.lastCaller() == address(account), "call bypassed account");
        require(ep.nonces(address(account)) == 1, "nonce");
        require(paymaster.getDeposit() == 1 ether - ep.ACTUAL_COST(), "sponsor net charge");
        require(ep.collected() == ep.ACTUAL_COST(), "fee accounting");
        require(ep.balanceOf(address(account)) == 0 && address(account).balance == 0, "account charged");
        require(address(ep).balance == paymaster.getDeposit() + ep.collected(), "ether conservation");
    }

    function testCompactSignatureWorksEndToEnd() public {
        PackedUserOperation memory op = _sponsored(0, 0, true);
        require(op.paymasterAndData.length == 180, "compact length");
        _assertValidation(op, 0);
        (bool ok,) = ep.handleOp(op);
        require(ok && target.count() == 1, "compact signature failed");
    }

    function testRefundFollowsValidationAndExecution() public {
        RefundObserver observer = new RefundObserver();
        PackedUserOperation memory op = _op();
        op.callData = abi.encodeCall(
            SimpleAccount.execute,
            (
                address(observer),
                0,
                abi.encodeCall(
                    RefundObserver.observe, (ep, address(paymaster), 1 ether - ep.PREFUND(), address(account))
                )
            )
        );
        op = _sponsor(op, address(paymaster), 0, 0, SIGNER_KEY, false);
        (bool ok,) = ep.handleOp(op);
        require(ok && observer.calls() == 1, "execution order");
        require(paymaster.getDeposit() == 1 ether - ep.ACTUAL_COST(), "refund missing");
    }

    function testHashAndParsingUseExactV07Offsets() public {
        uint48 until = 0x010203040506;
        uint48 afterTime = 0x0708090a0b0c;
        PackedUserOperation memory op = _sponsored(until, afterTime, false);
        require(op.paymasterAndData.length == 181, "standard length");
        bytes32 expected = keccak256(
            abi.encode(
                op.sender,
                op.nonce,
                keccak256(op.initCode),
                keccak256(op.callData),
                op.accountGasLimits,
                (uint256(VERIFICATION_GAS) << 128) | uint256(POST_OP_GAS),
                op.preVerificationGas,
                op.gasFees,
                block.chainid,
                address(paymaster),
                until,
                afterTime
            )
        );
        require(paymaster.getHash(op, until, afterTime) == expected, "hash layout");
        (uint48 parsedUntil, uint48 parsedAfter, bytes memory signature) =
            paymaster.parsePaymasterAndData(op.paymasterAndData);
        require(parsedUntil == until && parsedAfter == afterTime && signature.length == 65, "offsets");
        require(keccak256(signature) == keccak256(_sign(SIGNER_KEY, expected)), "signature offset");
        _assertValidation(op, _window(until, afterTime));
    }

    function testFuzzPackedValidationData(uint48 until, uint48 afterTime, bool compact) public {
        PackedUserOperation memory op = _sponsored(until, afterTime, compact);
        _assertValidation(op, _window(until, afterTime));
        op = _sponsor(_op(), address(paymaster), until, afterTime, OTHER_KEY, compact);
        _assertValidation(op, _window(until, afterTime) | 1);
    }

    function testHashExcludesBothSignaturesAndIncludesDynamicFieldHashes() public {
        PackedUserOperation memory op = _op();
        op.initCode = hex"1122334455";
        op.callData = hex"aabbccddeeff";
        op = _sponsor(op, address(paymaster), 2000, 900, SIGNER_KEY, false);
        bytes32 expected = _expectedHash(op, address(paymaster), 2000, 900);
        require(paymaster.getHash(op, 2000, 900) == expected, "dynamic hash encoding");
        op.signature = hex"123456";
        op.paymasterAndData[116] = bytes1(uint8(op.paymasterAndData[116]) ^ 1);
        require(paymaster.getHash(op, 2000, 900) == expected, "signature included");
        op.paymasterAndData = bytes.concat(_header(address(paymaster), 2000, 900), new bytes(64));
        require(paymaster.getHash(op, 2000, 900) == expected, "signature length included");
    }

    function testWrongSignerReturnsFailureAndCannotSpendDeposit() public {
        PackedUserOperation memory op = _sponsor(_op(), address(paymaster), 2000, 900, OTHER_KEY, false);
        _assertValidation(op, _window(2000, 900) | 1);
        _assertRejectedUnchanged(op, "signature failed");
    }

    function testAccountFailureCannotSpendValidSponsorDeposit() public {
        PackedUserOperation memory op = _sponsored(0, 0, false);
        op.signature = _sign(OTHER_KEY, ep.getUserOpHash(op));
        _assertValidation(op, 0);
        _assertRejectedUnchanged(op, "signature failed");
    }

    function testSignatureForAnotherChainFailsEvenWithFreshAccountSignature() public {
        uint256 originalChain = vm.getChainId();
        vm.chainId(originalChain + 1);
        PackedUserOperation memory op = _sponsored(0, 0, false);
        vm.chainId(originalChain);
        op = _signAccount(op);
        _assertValidation(op, 1);
        _assertRejectedUnchanged(op, "signature failed");
    }

    function testSignatureForAnotherPaymasterFailsWithSameSignerAndEntryPoint() public {
        VerifyingPaymaster other = new VerifyingPaymaster(address(ep), signer, paymasterOwner);
        PackedUserOperation memory op = _sponsor(_op(), address(other), 0, 0, SIGNER_KEY, false);
        (,, bytes memory signature) = other.parsePaymasterAndData(op.paymasterAndData);
        // Replace the routing address as an attacker would, retaining the signature.
        op.paymasterAndData = bytes.concat(_header(address(paymaster), 0, 0), signature);
        op = _signAccount(op);
        _assertValidation(op, 1);
        _assertRejectedUnchanged(op, "signature failed");
    }

    function testSignatureForAnotherSenderFailsWithSameAccountOwner() public {
        PackedUserOperation memory op = _sponsored(0, 0, false);
        SimpleAccount other = new SimpleAccount(address(ep), owner);
        op.sender = address(other);
        op = _signAccount(op);
        _assertValidation(op, 1);
        _assertRejectedUnchanged(op, "signature failed");
    }

    function testSignatureForAnotherNonceFailsAtCurrentValidNonce() public {
        PackedUserOperation memory op = _op();
        op.nonce = 1;
        op = _sponsor(op, address(paymaster), 0, 0, SIGNER_KEY, false);
        op.nonce = 0; // EntryPoint accepts zero; only the sponsor signature should fail.
        op = _signAccount(op);
        _assertValidation(op, 1);
        _assertRejectedUnchanged(op, "signature failed");
    }

    function testEveryOperationFieldIsBoundBySponsorSignature() public {
        for (uint256 field; field < 10; ++field) {
            PackedUserOperation memory op = _sponsored(0, 0, false);
            if (field == 0) op.initCode = hex"01";
            else if (field == 1) op.callData = abi.encodeCall(SimpleAccount.execute, (stranger, 1 ether, bytes("")));
            else if (field == 2) op.accountGasLimits = bytes32(uint256(op.accountGasLimits) ^ (uint256(1) << 128));
            else if (field == 3) op.accountGasLimits = bytes32(uint256(op.accountGasLimits) ^ 1);
            else if (field == 4) op.preVerificationGas++;
            else if (field == 5) op.gasFees = bytes32(uint256(op.gasFees) ^ (uint256(1) << 128));
            else if (field == 6) op.gasFees = bytes32(uint256(op.gasFees) ^ 1);
            else if (field == 7) op.paymasterAndData[20] = bytes1(uint8(op.paymasterAndData[20]) ^ 1);
            else if (field == 8) op.paymasterAndData[36] = bytes1(uint8(op.paymasterAndData[36]) ^ 1);
            else op.paymasterAndData[51] = bytes1(uint8(op.paymasterAndData[51]) ^ 1);
            op = _signAccount(op);
            _assertValidation(op, 1);
            // The harness intentionally does not implement account deployment.
            if (field != 0) _assertRejectedUnchanged(op, "signature failed");
        }
    }

    function testChangingEitherTimeWordInvalidatesSignature() public {
        PackedUserOperation memory op = _sponsored(2000, 900, false);
        (,, bytes memory signature) = paymaster.parsePaymasterAndData(op.paymasterAndData);
        op.paymasterAndData = bytes.concat(_header(address(paymaster), 2001, 900), signature);
        op = _signAccount(op);
        _assertValidation(op, _window(2001, 900) | 1);
        _assertRejectedUnchanged(op, "signature failed");
        op.paymasterAndData = bytes.concat(_header(address(paymaster), 2000, 901), signature);
        op = _signAccount(op);
        _assertValidation(op, _window(2000, 901) | 1);
        _assertRejectedUnchanged(op, "signature failed");
    }

    function testValidityWindowIncludesBothBoundariesAndRejectsOutside() public {
        PackedUserOperation memory op = _sponsored(1100, 1000, false);
        vm.warp(999);
        _assertValidation(op, _window(1100, 1000));
        _assertRejectedUnchanged(op, "not yet valid");
        vm.warp(1000);
        (bool first,) = ep.handleOp(op);
        require(first, "validAfter boundary");
        op = _sponsored(1100, 1000, false);
        vm.warp(1100);
        (bool second,) = ep.handleOp(op);
        require(second, "validUntil boundary");
        op = _sponsored(1100, 1000, false);
        vm.warp(1101);
        _assertRejectedUnchanged(op, "expired");
        require(target.count() == 2, "window executions");
    }

    function testZeroValidUntilHasNoExpiryButStillHonorsValidAfter() public {
        PackedUserOperation memory op = _sponsored(0, 1001, true);
        _assertRejectedUnchanged(op, "not yet valid");
        vm.warp(type(uint48).max);
        (bool ok,) = ep.handleOp(op);
        require(ok && target.count() == 1, "zero expiry expired");
    }

    function testInvertedWindowCannotExecute() public {
        PackedUserOperation memory op = _sponsored(999, 1001, false);
        _assertValidation(op, _window(999, 1001));
        _assertRejectedUnchanged(op, "not yet valid");
        vm.warp(1001);
        _assertRejectedUnchanged(op, "expired");
    }

    function testSponsoredReplayFailsOnNonceAndCannotChargeAgain() public {
        PackedUserOperation memory op = _sponsored(0, 0, false);
        (bool ok,) = ep.handleOp(op);
        require(ok, "first execution");
        _assertRejectedUnchanged(op, "invalid nonce");
        require(target.count() == 1, "replayed execution");
    }

    function testMalformedSignaturesOfValidLengthReturnFailure() public {
        PackedUserOperation memory op = _sponsored(2000, 900, false);
        bytes32 digest = _ethHash(_expectedHash(op, address(paymaster), 2000, 900));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        bytes memory header = _header(address(paymaster), 2000, 900);
        op.paymasterAndData =
            bytes.concat(header, abi.encodePacked(r, bytes32(CURVE_ORDER - uint256(s)), uint8(v == 27 ? 28 : 27)));
        _assertValidation(op, _window(2000, 900) | 1);
        op.paymasterAndData = bytes.concat(header, abi.encodePacked(r, s, uint8(29)));
        _assertValidation(op, _window(2000, 900) | 1);
        op.paymasterAndData = bytes.concat(header, abi.encodePacked(bytes32(0), bytes32(0), uint8(27)));
        _assertValidation(op, _window(2000, 900) | 1);
        op.paymasterAndData = bytes.concat(header, new bytes(64));
        _assertValidation(op, _window(2000, 900) | 1);
        // Compact s has its top bit masked; the remaining value can still be noncanonical.
        op.paymasterAndData = bytes.concat(
            header,
            abi.encodePacked(r, bytes32(uint256(0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1)))
        );
        _assertValidation(op, _window(2000, 900) | 1);
    }

    function testUnprefixedPaymasterSignatureFails() public {
        PackedUserOperation memory op = _sponsored(0, 0, false);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, _expectedHash(op, address(paymaster), 0, 0));
        op.paymasterAndData = bytes.concat(_header(address(paymaster), 0, 0), abi.encodePacked(r, s, v));
        op = _signAccount(op);
        _assertValidation(op, 1);
        _assertRejectedUnchanged(op, "signature failed");
    }

    function testFuzzOtherPaymasterDataLengthsRevert(uint16 seed) public {
        uint256 length = uint256(seed) % 513;
        if (length == 180 || length == 181) length = 182;
        PackedUserOperation memory op = _op();
        op.paymasterAndData = new bytes(length);
        bytes32 hash = ep.getUserOpHash(op);
        vm.prank(address(ep));
        vm.expectRevert();
        paymaster.validatePaymasterUserOp(op, hash, 0);
    }

    function testTruncatedAndTrailingSignatureBytesCannotSpendDeposit() public {
        PackedUserOperation memory op = _sponsored(0, 0, false);
        op.paymasterAndData = bytes.concat(op.paymasterAndData, hex"00");
        op = _signAccount(op);
        _assertRejectedUnchanged(op, "invalid paymasterAndData length");
        op.paymasterAndData = bytes.concat(_header(address(paymaster), 0, 0), new bytes(63));
        op = _signAccount(op);
        _assertRejectedUnchanged(op, "invalid paymasterAndData length");
    }

    function testNonCanonicalUint48TimeEncodingReverts() public {
        PackedUserOperation memory op = _sponsored(0, 0, false);
        op.paymasterAndData[52] = 0x01; // High bits outside uint48 in the first ABI word.
        bytes32 hash = ep.getUserOpHash(op);
        vm.prank(address(ep));
        vm.expectRevert();
        paymaster.validatePaymasterUserOp(op, hash, 0);
        op.paymasterAndData[52] = 0;
        op.paymasterAndData[84] = 0x01; // Likewise for validAfter.
        hash = ep.getUserOpHash(op);
        vm.prank(address(ep));
        vm.expectRevert();
        paymaster.validatePaymasterUserOp(op, hash, 0);
    }

    function testValidateRejectsOwnerSignerAndStranger() public {
        PackedUserOperation memory op = _sponsored(0, 0, false);
        bytes32 hash = ep.getUserOpHash(op);
        address[3] memory callers = [paymasterOwner, signer, stranger];
        for (uint256 i; i < callers.length; ++i) {
            vm.prank(callers[i]);
            vm.expectRevert();
            paymaster.validatePaymasterUserOp(op, hash, 0);
        }
    }

    function testRevertedSponsoredExecutionChargesOnceAndRollsBackBatch() public {
        address[] memory dest = new address[](2);
        dest[0] = address(target);
        dest[1] = address(target);
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(CallTarget.increment, (10));
        calls[1] = abi.encodeCall(CallTarget.fail, (123));
        uint256[] memory values = new uint256[](2);
        values[0] = 0.2 ether;
        PackedUserOperation memory op = _op();
        op.callData = abi.encodeCall(SimpleAccount.executeBatch, (dest, values, calls));
        op = _sponsor(op, address(paymaster), 0, 0, SIGNER_KEY, false);
        (bool ok, bytes memory result) = ep.handleOp(op);
        require(!ok, "reverted execution marked successful");
        require(
            keccak256(result) == keccak256(abi.encodeWithSelector(CallTarget.TargetFailure.selector, 123)),
            "lost revert data"
        );
        require(target.count() == 0 && address(target).balance == 0, "partial batch state");
        require(address(account).balance == 2 ether, "partial batch value");
        require(ep.nonces(address(account)) == 1, "revert did not consume nonce");
        require(paymaster.getDeposit() == 1 ether - ep.ACTUAL_COST(), "revert refund");
        _assertRejectedUnchanged(op, "invalid nonce");
    }

    function testSponsoredCallCannotWithdrawPaymasterDeposit() public {
        PackedUserOperation memory op = _op();
        op.callData = abi.encodeCall(
            SimpleAccount.execute,
            (address(paymaster), 0, abi.encodeCall(VerifyingPaymaster.withdrawTo, (payable(stranger), 0.5 ether)))
        );
        op = _sponsor(op, address(paymaster), 0, 0, SIGNER_KEY, false);
        uint256 beforeBalance = stranger.balance;
        (bool ok,) = ep.handleOp(op);
        require(!ok, "account withdrew paymaster deposit");
        require(stranger.balance == beforeBalance, "deposit stolen");
        require(paymaster.getDeposit() == 1 ether - ep.ACTUAL_COST(), "more than gas charged");
    }

    function testSponsoredValueTransferUsesAccountFunds() public {
        PackedUserOperation memory op = _op();
        op.callData = abi.encodeCall(
            SimpleAccount.execute, (address(target), 0.2 ether, abi.encodeCall(CallTarget.increment, (1)))
        );
        op = _sponsor(op, address(paymaster), 0, 0, SIGNER_KEY, false);
        (bool ok,) = ep.handleOp(op);
        require(ok && target.received() == 0.2 ether, "value transfer");
        require(address(account).balance == 1.8 ether, "account value debit");
        require(paymaster.getDeposit() == 1 ether - ep.ACTUAL_COST(), "paymaster paid call value");
    }

    function testInsufficientSponsorDepositDoesNotFallBackToAccountFunds() public {
        vm.prank(paymasterOwner);
        paymaster.withdrawTo(payable(paymasterOwner), 1 ether);
        PackedUserOperation memory op = _sponsored(0, 0, false);
        _assertRejectedUnchanged(op, "insufficient prefund");
        require(account.getDeposit() == 0 && address(account).balance == 2 ether, "account subsidized sponsor");
    }

    function testSignerRotationEmitsEventAndRevokesOldSignatures() public {
        PackedUserOperation memory oldOp = _sponsored(0, 0, false);
        vm.expectEmit(true, true, false, true, address(paymaster));
        emit VerifyingSignerChanged(signer, stranger);
        vm.prank(paymasterOwner);
        paymaster.setVerifyingSigner(stranger);
        require(paymaster.verifyingSigner() == stranger, "rotation failed");
        _assertValidation(oldOp, 1);
        _assertRejectedUnchanged(oldOp, "signature failed");
        PackedUserOperation memory newOp = _sponsor(_op(), address(paymaster), 0, 0, OTHER_KEY, false);
        _assertValidation(newOp, 0);
        (bool ok,) = ep.handleOp(newOp);
        require(ok, "new signer rejected");
        vm.prank(paymasterOwner);
        vm.expectRevert();
        paymaster.setVerifyingSigner(address(0));
        require(paymaster.verifyingSigner() == stranger, "zero signer installed");
    }

    function testOwnerOnlyManagementRejectsStrangerSignerAndEntryPoint() public {
        address[3] memory callers = [stranger, signer, address(ep)];
        for (uint256 i; i < callers.length; ++i) {
            vm.prank(callers[i]);
            vm.expectRevert();
            paymaster.setVerifyingSigner(stranger);
            vm.prank(callers[i]);
            vm.expectRevert();
            paymaster.deposit();
            vm.prank(callers[i]);
            vm.expectRevert();
            paymaster.withdrawTo(payable(stranger), 1);
            vm.prank(callers[i]);
            vm.expectRevert();
            paymaster.addStake(1);
            vm.prank(callers[i]);
            vm.expectRevert();
            paymaster.unlockStake();
            vm.prank(callers[i]);
            vm.expectRevert();
            paymaster.withdrawStake(payable(stranger));
        }
        require(paymaster.getDeposit() == 1 ether && paymaster.verifyingSigner() == signer, "unauthorized management");
    }

    function testOwnerDepositAndWithdrawalForwardExactAmounts() public {
        vm.prank(paymasterOwner);
        paymaster.deposit{value: 0.4 ether}();
        require(paymaster.getDeposit() == 1.4 ether && address(paymaster).balance == 0, "deposit forwarding");
        uint256 beforeBalance = stranger.balance;
        vm.prank(paymasterOwner);
        paymaster.withdrawTo(payable(stranger), 0.2 ether);
        require(
            paymaster.getDeposit() == 1.2 ether && stranger.balance == beforeBalance + 0.2 ether, "withdraw forwarding"
        );
        vm.prank(paymasterOwner);
        vm.expectRevert();
        paymaster.withdrawTo(payable(stranger), 2 ether);
        RejectEther rejector = new RejectEther();
        vm.prank(paymasterOwner);
        vm.expectRevert();
        paymaster.withdrawTo(payable(address(rejector)), 0.1 ether);
        require(paymaster.getDeposit() == 1.2 ether, "failed withdrawal lost deposit");
    }

    function testStakeLifecycleForwardsValueDelayAndRecipient() public {
        vm.prank(paymasterOwner);
        paymaster.addStake{value: 0.5 ether}(100);
        require(ep.stakes(address(paymaster)) == 0.5 ether && ep.delays(address(paymaster)) == 100, "stake forwarding");
        require(paymaster.getDeposit() == 1 ether, "stake mixed with deposit");
        vm.prank(paymasterOwner);
        vm.expectRevert();
        paymaster.withdrawStake(payable(stranger));
        vm.prank(paymasterOwner);
        paymaster.unlockStake();
        require(ep.withdrawTimes(address(paymaster)) == 1100, "unlock forwarding");
        vm.warp(1099);
        vm.prank(paymasterOwner);
        vm.expectRevert();
        paymaster.withdrawStake(payable(stranger));
        vm.warp(1100);
        uint256 beforeBalance = stranger.balance;
        vm.prank(paymasterOwner);
        paymaster.withdrawStake(payable(stranger));
        require(stranger.balance == beforeBalance + 0.5 ether && ep.stakes(address(paymaster)) == 0, "stake withdrawal");
        require(paymaster.getDeposit() == 1 ether, "stake withdrawal touched deposit");
    }

    function testPostOpHasNoLogicAndOnlyEntryPointCanCall() public {
        uint256 deposit = paymaster.getDeposit();
        for (uint256 mode; mode < 3; ++mode) {
            vm.prank(address(ep));
            paymaster.postOp(IPaymaster.PostOpMode(mode), hex"1234", 1 ether, 2 gwei);
        }
        require(paymaster.getDeposit() == deposit && paymaster.verifyingSigner() == signer, "postOp state change");
        vm.prank(stranger);
        vm.expectRevert();
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, "", 0, 0);
    }
}
