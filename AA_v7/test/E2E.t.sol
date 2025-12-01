// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../src/SmartUserAccount.sol";
import "../src/AccountFactory.sol";
import "../src/PayMaster.sol";
import { IEntryPoint } from "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { EntryPoint } from "../lib/account-abstraction/contracts/core/EntryPoint.sol";
import { PackedUserOperation } from "../lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ERC20Mock } from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title End-to-End ERC-4337 Flow Test
 * @notice Tests complete user operation flow from creation to execution
 */
contract E2ETest is Test {
    using MessageHashUtils for bytes32;
    using ECDSA for bytes32;

    // Core contracts
    AccountFactory public factory;
    PayMaster public paymaster;
    SmartUserAccount public account;
    IEntryPoint public entryPoint;
    ERC20Mock public usdt;
    
    // Actors
    address public factoryOwner;
    address public paymasterOwner;
    address public feeRecipient;
    address public bundler;
    address public alice;
    address public bob;
    address public charlie;
    
    // Keys
    uint256 public alicePrivateKey;
    uint256 public paymasterSignerPrivateKey;
    address public paymasterSigner;
    
    // Events to track
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );
    
    event FeeCollected(address indexed token, uint256 amount, address indexed recipient);
    event GasSponsored(address indexed user, uint256 actualGasCost);

    function setUp() public {
        // Setup actors
        factoryOwner = makeAddr("factoryOwner");
        paymasterOwner = makeAddr("paymasterOwner");
        feeRecipient = makeAddr("feeRecipient");
        bundler = makeAddr("bundler");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");
        
        // Setup Alice with private key
        alicePrivateKey = 0xA11CE;
        alice = vm.addr(alicePrivateKey);
        
        // Setup paymaster signer
        paymasterSignerPrivateKey = 0xB0B;
        paymasterSigner = vm.addr(paymasterSignerPrivateKey);
        
        // Deploy mock EntryPoint
        entryPoint = IEntryPoint(address(new EntryPoint()));
        
        // Deploy factory
        vm.prank(factoryOwner);
        factory = new AccountFactory(entryPoint, feeRecipient);
        
        // Deploy paymaster
        vm.prank(paymasterOwner);
        paymaster = new PayMaster(entryPoint, paymasterSigner, 1 ether);

        // Fund Paymaster Owner
        vm.deal(paymasterOwner, 20 ether);
        
        // Fund paymaster
        vm.deal(address(paymaster), 20 ether);

        vm.prank(paymasterOwner);
        paymaster.deposit{value: 10 ether}();
        
        // Deploy USDT mock
        usdt = new ERC20Mock();
        
        // Deploy Alice's smart account
        account = factory.createAccount(alice, 0);
        
        // Fund Alice's account
        vm.deal(address(account), 10 ether);
        usdt.mint(address(account), 10000 * 10**6); // 10,000 USDT (6 decimals)
        
        // Fund bundler for gas
        vm.deal(bundler, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    E2E: NATIVE TRANSFER WITH FEE
    //////////////////////////////////////////////////////////////*/

    function test_E2E_NativeTransferWithPaymaster() public {
        // Scenario: Alice sends 1 ETH to Bob
        // - Paymaster sponsors gas
        // - 1% fee goes to feeRecipient
        // - Bob receives 1 ETH
        
        uint256 sendAmount = 1 ether;
        uint256 expectedFee = (sendAmount * 100) / 10000; // 0.01 ETH
        
        // Setup: Whitelist Alice in paymaster
        vm.prank(paymasterOwner);
        paymaster.setWhitelistMode(true);
        vm.prank(paymasterOwner);
        paymaster.setWhitelist(address(account), true);
        
        // Record initial balances
        uint256 bobBalanceBefore = bob.balance;
        uint256 feeRecipientBalanceBefore = feeRecipient.balance;
        uint256 accountBalanceBefore = address(account).balance;
        
        // 1. Construct callData for the transfer
        bytes memory callData = abi.encodeWithSelector(
            account.execute.selector,
            bob,
            sendAmount,
            ""
        );
        
        // 2. Create UserOperation
        PackedUserOperation memory userOp = _createUserOp(
            address(account),
            alice,
            alicePrivateKey,
            0, // nonce
            callData,
            true, // use paymaster
            0, // validUntil (whitelist mode)
            0  // validAfter
        );
        
        // 3. Execute via EntryPoint
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        
        vm.prank(bundler);
        entryPoint.handleOps(ops, payable(bundler));
        
        // Verify results
        assertEq(bob.balance, bobBalanceBefore + sendAmount, "Bob should receive 1 ETH");
        assertEq(
            feeRecipient.balance,
            feeRecipientBalanceBefore + expectedFee,
            "Fee recipient should receive 0.01 ETH"
        );
        assertEq(
            address(account).balance,
            accountBalanceBefore - sendAmount - expectedFee,
            "Account should be debited 1.01 ETH"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    E2E: TOKEN TRANSFER WITH FEE
    //////////////////////////////////////////////////////////////*/

    function test_E2E_TokenTransferWithSignature() public {
        // Scenario: Alice sends 100 USDT to Charlie
        // - Paymaster sponsors gas (signature mode)
        // - 1% fee (1 USDT) goes to feeRecipient
        // - Charlie receives 100 USDT
        
        uint256 sendAmount = 100 * 10**6; // 100 USDT
        uint256 expectedFee = (sendAmount * 100) / 10000; // 1 USDT
        
        // Record initial balances
        uint256 charlieBalanceBefore = usdt.balanceOf(charlie);
        uint256 feeRecipientBalanceBefore = usdt.balanceOf(feeRecipient);
        uint256 accountBalanceBefore = usdt.balanceOf(address(account));
        
        // 1. Construct callData for token transfer
        bytes memory transferCall = abi.encodeWithSelector(
            IERC20.transfer.selector,
            charlie,
            sendAmount
        );
        
        bytes memory callData = abi.encodeWithSelector(
            account.execute.selector,
            address(usdt),
            0,
            transferCall
        );
        
        // 2. Create UserOperation with paymaster signature
        PackedUserOperation memory userOp = _createUserOp(
            address(account),
            alice,
            alicePrivateKey,
            0,
            callData,
            true,
            uint48(block.timestamp + 3600), // valid for 1 hour
            uint48(block.timestamp)
        );
        
        // 3. Execute
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        
        vm.prank(bundler);
        entryPoint.handleOps(ops, payable(bundler));
        
        // Verify results
        assertEq(
            usdt.balanceOf(charlie),
            charlieBalanceBefore + sendAmount,
            "Charlie should receive 100 USDT"
        );
        assertEq(
            usdt.balanceOf(feeRecipient),
            feeRecipientBalanceBefore + expectedFee,
            "Fee recipient should receive 1 USDT"
        );
        assertEq(
            usdt.balanceOf(address(account)),
            accountBalanceBefore - sendAmount - expectedFee,
            "Account should be debited 101 USDT"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    E2E: BATCH OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function test_E2E_BatchTransfersWithFees() public {
        // Scenario: Alice executes batch of transfers
        // - 0.5 ETH to Bob
        // - 50 USDT to Charlie
        // All with fees
        
        vm.prank(paymasterOwner);
        paymaster.setWhitelistMode(true);
        vm.prank(paymasterOwner);
        paymaster.setWhitelist(address(account), true);
        
        uint256 ethAmount = 0.5 ether;
        uint256 usdtAmount = 50 * 10**6;
        
        // Construct batch
        address[] memory dests = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory funcs = new bytes[](2);
        
        // ETH transfer
        dests[0] = bob;
        values[0] = ethAmount;
        funcs[0] = "";
        
        // USDT transfer
        dests[1] = address(usdt);
        values[1] = 0;
        funcs[1] = abi.encodeWithSelector(
            IERC20.transfer.selector,
            charlie,
            usdtAmount
        );
        
        bytes memory callData = abi.encodeWithSelector(
            account.executeBatch.selector,
            dests,
            values,
            funcs
        );
        
        PackedUserOperation memory userOp = _createUserOp(
            address(account),
            alice,
            alicePrivateKey,
            0,
            callData,
            true,
            0,
            0
        );
        
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        
        uint256 bobBalanceBefore = bob.balance;
        uint256 charlieUsdtBefore = usdt.balanceOf(charlie);
        
        vm.prank(bundler);
        entryPoint.handleOps(ops, payable(bundler));
        
        // Verify both transfers succeeded with fees
        assertEq(bob.balance, bobBalanceBefore + ethAmount);
        assertEq(usdt.balanceOf(charlie), charlieUsdtBefore + usdtAmount);
        assertGt(feeRecipient.balance, 0);
        assertGt(usdt.balanceOf(feeRecipient), 0);
    }

    /*//////////////////////////////////////////////////////////////
                    E2E: GAS LIMIT ENFORCEMENT
    //////////////////////////////////////////////////////////////*/

    function test_E2E_GasLimitEnforcement() public {
        // Setup paymaster with gas limit
        vm.startPrank(paymasterOwner);
        paymaster.setWhitelistMode(true);
        paymaster.setWhitelist(address(account), true);
        paymaster.setGasLimit(address(account), 0.1 ether);
        vm.stopPrank();
        
        // First operation should succeed
        bytes memory callData = abi.encodeWithSelector(
            account.execute.selector,
            bob,
            0.1 ether,
            ""
        );
        
        PackedUserOperation memory userOp1 = _createUserOp(
            address(account),
            alice,
            alicePrivateKey,
            0,
            callData,
            true,
            0,
            0
        );
        
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp1;
        
        vm.prank(bundler);
        entryPoint.handleOps(ops, payable(bundler));
        
        // Check remaining allowance
        uint256 remaining = paymaster.getRemainingGasAllowance(address(account));
        assertLt(remaining, 0.1 ether, "Some gas should be consumed");
    }

    /*//////////////////////////////////////////////////////////////
                    E2E: SEQUENTIAL OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function test_E2E_SequentialOperations() public {
        vm.prank(paymasterOwner);
        paymaster.setWhitelistMode(true);
        vm.prank(paymasterOwner);
        paymaster.setWhitelist(address(account), true);
        
        uint256 nonce = 0;
        
        // Execute 3 sequential operations
        for (uint256 i = 0; i < 3; i++) {
            bytes memory callData = abi.encodeWithSelector(
                account.execute.selector,
                bob,
                0.1 ether,
                ""
            );
            
            PackedUserOperation memory userOp = _createUserOp(
                address(account),
                alice,
                alicePrivateKey,
                nonce,
                callData,
                true,
                0,
                0
            );
            
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = userOp;
            
            vm.prank(bundler);
            entryPoint.handleOps(ops, payable(bundler));
            
            nonce++;
        }
        
        // Bob should have received 0.3 ETH total
        assertGt(bob.balance, 0.29 ether); // Account for fees
    }

    /*//////////////////////////////////////////////////////////////
                    E2E: MIXED MODE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function test_E2E_MixedTransferAndContractCall() public {
        vm.prank(paymasterOwner);
        paymaster.setWhitelistMode(true);
        vm.prank(paymasterOwner);
        paymaster.setWhitelist(address(account), true);
        
        // Batch: Transfer + Approve (approve shouldn't have fee)
        address[] memory dests = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory funcs = new bytes[](2);
        
        // Transfer (with fee)
        dests[0] = address(usdt);
        values[0] = 0;
        funcs[0] = abi.encodeWithSelector(
            IERC20.transfer.selector,
            bob,
            100 * 10**6
        );
        
        // Approve (no fee)
        dests[1] = address(usdt);
        values[1] = 0;
        funcs[1] = abi.encodeWithSelector(
            IERC20.approve.selector,
            charlie,
            200 * 10**6
        );
        
        bytes memory callData = abi.encodeWithSelector(
            account.executeBatch.selector,
            dests,
            values,
            funcs
        );
        
        PackedUserOperation memory userOp = _createUserOp(
            address(account),
            alice,
            alicePrivateKey,
            0,
            callData,
            true,
            0,
            0
        );
        
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        
        vm.prank(bundler);
        entryPoint.handleOps(ops, payable(bundler));
        
        // Verify transfer happened with fee
        assertEq(usdt.balanceOf(bob), 100 * 10**6);
        assertGt(usdt.balanceOf(feeRecipient), 0);
        
        // Verify approve happened without fee
        assertEq(usdt.allowance(address(account), charlie), 200 * 10**6);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _createUserOp(
        address sender,
        address signer,
        uint256 signerKey,
        uint256 nonce,
        bytes memory callData,
        bool usePaymaster,
        uint48 validUntil,
        uint48 validAfter
    ) internal view returns (PackedUserOperation memory userOp) {
        userOp = PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(uint256(150000) << 128 | uint256(150000)),
            preVerificationGas: 100000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(2 gwei)),
            paymasterAndData: "",
            signature: ""
        });
        
        if (usePaymaster) {
            if (paymaster.whitelistEnabled()) {
                // Whitelist mode - dummy signature
                userOp.paymasterAndData = abi.encodePacked(
                    address(paymaster),
                    uint128(100000),
                    uint128(50000),
                    uint48(0),
                    uint48(0),
                    new bytes(65)
                );
            } else {
                // Signature mode - real signature
                bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
                bytes32 ethSignedHash = hash.toEthSignedMessageHash();
                (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterSignerPrivateKey, ethSignedHash);
                bytes memory pmSignature = abi.encodePacked(r, s, v);
                
                userOp.paymasterAndData = abi.encodePacked(
                    address(paymaster),
                    uint128(100000),
                    uint128(50000),
                    validUntil,
                    validAfter,
                    pmSignature
                );
            }
        }
        
        // Sign the userOp
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 ethSignedUserOpHash = userOpHash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, ethSignedUserOpHash);
        userOp.signature = abi.encodePacked(r, s, v);
    }
}

// Full EntryPoint Mock with actual execution logic
// contract FullEntryPointMock is IEntryPoint {
//     using MessageHashUtils for bytes32;
//     using ECDSA for bytes32;
    
//     mapping(address => uint256) public deposits;
//     mapping(address => uint256) public nonces;
    
//     function handleOps(
//         PackedUserOperation[] calldata ops,
//         address payable beneficiary
//     ) external {
//         for (uint256 i = 0; i < ops.length; i++) {
//             _handleOp(ops[i], beneficiary);
//         }
//     }
    
//     function _handleOp(
//         PackedUserOperation calldata userOp,
//         address payable beneficiary
//     ) internal {
//         // Validate paymaster if present
//         if (userOp.paymasterAndData.length > 0) {
//             address paymaster = address(bytes20(userOp.paymasterAndData[0:20]));
            
//             bytes32 userOpHash = getUserOpHash(userOp);
            
//             try IPaymaster(paymaster).validatePaymasterUserOp(
//                 userOp,
//                 userOpHash,
//                 0.1 ether
//             ) returns (bytes memory context, uint256 validationData) {
//                 // Validation successful
                
//                 // Execute the operation
//                 (bool success,) = userOp.sender.call(userOp.callData);
//                 require(success, "UserOp execution failed");
                
//                 // Call postOp
//                 uint256 actualGasCost = 0.01 ether; // Mock gas cost
//                 IPaymaster(paymaster).postOp(
//                     success ? IPaymaster.PostOpMode.opSucceeded : IPaymaster.PostOpMode.opReverted,
//                     context,
//                     actualGasCost,
//                     1 gwei
//                 );
//             } catch {
//                 revert("Paymaster validation failed");
//             }
//         } else {
//             // No paymaster - execute directly
//             (bool success,) = userOp.sender.call(userOp.callData);
//             require(success, "UserOp execution failed");
//         }
        
//         nonces[userOp.sender]++;
//     }
    
//     function getUserOpHash(PackedUserOperation calldata userOp) public view returns (bytes32) {
//         return keccak256(abi.encode(
//             userOp.sender,
//             userOp.nonce,
//             keccak256(userOp.callData),
//             block.chainid,
//             address(this)
//         ));
//     }
    
//     function depositTo(address account) external payable {
//         deposits[account] += msg.value;
//     }
    
//     function withdrawTo(address payable withdrawAddress, uint256 amount) external {
//         deposits[msg.sender] -= amount;
//         withdrawAddress.transfer(amount);
//     }
    
//     function balanceOf(address account) external view returns (uint256) {
//         return deposits[account];
//     }
    
//     function getNonce(address sender, uint192) external view returns (uint256) {
//         return nonces[sender];
//     }
    
//     function handleAggregatedOps(UserOpsPerAggregator[] calldata, address payable) external {}
//     function getSenderAddress(bytes calldata) external {}
//     function addStake(uint32) external payable {}
//     function unlockStake() external {}
//     function withdrawStake(address payable) external {}
    
//     receive() external payable {}
// }