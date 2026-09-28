// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import {AuthToken, PermitToken, TestToken, HoneypotToken, FeeOnTransferToken} from "../src/Tokens.sol";
import {MiniAMM} from "../src/MiniAMM.sol";
import {DrainerSpender} from "../src/Attackers.sol";

/// Minimal cheatcode interface (no forge-std dependency).
interface Vm {
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function addr(uint256 privateKey) external returns (address);
    function prank(address sender) external;
    function startPrank(address sender) external;
    function stopPrank() external;
    function expectRevert(bytes calldata revertData) external;
    function warp(uint256 timestamp) external;
}

contract WorldTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 constant USER_KEY = 0xA11CE;
    address user;
    address constant ATTACKER = address(0xBAD);

    AuthToken usd;
    PermitToken dai;
    TestToken gov;
    HoneypotToken honey;
    FeeOnTransferToken tax;
    MiniAMM amm;

    function setUp() public {
        user = vm.addr(USER_KEY);
        usd = new AuthToken("Test USD", "tUSD", 6);
        dai = new PermitToken("Test DAI", "tDAI", 18);
        gov = new TestToken("Test Governance", "tGOV", 18);
        honey = new HoneypotToken("Honey Moon", "tHONEY", 18);
        tax = new FeeOnTransferToken("Tax Token", "tTAX", 18, 1000);
        amm = new MiniAMM();
        honey.setAmm(address(amm));

        usd.mint(address(this), 1_000_000e6);
        gov.mint(address(this), 100_000e18);
        honey.mint(address(this), 100_000e18);
        tax.mint(address(this), 100_000e18);
        usd.approve(address(amm), type(uint256).max);
        gov.approve(address(amm), type(uint256).max);
        honey.approve(address(amm), type(uint256).max);
        tax.approve(address(amm), type(uint256).max);
        amm.addLiquidity(address(usd), address(gov), 100_000e6, 10_000e18);
        amm.addLiquidity(address(usd), address(honey), 50_000e6, 50_000e18);
        amm.addLiquidity(address(usd), address(tax), 50_000e6, 50_000e18);

        usd.mint(user, 5_000e6);
        dai.mint(user, 500e18);
    }

    function _eq(uint256 a, uint256 b, string memory what) internal pure {
        require(a == b, what);
    }

    function test_permit_sets_allowance_and_drainer_takes_it() public {
        DrainerSpender drainer = new DrainerSpender();
        uint256 deadline = block.timestamp + 1 days;
        bytes32 structHash = keccak256(
            abi.encode(dai.PERMIT_TYPEHASH(), user, address(drainer), type(uint256).max, dai.nonces(user), deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", dai.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_KEY, digest);
        drainer.drainWithPermit(address(dai), user, type(uint256).max, deadline, v, r, s, ATTACKER);
        _eq(dai.balanceOf(ATTACKER), 500e18, "drained");
        _eq(dai.balanceOf(user), 0, "user empty");
    }

    function test_transfer_with_authorization_once_only() public {
        bytes32 nonce = keccak256("n1");
        uint256 validBefore = block.timestamp + 600;
        bytes32 structHash = keccak256(
            abi.encode(usd.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), user, ATTACKER, 5e6, 0, validBefore, nonce)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", usd.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_KEY, digest);
        vm.warp(block.timestamp + 1);
        usd.transferWithAuthorization(user, ATTACKER, 5e6, 0, validBefore, nonce, v, r, s);
        _eq(usd.balanceOf(ATTACKER), 5e6, "paid");
        vm.expectRevert(bytes("auth used"));
        usd.transferWithAuthorization(user, ATTACKER, 5e6, 0, validBefore, nonce, v, r, s);
    }

    function test_swap_quotes_match_execution() public {
        vm.startPrank(user);
        usd.approve(address(amm), 100e6);
        uint256 quoted = amm.getAmountOut(address(usd), address(gov), 100e6);
        uint256 out = amm.swapExactIn(address(usd), address(gov), 100e6, quoted, user);
        vm.stopPrank();
        _eq(out, quoted, "quote");
        _eq(gov.balanceOf(user), quoted, "received");
    }

    function test_honeypot_buy_ok_sell_reverts() public {
        vm.startPrank(user);
        usd.approve(address(amm), 100e6);
        uint256 bought = amm.swapExactIn(address(usd), address(honey), 100e6, 0, user);
        require(bought > 0, "bought");
        honey.approve(address(amm), bought);
        vm.expectRevert(bytes("TRANSFER_FAILED"));
        amm.swapExactIn(address(honey), address(usd), bought, 0, user);
        vm.stopPrank();
    }

    function test_fee_on_transfer_takes_ten_percent() public {
        vm.startPrank(user);
        usd.approve(address(amm), 100e6);
        uint256 quoted = amm.getAmountOut(address(usd), address(tax), 100e6);
        amm.swapExactIn(address(usd), address(tax), 100e6, 0, user);
        vm.stopPrank();
        _eq(tax.balanceOf(user), quoted - quoted / 10, "taxed");
    }

    function test_zero_value_transfer_from_needs_no_allowance() public {
        // The address-poisoning primitive: anyone can emit Transfer(user -> lookalike, 0).
        vm.prank(ATTACKER);
        usd.transferFrom(user, address(0x1234), 0);
        _eq(usd.balanceOf(user), 5_000e6, "unchanged");
    }

    function test_multicall_batches_approve_free_calls() public {
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeCall(MiniAMM.getAmountOut, (address(usd), address(gov), 1e6));
        bytes[] memory out = amm.multicall(calls);
        _eq(abi.decode(out[0], (uint256)), amm.getAmountOut(address(usd), address(gov), 1e6), "multicall");
    }
}
