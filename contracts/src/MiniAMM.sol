// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

/// @title Constant-product AMM with many pools in one contract, and multicall.
/// @notice Amounts actually received are measured by balance difference, so fee-on-transfer tokens
///         are handled honestly and their tax is visible in simulation.
contract MiniAMM {
    event Swap(address indexed sender, address indexed tokenIn, address indexed tokenOut, uint256 amountIn, uint256 amountOut, address to);
    event LiquidityAdded(address indexed tokenA, address indexed tokenB, uint256 amountA, uint256 amountB);

    struct Pool {
        uint256 reserve0;
        uint256 reserve1;
    }

    uint256 public constant FEE_BPS = 30;
    mapping(bytes32 => Pool) public pools;

    function _key(address a, address b) internal pure returns (bytes32 key, bool flipped) {
        require(a != b, "same token");
        flipped = a > b;
        (address t0, address t1) = flipped ? (b, a) : (a, b);
        key = keccak256(abi.encode(t0, t1));
    }

    function reserves(address tokenIn, address tokenOut) public view returns (uint256 rIn, uint256 rOut) {
        (bytes32 key, bool flipped) = _key(tokenIn, tokenOut);
        Pool storage p = pools[key];
        (rIn, rOut) = flipped ? (p.reserve1, p.reserve0) : (p.reserve0, p.reserve1);
    }

    function _pull(address token, uint256 amount) internal returns (uint256 received) {
        uint256 before = IERC20Like(token).balanceOf(address(this));
        require(IERC20Like(token).transferFrom(msg.sender, address(this), amount), "pull");
        received = IERC20Like(token).balanceOf(address(this)) - before;
    }

    function addLiquidity(address tokenA, address tokenB, uint256 amountA, uint256 amountB) external {
        uint256 gotA = _pull(tokenA, amountA);
        uint256 gotB = _pull(tokenB, amountB);
        (bytes32 key, bool flipped) = _key(tokenA, tokenB);
        Pool storage p = pools[key];
        if (flipped) {
            p.reserve0 += gotB;
            p.reserve1 += gotA;
        } else {
            p.reserve0 += gotA;
            p.reserve1 += gotB;
        }
        emit LiquidityAdded(tokenA, tokenB, gotA, gotB);
    }

    function getAmountOut(address tokenIn, address tokenOut, uint256 amountIn) public view returns (uint256) {
        (uint256 rIn, uint256 rOut) = reserves(tokenIn, tokenOut);
        require(rIn > 0 && rOut > 0, "no pool");
        uint256 inWithFee = amountIn * (10_000 - FEE_BPS);
        return (inWithFee * rOut) / (rIn * 10_000 + inWithFee);
    }

    function swapExactIn(address tokenIn, address tokenOut, uint256 amountIn, uint256 minOut, address to)
        external
        returns (uint256 amountOut)
    {
        uint256 received = _pull(tokenIn, amountIn);
        amountOut = getAmountOut(tokenIn, tokenOut, received);
        require(amountOut >= minOut, "slippage");
        (bytes32 key, bool flipped) = _key(tokenIn, tokenOut);
        Pool storage p = pools[key];
        if (flipped) {
            p.reserve1 += received;
            p.reserve0 -= amountOut;
        } else {
            p.reserve0 += received;
            p.reserve1 -= amountOut;
        }
        require(IERC20Like(tokenOut).transfer(to, amountOut), "push");
        emit Swap(msg.sender, tokenIn, tokenOut, received, amountOut, to);
    }

    /// @notice Batch several calls into this contract in one transaction.
    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory ret) = address(this).delegatecall(data[i]);
            if (!ok) {
                assembly {
                    revert(add(ret, 32), mload(ret))
                }
            }
            results[i] = ret;
        }
    }
}
