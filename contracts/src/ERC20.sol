// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

/// @title Minimal ERC-20 used by every WardenBench token.
/// @notice `_update` is the single hook for balance changes, so tokens with odd behaviour
///         (honeypot, transfer tax) override one function.
abstract contract ERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public totalSupply;
    address public immutable owner;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        _update(msg.sender, to, amount);
        return true;
    }

    /// @dev A zero-value transferFrom needs no allowance. Real tokens behave the same way, and
    ///      address-poisoning attacks rely on it to forge history entries.
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _update(from, to, amount);
        return true;
    }

    function _approve(address holder, address spender, uint256 amount) internal {
        allowance[holder][spender] = amount;
        emit Approval(holder, spender, amount);
    }

    function _update(address from, address to, uint256 amount) internal virtual {
        require(balanceOf[from] >= amount, "balance");
        unchecked {
            balanceOf[from] -= amount;
        }
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
