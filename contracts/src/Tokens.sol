// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

import {ERC20} from "./ERC20.sol";

/// @title EIP-712 domain + EIP-2612 permit.
abstract contract ERC20Permit is ERC20 {
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    mapping(address => uint256) public nonces;

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256("1"), block.chainid, address(this))
        );
    }

    function _digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    function _recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        // Reject malleable signatures (upper half of s), as OpenZeppelin's ECDSA does.
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "bad s");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        return signer;
    }

    function permit(
        address holder,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "permit expired");
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, holder, spender, value, nonces[holder]++, deadline));
        require(_recover(_digest(structHash), v, r, s) == holder, "permit signer");
        _approve(holder, spender, value);
    }
}

/// @notice Plain ERC-20 (tGOV).
contract TestToken is ERC20 {
    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC20(name_, symbol_, decimals_) {}
}

/// @notice ERC-20 with EIP-2612 permit (tDAI).
contract PermitToken is ERC20Permit {
    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC20(name_, symbol_, decimals_) {}
}

/// @notice ERC-20 with EIP-2612 permit and EIP-3009 transferWithAuthorization (tUSD, the x402 asset).
contract AuthToken is ERC20Permit {
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC20(name_, symbol_, decimals_) {}

    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp > validAfter, "auth not yet valid");
        require(block.timestamp < validBefore, "auth expired");
        require(!authorizationState[from][nonce], "auth used");
        bytes32 structHash =
            keccak256(abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce));
        require(_recover(_digest(structHash), v, r, s) == from, "auth signer");
        authorizationState[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);
        _update(from, to, value);
    }
}

/// @notice Buys succeed, sells revert: transfers into the AMM are refused unless from the owner.
contract HoneypotToken is ERC20 {
    address public amm;

    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC20(name_, symbol_, decimals_) {}

    function setAmm(address amm_) external onlyOwner {
        amm = amm_;
    }

    function _update(address from, address to, uint256 amount) internal override {
        require(!(to == amm && from != owner), "TRANSFER_FAILED");
        super._update(from, to, amount);
    }
}

/// @notice Takes a tax on every transfer that does not involve the owner.
contract FeeOnTransferToken is ERC20 {
    uint256 public immutable taxBps;

    constructor(string memory name_, string memory symbol_, uint8 decimals_, uint256 taxBps_)
        ERC20(name_, symbol_, decimals_)
    {
        require(taxBps_ <= 5000, "tax");
        taxBps = taxBps_;
    }

    function _update(address from, address to, uint256 amount) internal override {
        if (from == owner || to == owner || from == address(0)) {
            super._update(from, to, amount);
            return;
        }
        uint256 tax = (amount * taxBps) / 10_000;
        super._update(from, owner, tax);
        super._update(from, to, amount - tax);
    }
}
