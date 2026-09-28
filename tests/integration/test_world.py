from __future__ import annotations

import pytest

from warden.chain.abi import load_artifact
from warden.chain.rpc import RpcClient, RpcError
from warden.chain.world import World, units

pytestmark = pytest.mark.integration


async def _balance(rpc: RpcClient, world: World, symbol: str, who: str) -> int:
    t = world.token(symbol)
    art = load_artifact(t.kind)
    out = await rpc.eth_call(t.address, art.encode_call("balanceOf", who))
    return int(art.decode_output("balanceOf", out)[0])


async def test_balances_after_history(rpc: RpcClient, world: World) -> None:
    # user: 5000 minted - 100 (Acme) - 25 (Bob) - 900 (Carol)
    assert await _balance(rpc, world, "tUSD", world.user) == units(3975, 6)
    assert await _balance(rpc, world, "tUSD", world.accounts["acme"]) == units(1100, 6)


async def test_swap_and_honeypot(rpc: RpcClient, world: World) -> None:
    usd = world.token("tUSD")
    honey = world.token("tHONEY")
    amm = load_artifact("MiniAMM")
    token = load_artifact("AuthToken")
    user = world.user
    await rpc.send_and_wait(
        {
            "from": user,
            "to": usd.address,
            "data": token.encode_call("approve", world.amm, units(100, 6)),
        }
    )
    rcpt = await rpc.send_and_wait(
        {
            "from": user,
            "to": world.amm,
            "data": amm.encode_call(
                "swapExactIn", usd.address, honey.address, units(100, 6), 0, user
            ),
        }
    )
    assert int(rcpt["status"], 16) == 1
    bought = await _balance(rpc, world, "tHONEY", user)
    assert bought > 0
    hp = load_artifact("HoneypotToken")
    await rpc.send_and_wait(
        {"from": user, "to": honey.address, "data": hp.encode_call("approve", world.amm, bought)}
    )
    with pytest.raises(RpcError, match="TRANSFER_FAILED"):
        await rpc.eth_call(
            world.amm,
            amm.encode_call("swapExactIn", honey.address, usd.address, bought, 0, user),
            sender=user,
        )


async def test_snapshot_isolation(rpc: RpcClient, world: World) -> None:
    before = await _balance(rpc, world, "tUSD", world.user)
    snap = await rpc.snapshot()
    token = load_artifact("AuthToken")
    await rpc.send_and_wait(
        {
            "from": world.user,
            "to": world.token("tUSD").address,
            "data": token.encode_call("transfer", world.accounts["bob"], 1),
        }
    )
    assert await _balance(rpc, world, "tUSD", world.user) == before - 1
    await rpc.revert(snap)
    assert await _balance(rpc, world, "tUSD", world.user) == before
