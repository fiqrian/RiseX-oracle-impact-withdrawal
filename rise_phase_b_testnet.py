#!/usr/bin/env python3
"""Bootstrap disposable RISEx testnet accounts for Phase-B validation.

Dependencies (Ubuntu/Python 3.10+):
    python3 -m pip install 'eth-account==0.11.3' 'requests>=2.31,<3'

Run:
    python3 rise_phase_b_testnet.py bootstrap

The script is hard-pinned to the official testnet chain/API and refuses any
other chain ID. Private keys are generated locally, stored mode 0600, and are
never printed or written into evidence files.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import math
import os
import stat
import sys
import time
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from eth_abi import decode, encode
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak, to_checksum_address


API = "https://api.testnet.rise.trade"
RPC = "https://testnet.riselabs.xyz"
EXPECTED_CHAIN_ID = 11_155_931
KEY_DIR = Path("/root/rise-phase-b-private")
KEY_FILE = KEY_DIR / "disposable-accounts.json"
JWT_FILE = KEY_DIR / "testnet-jwts.json"
EVIDENCE_DIR = Path("/root/rise-phase-b-evidence")
PHASE_STATE_FILE = EVIDENCE_DIR / "impact-phase-state.json"
TIMELINE_JSON = EVIDENCE_DIR / "impact-timeline.json"
TIMELINE_CSV = EVIDENCE_DIR / "impact-timeline.csv"
HTTP_TIMEOUT = 60
MARKET_ID = 1
MAX_IMPACT_ORDER_NOTIONAL_USD = Decimal("25500")
MIN_IMPACT_ORDER_NOTIONAL_USD = Decimal("25000")
MAX_WITHDRAW_USDC = Decimal("1")


class FlowError(RuntimeError):
    pass


def rpc(method: str, params: list[Any]) -> Any:
    response = requests.post(
        RPC,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": "RISEx-security-validation/1.0"},
    )
    response.raise_for_status()
    payload = response.json()
    if "error" in payload:
        raise FlowError(f"RPC {method} failed: {payload['error']}")
    return payload["result"]


def api(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {"User-Agent": "RISEx-security-validation/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.request(
        method,
        API + path,
        json=body,
        timeout=HTTP_TIMEOUT,
        headers=headers,
    )
    try:
        payload = response.json()
    except ValueError as exc:
        raise FlowError(f"{method} {path} returned non-JSON HTTP {response.status_code}") from exc
    return response.status_code, payload


def web_api(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    url = "https://testnet.rise.trade" + path
    headers = {
        "User-Agent": "Mozilla/5.0 RISEx-security-validation/1.0",
        "Content-Type": "application/json",
        "Origin": "https://testnet.rise.trade",
        "Referer": "https://testnet.rise.trade/en",
    }
    response = requests.post(url, json=body, timeout=HTTP_TIMEOUT, headers=headers)
    if response.status_code == 403:
        proxy_file = Path("/root/Proxy.md")
        if proxy_file.exists():
            candidates = [
                line.strip()
                for line in proxy_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            if candidates:
                host, port, username, password = candidates[0].split(":", 3)
                proxy_url = (
                    f"http://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
                )
                response = requests.post(
                    url,
                    json=body,
                    timeout=HTTP_TIMEOUT,
                    headers=headers,
                    proxies={"http": proxy_url, "https": proxy_url},
                )
    try:
        payload = response.json()
    except ValueError as exc:
        raise FlowError(f"POST {path} returned non-JSON HTTP {response.status_code}") from exc
    return response.status_code, payload


def write_json(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temp, path)
        os.chmod(path, mode)
    finally:
        if temp.exists():
            temp.unlink()


def load_or_create_accounts() -> dict[str, dict[str, str]]:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(KEY_DIR, 0o700)
    if KEY_FILE.exists():
        mode = stat.S_IMODE(KEY_FILE.stat().st_mode)
        if mode & 0o077:
            raise FlowError(f"Refusing insecure key file permissions: {oct(mode)}")
        data = json.loads(KEY_FILE.read_text(encoding="utf-8"))
    else:
        data: dict[str, dict[str, str]] = {}
        for label in ("A", "B"):
            wallet = Account.create()
            signer = Account.create()
            data[label] = {
                "account": wallet.address,
                "account_private_key": wallet.key.hex(),
                "signer": signer.address,
                "signer_private_key": signer.key.hex(),
            }
        write_json(KEY_FILE, data, 0o600)

    for label in ("A", "B"):
        record = data.get(label, {})
        required = {"account", "account_private_key", "signer", "signer_private_key"}
        if set(record) != required:
            raise FlowError(f"Invalid key record for {label}")
        if Account.from_key(record["account_private_key"]).address.lower() != record["account"].lower():
            raise FlowError(f"Account key/address mismatch for {label}")
        if Account.from_key(record["signer_private_key"]).address.lower() != record["signer"].lower():
            raise FlowError(f"Signer key/address mismatch for {label}")
    return data


def public_config() -> tuple[dict[str, Any], dict[str, Any]]:
    chain_id = int(rpc("eth_chainId", []), 16)
    if chain_id != EXPECTED_CHAIN_ID:
        raise FlowError(f"Write guard: expected chain {EXPECTED_CHAIN_ID}, got {chain_id}")

    config_status, config = api("GET", "/v1/system/config")
    domain_status, domain = api("GET", "/v1/auth/eip712-domain")
    if config_status != 200 or domain_status != 200:
        raise FlowError("Unable to fetch testnet config/domain")
    if int(config["data"]["chain"]["chain_id"]) != EXPECTED_CHAIN_ID:
        raise FlowError("API config is not testnet")
    if int(domain["data"]["chain_id"]) != EXPECTED_CHAIN_ID:
        raise FlowError("EIP-712 domain is not testnet")
    return config["data"], domain["data"]


def chain_timestamp() -> int:
    block = rpc("eth_getBlockByNumber", ["latest", False])
    return int(block["timestamp"], 16)


def receipt_status(tx_hash: str, attempts: int = 20) -> tuple[str, dict[str, Any]]:
    for _ in range(attempts):
        receipt = rpc("eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return receipt.get("status", ""), receipt
        time.sleep(0.5)
    raise FlowError(f"Receipt not found: {tx_hash}")


def nonce_state(account: str) -> tuple[int, int]:
    status, payload = api("GET", f"/v1/nonce-state/{account}")
    if status != 200:
        raise FlowError(f"nonce-state HTTP {status}: {payload.get('error')}")
    anchor = int(payload["data"]["nonce_anchor"])
    bitmap = int(payload["data"]["current_bitmap_index"])
    if bitmap >= 208:
        return anchor + 1, 0
    return anchor, bitmap


def typed_domain(domain: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": domain["name"],
        "version": domain["version"],
        "chainId": int(domain["chain_id"]),
        "verifyingContract": domain["verifying_contract"],
    }


def sign_typed(private_key: str, full_message: dict[str, Any], expected: str) -> str:
    signable = encode_typed_data(full_message=full_message)
    signed = Account.sign_message(signable, private_key=private_key)
    recovered = Account.recover_message(signable, signature=signed.signature)
    if recovered.lower() != expected.lower():
        raise FlowError("Local EIP-712 recovery mismatch")
    signature_hex = signed.signature.hex()
    return signature_hex if signature_hex.startswith("0x") else "0x" + signature_hex


def ensure_funded(label: str, record: dict[str, str], chain_ts: int) -> dict[str, Any]:
    status, portfolio = api("GET", f"/v1/portfolio/details?account={record['account']}")
    if status == 200 and float(portfolio["data"]["summary"]["usdc_balance"]) >= 1000:
        return {"already_funded": True, "balance": portfolio["data"]["summary"]["usdc_balance"]}

    body = {
        "amount": "1000",
        "account": record["account"],
        "permit_params": {
            "account": record["account"],
            "signer": "",
            "deadline": chain_ts + 604_800,
            "nonce_anchor": 0,
            "nonce_bitmap_index": 0,
            "signature": "0x" + ("0" * 128),
        },
    }
    status, result = api("POST", "/v1/account/deposit", body=body)
    write_json(EVIDENCE_DIR / f"bootstrap-{label}-faucet.json", result, 0o600)
    if status != 200 or not result.get("data", {}).get("success"):
        raise FlowError(f"Faucet {label} failed HTTP {status}: {result.get('error')}")
    tx_hash = result["data"]["transaction_hash"]
    tx_status, receipt = receipt_status(tx_hash)
    if tx_status != "0x1":
        raise FlowError(f"Faucet {label} transaction failed: {tx_hash}")
    return {"already_funded": False, "tx_hash": tx_hash, "block": receipt["blockNumber"]}


def register_signer(
    label: str,
    record: dict[str, str],
    domain: dict[str, Any],
    expiration: int,
) -> dict[str, Any]:
    anchor, bitmap = nonce_state(record["account"])
    message = "Register signer for RISEx oracle sandbox validation"
    eip_domain = typed_domain(domain)

    account_typed = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "RegisterSigner": [
                {"name": "account", "type": "address"},
                {"name": "signer", "type": "address"},
                {"name": "message", "type": "string"},
                {"name": "expiration", "type": "uint32"},
                {"name": "nonceAnchor", "type": "uint48"},
                {"name": "nonceBitmap", "type": "uint8"},
            ],
        },
        "primaryType": "RegisterSigner",
        "domain": eip_domain,
        "message": {
            "account": record["account"],
            "signer": record["signer"],
            "message": message,
            "expiration": expiration,
            "nonceAnchor": anchor,
            "nonceBitmap": bitmap,
        },
    }
    signer_typed = {
        "types": {
            "EIP712Domain": account_typed["types"]["EIP712Domain"],
            "VerifySigner": [
                {"name": "account", "type": "address"},
                {"name": "nonceAnchor", "type": "uint48"},
                {"name": "nonceBitmap", "type": "uint8"},
            ],
        },
        "primaryType": "VerifySigner",
        "domain": eip_domain,
        "message": {"account": record["account"], "nonceAnchor": anchor, "nonceBitmap": bitmap},
    }

    body = {
        "account": record["account"],
        "signer": record["signer"],
        "message": message,
        "nonce_anchor": str(anchor),
        "expiration": str(expiration),
        "account_signature": sign_typed(record["account_private_key"], account_typed, record["account"]),
        "signer_signature": sign_typed(record["signer_private_key"], signer_typed, record["signer"]),
        "nonce_bitmap_index": bitmap,
        "label": f"oracle-sandbox-{label}",
    }
    status, result = api("POST", "/v1/auth/register-signer", body=body)
    write_json(EVIDENCE_DIR / f"bootstrap-{label}-register-signer.json", result, 0o600)
    if status != 200 or not result.get("data", {}).get("success"):
        raise FlowError(f"Register signer {label} failed HTTP {status}: {result.get('error')}")
    tx_hash = result["data"].get("transaction_hash", "")
    if tx_hash:
        tx_status, receipt = receipt_status(tx_hash)
        if tx_status != "0x1":
            raise FlowError(f"Register signer {label} transaction failed: {tx_hash}")
        return {"tx_hash": tx_hash, "block": receipt["blockNumber"]}
    return {"already_registered": True}


def bootstrap() -> None:
    config, domain = public_config()
    accounts = load_or_create_accounts()
    now = chain_timestamp()
    expiration = now + 604_800
    public_summary: dict[str, Any] = {
        "api": API,
        "rpc": RPC,
        "chain_id": EXPECTED_CHAIN_ID,
        "router": config["addresses"]["router"],
        "oracle": config["addresses"]["oracle"],
        "accounts": {},
    }

    for label in ("A", "B"):
        record = accounts[label]
        funded = ensure_funded(label, record, now)
        registered = register_signer(label, record, domain, expiration)
        public_summary["accounts"][label] = {
            "account": record["account"],
            "signer": record["signer"],
            "funding": funded,
            "registration": registered,
        }
        print(f"{label}: account={record['account']} signer={record['signer']} funded=yes registered=yes")

    write_json(EVIDENCE_DIR / "bootstrap-summary.json", public_summary, 0o600)
    print(f"PASS: disposable Phase-B accounts bootstrapped on chain {EXPECTED_CHAIN_ID}")
    print(f"Evidence: {EVIDENCE_DIR / 'bootstrap-summary.json'}")
    print(f"Keys: {KEY_FILE} (mode 0600; never include in a report)")


def approve_jwt() -> None:
    config, domain = public_config()
    accounts = load_or_create_accounts()
    now = chain_timestamp()
    expiry = now + 31_536_000
    operator = config["addresses"]["operator_hub"]
    budget = (1 << 96) - 1
    jwt_records: dict[str, Any] = {}

    domain_types = [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ]
    permit_types = [
        {"name": "account", "type": "address"},
        {"name": "operator", "type": "address"},
        {"name": "budget", "type": "uint96"},
        {"name": "allowanceExpiry", "type": "uint32"},
        {"name": "nonceAnchor", "type": "uint48"},
        {"name": "nonceBitmap", "type": "uint8"},
    ]

    for label in ("A", "B"):
        record = accounts[label]
        anchor, bitmap = nonce_state(record["account"])
        typed = {
            "types": {"EIP712Domain": domain_types, "PermitSingle": permit_types},
            "primaryType": "PermitSingle",
            "domain": typed_domain(domain),
            "message": {
                "account": record["account"],
                "operator": operator,
                "budget": budget,
                "allowanceExpiry": expiry,
                "nonceAnchor": anchor,
                "nonceBitmap": bitmap,
            },
        }
        signature = sign_typed(record["account_private_key"], typed, record["account"])
        status, result = web_api(
            "/api/risex-auth/approve-single",
            {
                "account": record["account"],
                "operator": operator,
                "budget": str(budget),
                "allowance_expiry": expiry,
                "nonce_anchor": str(anchor),
                "nonce_bitmap_index": bitmap,
                "signature": signature,
                "stayConnected": False,
            },
        )
        data = result.get("data", {})
        token = data.get("access_token")
        expires_in = data.get("expires_in")
        if status != 200 or not isinstance(token, str) or len(token) < 80:
            write_json(EVIDENCE_DIR / f"approve-jwt-{label}-error.json", result, 0o600)
            raise FlowError(f"JWT approval {label} failed HTTP {status}: {result.get('error')}")
        jwt_records[label] = {
            "account": record["account"],
            "access_token": token,
            "expires_in": expires_in,
            "obtained_at": now,
        }
        sanitized = {
            "http_status": status,
            "request_id": result.get("request_id"),
            "data_keys": sorted(data.keys()),
            "expires_in": expires_in,
            "account": record["account"],
        }
        write_json(EVIDENCE_DIR / f"approve-jwt-{label}.json", sanitized, 0o600)
        print(f"{label}: OperatorHub approved; testnet JWT obtained (token redacted)")

    write_json(JWT_FILE, jwt_records, 0o600)
    print(f"PASS: JWT A/B ready in {JWT_FILE} (mode 0600)")


def load_jwts() -> dict[str, dict[str, Any]]:
    if not JWT_FILE.exists():
        raise FlowError("JWT file missing; run approve-jwt first")
    mode = stat.S_IMODE(JWT_FILE.stat().st_mode)
    if mode & 0o077:
        raise FlowError(f"Refusing insecure JWT file permissions: {oct(mode)}")
    data = json.loads(JWT_FILE.read_text(encoding="utf-8"))
    for label in ("A", "B"):
        token = data.get(label, {}).get("access_token", "")
        if not isinstance(token, str) or len(token) < 80:
            raise FlowError(f"Invalid JWT record for {label}")
    return data


def find_tx_hash(payload: dict[str, Any]) -> str:
    data = payload.get("data", {})
    for key in ("transaction_hash", "tx_hash"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, str) and value.startswith("0x") and len(value) == 66:
            return value
    return ""


def function_data(signature: str, types: tuple[str, ...], values: tuple[Any, ...]) -> str:
    return "0x" + (keccak(text=signature)[:4] + encode(types, values)).hex()


def eth_call(
    to: str,
    signature: str,
    input_types: tuple[str, ...] = (),
    values: tuple[Any, ...] = (),
    output_types: tuple[str, ...] = ("uint256",),
    *,
    sender: str | None = None,
) -> tuple[Any, ...]:
    transaction = {
        "to": to_checksum_address(to),
        "data": function_data(signature, input_types, values),
    }
    if sender:
        transaction["from"] = to_checksum_address(sender)
    raw = rpc("eth_call", [transaction, "latest"])
    return decode(output_types, bytes.fromhex(raw.removeprefix("0x")))


def current_block() -> dict[str, Any]:
    block = rpc("eth_getBlockByNumber", ["latest", False])
    return {
        "number": int(block["number"], 16),
        "timestamp": int(block["timestamp"], 16),
    }


def native_balance(address: str) -> int:
    return int(rpc("eth_getBalance", [address, "latest"]), 16)


def account_open_orders(account: str) -> list[dict[str, Any]]:
    status, payload = api("GET", f"/v1/orders/open?account={account}&market_id={MARKET_ID}")
    if status != 200:
        raise FlowError(f"Unable to read open orders for {account}: HTTP {status}")
    return payload.get("data", {}).get("orders", [])


def market_details() -> tuple[dict[str, Any], Decimal, Decimal, Decimal]:
    status, payload = api("GET", "/v1/markets")
    if status != 200:
        raise FlowError("Unable to read markets")
    market = next(
        item for item in payload["data"]["markets"] if int(item["market_id"]) == MARKET_ID
    )
    config = market["config"]
    return (
        market,
        Decimal(str(config["step_size"])),
        Decimal(str(config["step_price"])),
        Decimal(str(config["min_order_size"])),
    )


def orderbook() -> tuple[dict[str, Any], Decimal, Decimal]:
    status, payload = api("GET", f"/v1/orderbook?market_id={MARKET_ID}")
    if status != 200:
        raise FlowError(f"Unable to read market-{MARKET_ID} orderbook")
    data = payload.get("data", {})
    if not data.get("bids") or not data.get("asks"):
        raise FlowError(f"Market-{MARKET_ID} orderbook has no two-sided liquidity")
    return data, Decimal(str(data["bids"][0]["price"])), Decimal(str(data["asks"][0]["price"]))


def phase_metrics(config: dict[str, Any], account_b: str) -> dict[str, Any]:
    addresses = config["addresses"]
    block = current_block()
    index_price = int(
        eth_call(
            addresses["oracle"],
            "getIndexPrice(uint16)",
            ("uint16",),
            (MARKET_ID,),
        )[0]
    )
    mark_price = int(
        eth_call(
            addresses["oracle"],
            "getMarkPrice(uint16)",
            ("uint16",),
            (MARKET_ID,),
        )[0]
    )
    withdrawable = int(
        eth_call(
            addresses["collateral_manager"],
            "getWithdrawableUSDC(address)",
            ("address",),
            (account_b,),
        )[0]
    )
    portfolio_status, portfolio = api("GET", f"/v1/portfolio/details?account={account_b}")
    if portfolio_status != 200:
        raise FlowError(f"Unable to read B portfolio: HTTP {portfolio_status}")
    position_status, positions = api("GET", f"/v1/positions?account={account_b}")
    if position_status != 200:
        raise FlowError(f"Unable to read B positions: HTTP {position_status}")
    summary = portfolio.get("data", {}).get("summary", {})
    market_positions = [
        position
        for position in positions.get("data", {}).get("positions", [])
        if int(position.get("market_id", 0)) == MARKET_ID
    ]
    return {
        **block,
        "index_price_wad": index_price,
        "mark_price_wad": mark_price,
        "withdrawable_usdc_wad": withdrawable,
        "api_withdrawable_usdc_wad": summary.get("withdrawable_usdc"),
        "free_cross_margin_balance_wad": summary.get("free_cross_margin_balance"),
        "account_equity_wad": summary.get("account_equity"),
        "position": market_positions[0] if market_positions else None,
    }


def live_impact_prices(config: dict[str, Any], index_price_wad: int) -> tuple[int, int]:
    addresses = config["addresses"]
    result = eth_call(
        addresses["orders_manager"],
        "computeImpactPrices(address,uint16,uint256)",
        ("address", "uint16", "uint256"),
        (addresses["perps_manager"], MARKET_ID, index_price_wad),
        ("uint256", "uint256"),
    )
    return int(result[0]), int(result[1])


def accepted_order(payload: dict[str, Any]) -> bool:
    data = payload.get("data", {})
    return bool(
        isinstance(data, dict)
        and (data.get("success") or data.get("order_id") or data.get("tx_hash"))
    )


def place_jwt_order(
    *,
    account: str,
    token: str,
    side: int,
    size_steps: int,
    price_ticks: int,
    client_order_id: str,
    post_only: bool,
    reduce_only: bool,
    order_type: int,
    time_in_force: int,
) -> tuple[dict[str, Any], str]:
    body = {
        "account": account,
        "market_id": MARKET_ID,
        "size_steps": size_steps,
        "price_ticks": price_ticks,
        "side": side,
        "post_only": post_only,
        "reduce_only": reduce_only,
        "stp_mode": 0,
        "order_type": order_type,
        "time_in_force": time_in_force,
        "builder_id": 0,
        "client_order_id": client_order_id,
        "ttl_units": 0,
        "builder_fee_bps": 0,
    }
    status, payload = api("POST", "/v1/orders/place", body=body, token=token)
    if status != 200 or not accepted_order(payload):
        raise FlowError(f"Order {client_order_id} rejected HTTP {status}: {payload.get('error')}")
    tx_hash = find_tx_hash(payload)
    if tx_hash:
        tx_status, _ = receipt_status(tx_hash)
        if tx_status != "0x1":
            raise FlowError(f"Order transaction failed: {tx_hash}")
    return payload, tx_hash


def cancel_all_a(*, require_success: bool = True) -> dict[str, Any]:
    accounts = load_or_create_accounts()
    jwts = load_jwts()
    status, payload = api(
        "POST",
        "/v1/orders/cancel-all",
        body={"account": accounts["A"]["account"], "market_id": MARKET_ID},
        token=jwts["A"]["access_token"],
    )
    if require_success and (status != 200 or not payload.get("data", {}).get("success")):
        raise FlowError(f"A cancel-all failed HTTP {status}: {payload.get('error')}")
    tx_hash = find_tx_hash(payload)
    if tx_hash:
        tx_status, _ = receipt_status(tx_hash)
        if require_success and tx_status != "0x1":
            raise FlowError(f"A cancel-all transaction failed: {tx_hash}")
    return {"http_status": status, "tx_hash": tx_hash, "response": payload}


def send_eoa_transaction(record: dict[str, str], to: str, calldata: str) -> tuple[str, dict[str, Any]]:
    account = record["account"]
    call = {
        "from": account,
        "to": to_checksum_address(to),
        "data": calldata,
        "value": "0x0",
    }
    rpc("eth_call", [call, "latest"])
    estimated_gas = int(rpc("eth_estimateGas", [call]), 16)
    gas_price = int(rpc("eth_gasPrice", []), 16)
    gas_limit = max(estimated_gas + 20_000, int(estimated_gas * 1.20))
    required_native = gas_limit * gas_price
    available_native = native_balance(account)
    if available_native < required_native:
        raise FlowError(
            f"{account} needs testnet ETH: have {available_native} wei, "
            f"estimated requirement {required_native} wei"
        )
    nonce = int(rpc("eth_getTransactionCount", [account, "pending"]), 16)
    unsigned = {
        "nonce": nonce,
        "gasPrice": gas_price,
        "gas": gas_limit,
        "to": to_checksum_address(to),
        "value": 0,
        "data": calldata,
        "chainId": EXPECTED_CHAIN_ID,
    }
    signed = Account.sign_transaction(unsigned, record["account_private_key"])
    raw_transaction = getattr(signed, "rawTransaction", None)
    if raw_transaction is None:
        raw_transaction = signed.raw_transaction
    tx_hash = rpc("eth_sendRawTransaction", ["0x" + bytes(raw_transaction).hex()])
    tx_status, receipt = receipt_status(tx_hash, attempts=60)
    if tx_status != "0x1":
        raise FlowError(f"EOA transaction failed: {tx_hash}")
    return tx_hash, receipt


def safe_order() -> None:
    public_config()
    accounts = load_or_create_accounts()
    jwts = load_jwts()
    label = "A"
    account = accounts[label]["account"]
    token = jwts[label]["access_token"]

    status, markets_payload = api("GET", "/v1/markets")
    if status != 200:
        raise FlowError("Unable to read markets")
    market = next(m for m in markets_payload["data"]["markets"] if int(m["market_id"]) == 1)
    step_size = float(market["config"]["step_size"])
    step_price = float(market["config"]["step_price"])
    minimum = float(market["config"]["min_order_size"])
    size_steps = int(round(minimum / step_size))

    status, book_payload = api("GET", "/v1/orderbook?market_id=1")
    if status != 200 or not book_payload["data"].get("bids") or not book_payload["data"].get("asks"):
        raise FlowError("Order book unavailable")
    best_bid = float(book_payload["data"]["bids"][0]["price"])
    best_ask = float(book_payload["data"]["asks"][0]["price"])
    safe_price = best_bid * 0.80
    price_ticks = int(safe_price // step_price)
    if price_ticks <= 0 or price_ticks >= 16_777_216:
        raise FlowError("Calculated safe price ticks are invalid")
    if price_ticks * step_price >= best_ask:
        raise FlowError("Post-only guard: calculated price would cross")

    body = {
        "account": account,
        "market_id": 1,
        "size_steps": size_steps,
        "price_ticks": price_ticks,
        "side": 0,
        "post_only": True,
        "reduce_only": False,
        "stp_mode": 0,
        "order_type": 1,
        "time_in_force": 0,
        "builder_id": 0,
        "client_order_id": "831100001",
        "ttl_units": 0,
        "builder_fee_bps": 0,
    }
    status, placed = api("POST", "/v1/orders/place", body=body, token=token)
    write_json(EVIDENCE_DIR / "safe-order-A-place.json", placed, 0o600)
    placed_data = placed.get("data", {})
    place_accepted = bool(
        isinstance(placed_data, dict)
        and (placed_data.get("success") or placed_data.get("order_id") or placed_data.get("tx_hash"))
    )
    if status != 200 or not place_accepted:
        raise FlowError(f"Safe order placement failed HTTP {status}: {placed.get('error')}")
    place_tx = find_tx_hash(placed)
    if place_tx:
        tx_status, _ = receipt_status(place_tx)
        if tx_status != "0x1":
            raise FlowError(f"Safe order transaction failed: {place_tx}")

    open_orders: list[dict[str, Any]] = []
    for _ in range(20):
        _, current = api("GET", f"/v1/orders/open?account={account}&market_id=1")
        open_orders = current.get("data", {}).get("orders", [])
        if open_orders:
            break
        time.sleep(0.5)
    if not open_orders:
        raise FlowError("Placed order was not indexed as OPEN")
    if any(
        (order.get("sender") or order.get("account") or "").lower() != account.lower()
        for order in open_orders
    ):
        raise FlowError("Open-order ownership mismatch")
    write_json(EVIDENCE_DIR / "safe-order-A-open.json", {"orders": open_orders}, 0o600)

    cancel_body = {"account": account, "market_id": 1}
    status, cancelled = api("POST", "/v1/orders/cancel-all", body=cancel_body, token=token)
    write_json(EVIDENCE_DIR / "safe-order-A-cancel.json", cancelled, 0o600)
    if status != 200 or not cancelled.get("data", {}).get("success"):
        raise FlowError(f"Safe order cleanup failed HTTP {status}: {cancelled.get('error')}")
    cancel_tx = find_tx_hash(cancelled)
    if cancel_tx:
        tx_status, _ = receipt_status(cancel_tx)
        if tx_status != "0x1":
            raise FlowError(f"Cancel transaction failed: {cancel_tx}")

    remaining: list[dict[str, Any]] = open_orders
    for _ in range(20):
        _, current = api("GET", f"/v1/orders/open?account={account}&market_id=1")
        remaining = current.get("data", {}).get("orders", [])
        if not remaining:
            break
        time.sleep(0.5)
    if remaining:
        raise FlowError("Cleanup incomplete: Account A still has an open market-1 order")

    result = {
        "account": account,
        "market_id": 1,
        "best_bid_before": best_bid,
        "best_ask_before": best_ask,
        "safe_order_price": price_ticks * step_price,
        "size_steps": size_steps,
        "place_tx": place_tx,
        "cancel_tx": cancel_tx,
        "remaining_orders": 0,
    }
    write_json(EVIDENCE_DIR / "safe-order-summary.json", result, 0o600)
    print(
        f"PASS: A post-only minimum order placed at {result['safe_order_price']} "
        f"(book {best_bid}/{best_ask}) and fully cancelled"
    )
    print(f"place_tx={place_tx or 'reported without tx hash'}")
    print(f"cancel_tx={cancel_tx or 'reported without tx hash'}")


def open_b_long(size_steps: int) -> None:
    public_config()
    accounts = load_or_create_accounts()
    jwts = load_jwts()
    account = accounts["B"]["account"]
    token = jwts["B"]["access_token"]

    status, before = api("GET", f"/v1/positions?account={account}")
    if status != 200:
        raise FlowError("Unable to read B positions")
    existing = [p for p in before.get("data", {}).get("positions", []) if int(p.get("market_id", 0)) == 1]
    if existing and abs(float(existing[0].get("size", "0") or 0)) > 0:
        print(f"B already has a market-1 position; no additional position opened")
        write_json(EVIDENCE_DIR / "b-position-current.json", {"positions": existing}, 0o600)
        return

    status, book = api("GET", "/v1/orderbook?market_id=1")
    if status != 200 or not book["data"].get("asks"):
        raise FlowError("Market-1 asks unavailable")
    best_ask = float(book["data"]["asks"][0]["price"])
    if size_steps < 100 or size_steps > 50_000:
        raise FlowError("B fixture size_steps must be 100..50000")
    size_btc = size_steps * 0.000001
    notional = best_ask * size_btc
    if notional > 4_100:
        raise FlowError(f"B fixture notional guard exceeded: {notional}")

    body = {
        "account": account,
        "market_id": 1,
        "size_steps": size_steps,
        "price_ticks": 0,
        "side": 0,
        "post_only": False,
        "reduce_only": False,
        "stp_mode": 0,
        "order_type": 0,
        "time_in_force": 2,
        "builder_id": 0,
        "client_order_id": "831200001",
        "ttl_units": 0,
        "builder_fee_bps": 0,
    }
    status, placed = api("POST", "/v1/orders/place", body=body, token=token)
    write_json(EVIDENCE_DIR / "b-long-place.json", placed, 0o600)
    placed_data = placed.get("data", {})
    accepted = bool(
        isinstance(placed_data, dict)
        and (placed_data.get("success") or placed_data.get("order_id") or placed_data.get("tx_hash"))
    )
    if status != 200 or not accepted:
        raise FlowError(f"B long placement failed HTTP {status}: {placed.get('error')}")
    tx_hash = find_tx_hash(placed)
    if tx_hash:
        tx_status, _ = receipt_status(tx_hash)
        if tx_status != "0x1":
            raise FlowError(f"B long transaction failed: {tx_hash}")

    position: dict[str, Any] | None = None
    for _ in range(30):
        _, current = api("GET", f"/v1/positions?account={account}")
        matches = [p for p in current.get("data", {}).get("positions", []) if int(p.get("market_id", 0)) == 1]
        if matches and abs(float(matches[0].get("size", "0") or 0)) > 0:
            position = matches[0]
            break
        time.sleep(0.5)
    if position is None:
        raise FlowError("B long transaction mined but position was not indexed")
    write_json(EVIDENCE_DIR / "b-position-open.json", position, 0o600)
    print(
        f"PASS: B long opened market=1 size={position.get('size')} "
        f"entry={position.get('avg_entry_price')} tx={tx_hash}"
    )


def snapshot() -> None:
    config, _ = public_config()
    accounts = load_or_create_accounts()
    account_a = accounts["A"]["account"]
    account_b = accounts["B"]["account"]
    metrics = phase_metrics(config, account_b)
    _, best_bid, best_ask = orderbook()
    result = {
        "chain_id": EXPECTED_CHAIN_ID,
        "account_a": account_a,
        "account_b": account_b,
        "account_a_native_balance_wei": native_balance(account_a),
        "account_b_native_balance_wei": native_balance(account_b),
        "account_a_open_orders": len(account_open_orders(account_a)),
        "best_bid": str(best_bid),
        "best_ask": str(best_ask),
        "metrics_b": metrics,
    }
    write_json(EVIDENCE_DIR / "phase-b-readonly-snapshot.json", result, 0o600)
    print(
        f"READ-ONLY: block={metrics['number']} index={Decimal(metrics['index_price_wad']) / Decimal(10**18)} "
        f"mark={Decimal(metrics['mark_price_wad']) / Decimal(10**18)}"
    )
    print(
        f"B withdrawable={Decimal(metrics['withdrawable_usdc_wad']) / Decimal(10**18)} USDC "
        f"native_gas={result['account_b_native_balance_wei']} wei"
    )
    print(f"A open_orders={result['account_a_open_orders']} book={best_bid}/{best_ask}")


def start_a_impact() -> None:
    config, _ = public_config()
    accounts = load_or_create_accounts()
    jwts = load_jwts()
    account_a = accounts["A"]["account"]
    account_b = accounts["B"]["account"]
    if account_open_orders(account_a):
        raise FlowError("A already has open market-1 orders; cleanup before starting")

    baseline = phase_metrics(config, account_b)
    position = baseline.get("position")
    if not position or abs(int(position.get("size", "0") or 0)) == 0:
        raise FlowError("B has no market-1 position; run open-b-long first")

    _, step_size, step_price, minimum = market_details()
    _, best_bid, best_ask = orderbook()
    best_ask_ticks = int((best_ask / step_price).to_integral_value(rounding=ROUND_FLOOR))
    ask_ticks = best_ask_ticks - 1
    bid_ticks = ask_ticks - 1
    bid_price = Decimal(bid_ticks) * step_price
    ask_price = Decimal(ask_ticks) * step_price
    if not (best_bid < bid_price < ask_price < best_ask):
        raise FlowError(
            f"Impact guard: no safe two-tick gap inside book {best_bid}/{best_ask}"
        )

    minimum_steps = int((minimum / step_size).to_integral_value(rounding=ROUND_CEILING))
    target_steps = int(
        (MIN_IMPACT_ORDER_NOTIONAL_USD / (bid_price * step_size)).to_integral_value(
            rounding=ROUND_CEILING
        )
    )
    size_steps = max(minimum_steps, target_steps)
    bid_notional = Decimal(size_steps) * step_size * bid_price
    ask_notional = Decimal(size_steps) * step_size * ask_price
    if bid_notional < MIN_IMPACT_ORDER_NOTIONAL_USD:
        raise FlowError(
            f"Impact order does not clear the configured ${MIN_IMPACT_ORDER_NOTIONAL_USD} threshold"
        )
    if max(bid_notional, ask_notional) > MAX_IMPACT_ORDER_NOTIONAL_USD:
        raise FlowError(
            f"Impact guard: per-order notional {max(bid_notional, ask_notional)} "
            f"exceeds ${MAX_IMPACT_ORDER_NOTIONAL_USD}"
        )

    stamp = str(int(time.time()))
    buy_client_id = (stamp + "01")[-18:]
    sell_client_id = (stamp + "02")[-18:]
    placed_ids: list[str] = []
    try:
        buy, buy_tx = place_jwt_order(
            account=account_a,
            token=jwts["A"]["access_token"],
            side=0,
            size_steps=size_steps,
            price_ticks=bid_ticks,
            client_order_id=buy_client_id,
            post_only=True,
            reduce_only=False,
            order_type=1,
            time_in_force=0,
        )
        write_json(EVIDENCE_DIR / "impact-A-buy-place.json", buy, 0o600)
        placed_ids.append(str(buy.get("data", {}).get("order_id", "")))

        _, interim_bid, interim_ask = orderbook()
        if interim_bid >= ask_price or interim_ask <= ask_price:
            raise FlowError(
                f"Impact guard tripped after buy: live book {interim_bid}/{interim_ask}"
            )
        sell, sell_tx = place_jwt_order(
            account=account_a,
            token=jwts["A"]["access_token"],
            side=1,
            size_steps=size_steps,
            price_ticks=ask_ticks,
            client_order_id=sell_client_id,
            post_only=True,
            reduce_only=False,
            order_type=1,
            time_in_force=0,
        )
        write_json(EVIDENCE_DIR / "impact-A-sell-place.json", sell, 0o600)
        placed_ids.append(str(sell.get("data", {}).get("order_id", "")))

        live_orders: list[dict[str, Any]] = []
        for _ in range(30):
            live_orders = account_open_orders(account_a)
            live_ids = {str(order.get("order_id", "")) for order in live_orders}
            if all(order_id in live_ids for order_id in placed_ids):
                break
            time.sleep(0.5)
        live_ids = {str(order.get("order_id", "")) for order in live_orders}
        if not placed_ids or any(not order_id or order_id not in live_ids for order_id in placed_ids):
            raise FlowError("Impact orders were not both indexed as OPEN")

        after = phase_metrics(config, account_b)
        impact_bid_wad, impact_ask_wad = live_impact_prices(config, after["index_price_wad"])
        bid_price_wad = int(bid_price * Decimal(10**18))
        ask_price_wad = int(ask_price * Decimal(10**18))
        tolerance_wad = int(step_price * Decimal(2) * Decimal(10**18))
        if (
            impact_bid_wad < bid_price_wad - tolerance_wad
            or impact_ask_wad > ask_price_wad + tolerance_wad
        ):
            raise FlowError(
                "Impact verification failed: live contract impact prices are "
                f"{Decimal(impact_bid_wad) / Decimal(10**18)}/"
                f"{Decimal(impact_ask_wad) / Decimal(10**18)}, expected near "
                f"{bid_price}/{ask_price}"
            )
        state = {
            "chain_id": EXPECTED_CHAIN_ID,
            "market_id": MARKET_ID,
            "account_a": account_a,
            "account_b": account_b,
            "started_at": int(time.time()),
            "baseline": baseline,
            "after_placement": after,
            "verified_impact_bid_wad": impact_bid_wad,
            "verified_impact_ask_wad": impact_ask_wad,
            "orders": {
                "buy": {
                    "order_id": placed_ids[0],
                    "tx_hash": buy_tx,
                    "client_order_id": buy_client_id,
                    "price_ticks": bid_ticks,
                    "price": str(bid_price),
                    "size_steps": size_steps,
                    "notional_usdc": str(bid_notional),
                },
                "sell": {
                    "order_id": placed_ids[1],
                    "tx_hash": sell_tx,
                    "client_order_id": sell_client_id,
                    "price_ticks": ask_ticks,
                    "price": str(ask_price),
                    "size_steps": size_steps,
                    "notional_usdc": str(ask_notional),
                },
            },
        }
        write_json(PHASE_STATE_FILE, state, 0o600)
        print(
            f"PASS: A impact pair OPEN at {bid_price}/{ask_price}; "
            f"size={Decimal(size_steps) * step_size} BTC each"
        )
        print(f"buy_tx={buy_tx} sell_tx={sell_tx}")
    except Exception:
        if placed_ids:
            cleanup = cancel_all_a(require_success=False)
            write_json(EVIDENCE_DIR / "impact-start-emergency-cancel.json", cleanup, 0o600)
        raise


def persist_timeline(state: dict[str, Any], samples: list[dict[str, Any]]) -> None:
    write_json(TIMELINE_JSON, {"state": state, "samples": samples}, 0o600)
    with TIMELINE_CSV.open("w", encoding="utf-8", newline="") as handle:
        fields = [
            "elapsed_seconds",
            "number",
            "timestamp",
            "index_price_wad",
            "mark_price_wad",
            "withdrawable_usdc_wad",
            "api_withdrawable_usdc_wad",
            "free_cross_margin_balance_wad",
            "account_equity_wad",
            "best_bid",
            "best_ask",
            "a_live_order_count",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(samples)


def monitor_impact(duration: int, interval: int, target_amount_usdc: Decimal) -> None:
    if not PHASE_STATE_FILE.exists():
        raise FlowError("Impact state missing; run start-a-impact first")
    if duration < 60 or duration > 900:
        raise FlowError("Monitor duration must be 60..900 seconds")
    if interval < 10 or interval > 60:
        raise FlowError("Monitor interval must be 10..60 seconds")
    config, _ = public_config()
    accounts = load_or_create_accounts()
    state = json.loads(PHASE_STATE_FILE.read_text(encoding="utf-8"))
    expected_ids = {
        state["orders"]["buy"]["order_id"],
        state["orders"]["sell"]["order_id"],
    }
    account_a = accounts["A"]["account"]
    account_b = accounts["B"]["account"]
    samples: list[dict[str, Any]] = []
    sync_transactions: list[dict[str, Any]] = []
    target_wad = int(target_amount_usdc * Decimal(10**18))
    started = time.monotonic()
    next_sample = 0.0
    next_sync = float(interval)
    target_reached = False
    while True:
        elapsed = time.monotonic() - started
        orders = account_open_orders(account_a)
        live_ids = {str(order.get("order_id", "")) for order in orders}
        if not expected_ids.issubset(live_ids):
            emergency = cancel_all_a(require_success=False)
            write_json(EVIDENCE_DIR / "impact-monitor-emergency-cancel.json", emergency, 0o600)
            state["monitor"] = {
                "outcome": "impact_order_disappeared_or_filled",
                "elapsed_seconds": elapsed,
                "sync_transactions": sync_transactions,
            }
            persist_timeline(state, samples)
            write_json(PHASE_STATE_FILE, state, 0o600)
            raise FlowError("An A impact order disappeared or filled; emergency cancel-all submitted")

        synced_now = False
        if elapsed >= next_sync:
            index_tx, index_receipt = send_eoa_transaction(
                accounts["B"],
                config["addresses"]["oracle"],
                function_data("syncIndexBlockEMA(uint16)", ("uint16",), (MARKET_ID,)),
            )
            mark_tx, mark_receipt = send_eoa_transaction(
                accounts["B"],
                config["addresses"]["oracle"],
                function_data("syncMarkPriceEMA(uint16)", ("uint16",), (MARKET_ID,)),
            )
            sync_transactions.append(
                {
                    "elapsed_seconds": elapsed,
                    "index_tx": index_tx,
                    "index_block": int(index_receipt["blockNumber"], 16),
                    "mark_tx": mark_tx,
                    "mark_block": int(mark_receipt["blockNumber"], 16),
                }
            )
            print(f"permissionless-sync index_tx={index_tx} mark_tx={mark_tx}", flush=True)
            next_sync += interval
            synced_now = True

        if elapsed >= next_sample or elapsed >= duration or synced_now:
            metrics = phase_metrics(config, account_b)
            _, best_bid, best_ask = orderbook()
            sample = {
                "elapsed_seconds": round(min(elapsed, float(duration)), 3),
                **metrics,
                "best_bid": str(best_bid),
                "best_ask": str(best_ask),
                "a_live_order_count": len(orders),
            }
            samples.append(sample)
            delta = metrics["withdrawable_usdc_wad"] - state["baseline"]["withdrawable_usdc_wad"]
            print(
                f"t={sample['elapsed_seconds']:.0f}s block={metrics['number']} "
                f"mark={Decimal(metrics['mark_price_wad']) / Decimal(10**18)} "
                f"withdrawable_delta={Decimal(delta) / Decimal(10**18)} USDC",
                flush=True,
            )
            next_sample += interval
            if sync_transactions and delta >= target_wad:
                target_reached = True
                break
        if elapsed >= duration:
            break
        time.sleep(min(5.0, max(0.2, duration - elapsed)))

    final_delta = samples[-1]["withdrawable_usdc_wad"] - state["baseline"]["withdrawable_usdc_wad"]
    state["monitor"] = {
        "outcome": "target_reached" if target_reached else "duration_exhausted",
        "duration_seconds": duration,
        "elapsed_seconds": time.monotonic() - started,
        "samples": len(samples),
        "final_withdrawable_delta_wad": final_delta,
        "target_withdrawable_delta_wad": target_wad,
        "sync_transactions": sync_transactions,
    }
    persist_timeline(state, samples)
    write_json(PHASE_STATE_FILE, state, 0o600)
    if not target_reached:
        raise FlowError(
            f"Impact target not reached in {duration}s; final delta="
            f"{Decimal(final_delta) / Decimal(10**18)} USDC"
        )
    print(
        f"PASS: impact target reached; final delta={Decimal(final_delta) / Decimal(10**18)} USDC"
    )


def token_balance(token: str, account: str) -> int:
    return int(
        eth_call(
            token,
            "balanceOf(address)",
            ("address",),
            (account,),
        )[0]
    )


def withdraw_b(amount_usdc: Decimal) -> None:
    if amount_usdc <= 0 or amount_usdc > MAX_WITHDRAW_USDC:
        raise FlowError(f"Withdrawal must be >0 and <= {MAX_WITHDRAW_USDC} USDC")
    if not PHASE_STATE_FILE.exists():
        raise FlowError("Impact state missing; run and monitor the impact phase first")
    config, _ = public_config()
    accounts = load_or_create_accounts()
    state = json.loads(PHASE_STATE_FILE.read_text(encoding="utf-8"))
    account_a = accounts["A"]["account"]
    account_b = accounts["B"]["account"]
    expected_ids = {
        state["orders"]["buy"]["order_id"],
        state["orders"]["sell"]["order_id"],
    }
    live_ids = {str(order.get("order_id", "")) for order in account_open_orders(account_a)}
    if not expected_ids.issubset(live_ids):
        raise FlowError("Both A impact orders must remain OPEN before withdrawal")

    before_metrics = phase_metrics(config, account_b)
    delta_wad = before_metrics["withdrawable_usdc_wad"] - state["baseline"]["withdrawable_usdc_wad"]
    requested_wad = int(amount_usdc * Decimal(10**18))
    if delta_wad < requested_wad:
        raise FlowError(
            f"Incremental withdrawable is only {Decimal(delta_wad) / Decimal(10**18)} USDC"
        )

    collateral = config["addresses"]["collateral_manager"]
    token = config["addresses"]["usdc"]
    amount_token_units = int(amount_usdc * Decimal(10**6))
    calldata = function_data(
        "withdraw(address,address,uint256)",
        ("address", "address", "uint256"),
        (account_b, token, amount_token_units),
    )
    transaction_for_call = {
        "from": account_b,
        "to": collateral,
        "data": calldata,
        "value": "0x0",
    }
    rpc("eth_call", [transaction_for_call, "latest"])
    estimated_gas = int(rpc("eth_estimateGas", [transaction_for_call]), 16)
    gas_price = int(rpc("eth_gasPrice", []), 16)
    gas_limit = max(estimated_gas + 20_000, int(estimated_gas * 1.20))
    required_native = gas_limit * gas_price
    available_native = native_balance(account_b)
    if available_native < required_native:
        raise FlowError(
            f"B needs testnet ETH for direct withdrawal: have {available_native} wei, "
            f"estimated requirement {required_native} wei. Fund {account_b} from the official faucet."
        )

    before_token = token_balance(token, account_b)
    nonce = int(rpc("eth_getTransactionCount", [account_b, "pending"]), 16)
    unsigned = {
        "nonce": nonce,
        "gasPrice": gas_price,
        "gas": gas_limit,
        "to": to_checksum_address(collateral),
        "value": 0,
        "data": calldata,
        "chainId": EXPECTED_CHAIN_ID,
    }
    signed = Account.sign_transaction(unsigned, accounts["B"]["account_private_key"])
    raw_transaction = getattr(signed, "rawTransaction", None)
    if raw_transaction is None:
        raw_transaction = signed.raw_transaction
    tx_hash = rpc("eth_sendRawTransaction", ["0x" + bytes(raw_transaction).hex()])
    tx_status, receipt = receipt_status(tx_hash, attempts=60)
    if tx_status != "0x1":
        raise FlowError(f"B withdrawal transaction failed: {tx_hash}")
    after_token = token_balance(token, account_b)
    if after_token - before_token != amount_token_units:
        raise FlowError(
            f"Withdrawal receipt succeeded but token delta was {after_token - before_token}, "
            f"expected {amount_token_units}"
        )
    remaining_ids = {str(order.get("order_id", "")) for order in account_open_orders(account_a)}
    if not expected_ids.issubset(remaining_ids):
        raise FlowError("Withdrawal settled, but an A impact order no longer remains OPEN")
    after_metrics = phase_metrics(config, account_b)
    evidence = {
        "chain_id": EXPECTED_CHAIN_ID,
        "account_b": account_b,
        "amount_usdc": str(amount_usdc),
        "amount_token_units": amount_token_units,
        "incremental_withdrawable_before_wad": delta_wad,
        "token_balance_before": before_token,
        "token_balance_after": after_token,
        "tx_hash": tx_hash,
        "block_number": int(receipt["blockNumber"], 16),
        "a_impact_orders_still_open": True,
        "metrics_before": before_metrics,
        "metrics_after": after_metrics,
    }
    write_json(EVIDENCE_DIR / "b-incremental-withdrawal.json", evidence, 0o600)
    state["withdrawal"] = evidence
    write_json(PHASE_STATE_FILE, state, 0o600)
    print(f"PASS: B settled {amount_usdc} USDC while both A impact orders remained OPEN")
    print(f"withdraw_tx={tx_hash}")


def close_position(label: str) -> dict[str, Any]:
    accounts = load_or_create_accounts()
    jwts = load_jwts()
    account = accounts[label]["account"]
    _, step_size, step_price, _ = market_details()
    chunks: list[dict[str, Any]] = []
    initial_size_wad: int | None = None
    no_progress = 0
    for chunk_index in range(24):
        status, payload = api("GET", f"/v1/positions?account={account}")
        if status != 200:
            raise FlowError(f"Unable to read {label} positions")
        positions = [
            position
            for position in payload.get("data", {}).get("positions", [])
            if int(position.get("market_id", 0)) == MARKET_ID
            and abs(int(position.get("size", "0") or 0)) > 0
        ]
        if not positions:
            break
        position = positions[0]
        size_wad = int(position["size"])
        if initial_size_wad is None:
            initial_size_wad = size_wad
        size_base = abs(Decimal(size_wad)) / Decimal(10**18)
        size_steps_decimal = size_base / step_size
        remaining_steps = int(size_steps_decimal.to_integral_value(rounding=ROUND_FLOOR))
        if remaining_steps <= 0 or Decimal(remaining_steps) != size_steps_decimal:
            raise FlowError(f"{label} position is not aligned to market step size")
        side = 1 if size_wad > 0 or str(position.get("side", "")).upper() == "BUY" else 0

        book, _, _ = orderbook()
        levels = book["bids"] if side == 1 else book["asks"]
        top_price = Decimal(str(levels[0]["price"]))
        price_ticks_decimal = top_price / step_price
        price_ticks = int(price_ticks_decimal.to_integral_value(rounding=ROUND_FLOOR))
        if price_ticks <= 0 or Decimal(price_ticks) != price_ticks_decimal:
            raise FlowError(f"Top-of-book price is not aligned to ticks for {label}")
        top_quantity = Decimal(str(levels[0]["quantity"]))
        top_steps = int((top_quantity / step_size).to_integral_value(rounding=ROUND_FLOOR))
        chunk_steps = min(remaining_steps, top_steps)
        if chunk_steps <= 0:
            raise FlowError(f"No top-level liquidity available to close {label}")

        order, tx_hash = place_jwt_order(
            account=account,
            token=jwts[label]["access_token"],
            side=side,
            size_steps=chunk_steps,
            price_ticks=price_ticks,
            client_order_id=(str(int(time.time() * 1000)) + str(chunk_index))[-18:],
            post_only=False,
            reduce_only=True,
            order_type=1,
            time_in_force=3,
        )
        chunks.append(
            {
                "size_steps": chunk_steps,
                "tx_hash": tx_hash,
                "limit_price": str(top_price),
                "order_type": "LIMIT",
                "time_in_force": "IOC",
                "response": order,
            }
        )
        previous_size = abs(size_wad)
        changed = False
        for _ in range(40):
            _, current = api("GET", f"/v1/positions?account={account}")
            current_positions = [
                item
                for item in current.get("data", {}).get("positions", [])
                if int(item.get("market_id", 0)) == MARKET_ID
                and abs(int(item.get("size", "0") or 0)) > 0
            ]
            if not current_positions or abs(int(current_positions[0]["size"])) < previous_size:
                changed = True
                break
            time.sleep(0.5)
        if not changed:
            no_progress += 1
            if no_progress >= 3:
                raise FlowError(
                    f"{label} cleanup made no progress after 3 reduce-only limit IOC attempts"
                )
            time.sleep(1)
            continue
        no_progress = 0
    else:
        raise FlowError(f"{label} cleanup exceeded maximum chunk count")

    if initial_size_wad is None:
        return {"label": label, "already_flat": True}
    return {
        "label": label,
        "already_flat": False,
        "closed_size_wad": initial_size_wad,
        "chunks": chunks,
    }


def cleanup_phase() -> None:
    public_config()
    results: dict[str, Any] = {}
    errors: list[str] = []
    try:
        results["cancel_a"] = cancel_all_a(require_success=True)
    except Exception as exc:
        errors.append(f"cancel A: {exc}")
    for label in ("A", "B"):
        try:
            results[f"close_{label.lower()}"] = close_position(label)
        except Exception as exc:
            errors.append(f"close {label}: {exc}")
    accounts = load_or_create_accounts()
    try:
        results["a_remaining_orders"] = len(account_open_orders(accounts["A"]["account"]))
    except Exception as exc:
        errors.append(f"verify A orders: {exc}")
    results["errors"] = errors
    write_json(EVIDENCE_DIR / "phase-b-cleanup.json", results, 0o600)
    if errors:
        raise FlowError("Cleanup incomplete: " + "; ".join(errors))
    print("PASS: A orders cancelled and A/B market-1 positions are flat")


def full_phase(duration: int, interval: int, amount_usdc: Decimal) -> None:
    primary_error: Exception | None = None
    try:
        start_a_impact()
        monitor_impact(duration, interval, amount_usdc)
        withdraw_b(amount_usdc)
    except Exception as exc:
        primary_error = exc
    finally:
        try:
            cleanup_phase()
        except Exception as cleanup_error:
            if primary_error is not None:
                raise FlowError(
                    f"Phase failed: {primary_error}; cleanup also failed: {cleanup_error}"
                ) from primary_error
            raise
    if primary_error is not None:
        raise primary_error


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=(
            "bootstrap",
            "approve-jwt",
            "safe-order",
            "open-b-long",
            "snapshot",
            "start-a-impact",
            "monitor-impact",
            "withdraw-b",
            "cleanup",
            "full-phase",
        ),
    )
    parser.add_argument("--duration", type=int, default=480)
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--withdraw-usdc", type=Decimal, default=Decimal("1"))
    parser.add_argument("--b-size-steps", type=int, default=50_000)
    args = parser.parse_args()
    if args.action == "bootstrap":
        bootstrap()
    elif args.action == "approve-jwt":
        approve_jwt()
    elif args.action == "safe-order":
        safe_order()
    elif args.action == "open-b-long":
        open_b_long(args.b_size_steps)
    elif args.action == "snapshot":
        snapshot()
    elif args.action == "start-a-impact":
        start_a_impact()
    elif args.action == "monitor-impact":
        monitor_impact(args.duration, args.interval, args.withdraw_usdc)
    elif args.action == "withdraw-b":
        withdraw_b(args.withdraw_usdc)
    elif args.action == "cleanup":
        cleanup_phase()
    elif args.action == "full-phase":
        full_phase(args.duration, args.interval, args.withdraw_usdc)


if __name__ == "__main__":
    try:
        main()
    except (FlowError, requests.RequestException, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
