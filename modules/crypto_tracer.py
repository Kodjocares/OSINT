"""
modules/crypto_tracer.py — Cryptocurrency & blockchain OSINT
Bitcoin, Ethereum address lookup, transaction history, cluster analysis
"""

import re
import logging
from typing import Dict, List, Optional
from utils.helpers import safe_request

logger = logging.getLogger(__name__)

BTC_API   = "https://blockchain.info"
ETH_API   = "https://api.etherscan.io/api"
BLOCKCHAIR= "https://api.blockchair.com"


class CryptoTracer:
    """Blockchain OSINT — address lookup, transaction tracing, wallet intelligence."""

    def __init__(self, etherscan_key: str = ""):
        self.etherscan_key = etherscan_key

    # ──────────────────────────────────────────────────────────
    # AUTO-DETECT & ROUTE
    # ──────────────────────────────────────────────────────────
    def lookup(self, address: str) -> Dict:
        """Auto-detect crypto address type and run appropriate lookup."""
        address = address.strip()
        addr_type = self._detect_address_type(address)

        if addr_type == "bitcoin":
            return self.bitcoin_lookup(address)
        elif addr_type == "ethereum":
            return self.ethereum_lookup(address)
        else:
            return {"address": address, "error": f"Unrecognized address format: {address[:20]}..."}

    # ──────────────────────────────────────────────────────────
    # BITCOIN
    # ──────────────────────────────────────────────────────────
    def bitcoin_lookup(self, address: str) -> Dict:
        result = {
            "address": address,
            "blockchain": "bitcoin",
            "balance_btc": None,
            "balance_usd": None,
            "total_received": None,
            "total_sent": None,
            "tx_count": None,
            "transactions": [],
            "first_seen": None,
            "last_seen": None,
            "risk_flags": [],
        }

        # Blockchain.info
        resp = safe_request(f"{BTC_API}/rawaddr/{address}",
                            params={"limit": 10})
        if resp and resp.status_code == 200:
            d = resp.json()
            satoshi = 100_000_000
            result["balance_btc"]    = d.get("final_balance", 0) / satoshi
            result["total_received"] = d.get("total_received", 0) / satoshi
            result["total_sent"]     = d.get("total_sent", 0) / satoshi
            result["tx_count"]       = d.get("n_tx", 0)

            txs = d.get("txs", [])
            for tx in txs[:10]:
                result["transactions"].append({
                    "hash":          tx.get("hash"),
                    "time":          tx.get("time"),
                    "inputs":        len(tx.get("inputs", [])),
                    "outputs":       len(tx.get("out", [])),
                    "result_satoshi":tx.get("result", 0),
                    "explorer_url":  f"https://www.blockchain.com/btc/tx/{tx.get('hash')}",
                })

            if txs:
                result["first_seen"] = min(t.get("time", 0) for t in txs)
                result["last_seen"]  = max(t.get("time", 0) for t in txs)

        # Get USD price
        price_resp = safe_request("https://blockchain.info/ticker")
        if price_resp and price_resp.status_code == 200:
            usd_rate = price_resp.json().get("USD", {}).get("last", 0)
            if result["balance_btc"] is not None:
                result["balance_usd"] = round(result["balance_btc"] * usd_rate, 2)
                result["usd_rate"]    = usd_rate

        result["explorer_url"] = f"https://www.blockchain.com/btc/address/{address}"
        result["risk_flags"]   = self._assess_btc_risk(result)
        return result

    # ──────────────────────────────────────────────────────────
    # ETHEREUM
    # ──────────────────────────────────────────────────────────
    def ethereum_lookup(self, address: str) -> Dict:
        result = {
            "address":    address,
            "blockchain": "ethereum",
            "balance_eth": None,
            "balance_usd": None,
            "tx_count":   None,
            "transactions": [],
            "tokens":     [],
            "is_contract":False,
            "risk_flags": [],
        }

        # Etherscan — balance
        key_param = f"&apikey={self.etherscan_key}" if self.etherscan_key else ""
        bal_resp = safe_request(
            f"https://api.etherscan.io/api?module=account&action=balance"
            f"&address={address}&tag=latest{key_param}"
        )
        if bal_resp and bal_resp.status_code == 200:
            d = bal_resp.json()
            if d.get("status") == "1":
                wei = int(d.get("result", 0))
                result["balance_eth"] = wei / 10**18

        # Transactions
        tx_resp = safe_request(
            f"https://api.etherscan.io/api?module=account&action=txlist"
            f"&address={address}&startblock=0&endblock=99999999"
            f"&page=1&offset=10&sort=desc{key_param}"
        )
        if tx_resp and tx_resp.status_code == 200:
            txs = tx_resp.json().get("result", [])
            if isinstance(txs, list):
                for tx in txs[:10]:
                    result["transactions"].append({
                        "hash":        tx.get("hash"),
                        "from":        tx.get("from"),
                        "to":          tx.get("to"),
                        "value_eth":   int(tx.get("value", 0)) / 10**18,
                        "timestamp":   tx.get("timeStamp"),
                        "block":       tx.get("blockNumber"),
                        "gas_used":    tx.get("gasUsed"),
                        "is_error":    tx.get("isError") == "1",
                        "explorer_url":f"https://etherscan.io/tx/{tx.get('hash')}",
                    })
                result["tx_count"] = len(txs)

        # Token holdings
        token_resp = safe_request(
            f"https://api.etherscan.io/api?module=account&action=tokentx"
            f"&address={address}&page=1&offset=20&sort=desc{key_param}"
        )
        if token_resp and token_resp.status_code == 200:
            token_txs = token_resp.json().get("result", [])
            if isinstance(token_txs, list):
                seen = set()
                for tx in token_txs:
                    sym = tx.get("tokenSymbol", "")
                    if sym and sym not in seen:
                        seen.add(sym)
                        result["tokens"].append({
                            "symbol": sym,
                            "name":   tx.get("tokenName"),
                        })

        result["explorer_url"] = f"https://etherscan.io/address/{address}"
        result["risk_flags"]   = self._assess_eth_risk(result)
        return result

    # ──────────────────────────────────────────────────────────
    # BLOCKCHAIR MULTI-CHAIN
    # ──────────────────────────────────────────────────────────
    def blockchair_lookup(self, address: str, chain: str = "bitcoin") -> Dict:
        """Query Blockchair for multi-chain address data."""
        resp = safe_request(f"{BLOCKCHAIR}/{chain}/dashboards/address/{address}")
        if resp and resp.status_code == 200:
            data = resp.json().get("data", {}).get(address, {})
            addr = data.get("address", {})
            return {
                "address":      address,
                "chain":        chain,
                "balance":      addr.get("balance"),
                "tx_count":     addr.get("transaction_count"),
                "first_seen":   addr.get("first_seen_receiving"),
                "last_seen":    addr.get("last_seen_receiving"),
                "total_received": addr.get("received"),
                "total_spent":  addr.get("spent"),
                "dust_warning": addr.get("dust_value", 0) > 0,
            }
        return {"address": address, "error": "Blockchair lookup failed"}

    # ──────────────────────────────────────────────────────────
    # DETECT ADDRESS TYPE
    # ──────────────────────────────────────────────────────────
    def _detect_address_type(self, address: str) -> str:
        if re.match(r"^(1|3)[a-zA-HJ-NP-Z1-9]{25,34}$", address):
            return "bitcoin"
        if re.match(r"^bc1[a-zA-HJ-NP-Z0-9]{6,87}$", address):
            return "bitcoin_segwit"
        if re.match(r"^0x[a-fA-F0-9]{40}$", address):
            return "ethereum"
        if re.match(r"^L[a-zA-HJ-NP-Z1-9]{26,33}$", address):
            return "litecoin"
        if re.match(r"^D[a-zA-HJ-NP-Z0-9]{33}$", address):
            return "dogecoin"
        return "unknown"

    def _assess_btc_risk(self, result: Dict) -> List[str]:
        flags = []
        if (result.get("total_received") or 0) > 100:
            flags.append("High-volume wallet (>100 BTC received)")
        if (result.get("tx_count") or 0) > 1000:
            flags.append("Very high transaction count (>1000 txs)")
        return flags

    def _assess_eth_risk(self, result: Dict) -> List[str]:
        flags = []
        if result.get("is_contract"):
            flags.append("Smart contract address")
        if (result.get("balance_eth") or 0) > 100:
            flags.append("High-value wallet (>100 ETH)")
        return flags
