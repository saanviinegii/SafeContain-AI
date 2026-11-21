"""SafeContain AI EVM Blockchain Client & JSON-RPC Connection Manager.

Integrates directly with EVM testnets (Ethereum Sepolia, Arbitrum Sepolia, local EVM testbeds)
using standard JSON-RPC 2.0. Handles contract calls, batch evidence root anchoring,
gas estimation, EIP-155 signing, receipt verification, and block confirmation tracking.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

import httpx
from backend.app.core.config import settings
from backend.app.audit.crypto_utils import (
    keccak_256,
    private_key_to_address,
    sign_transaction,
    encode_abi_call,
    decode_abi_output,
    to_checksum_address,
)

logger = logging.getLogger(__name__)


class BlockchainNetworkConfig(BaseModel):
    """Configuration for EVM blockchain network connection."""
    enabled: bool = True
    network_name: str = "Ethereum Sepolia Testnet"
    chain_id: int = 11155111
    rpc_url: Optional[str] = None
    wallet_address: Optional[str] = None
    contract_address: Optional[str] = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    confirmations: int = 1
    timeout_seconds: float = 10.0
    explorer_tx_template: str = "https://sepolia.etherscan.io/tx/{tx_hash}"
    explorer_address_template: str = "https://sepolia.etherscan.io/address/{address}"


class BlockchainStatusReport(BaseModel):
    """Full operational health and connectivity summary of the blockchain anchor."""
    connected: bool
    mode: str = Field(description="LIVE_TESTNET | RPC_UNAVAILABLE | UNCONFIGURED")
    network_name: str
    chain_id: int
    contract_address: Optional[str] = None
    wallet_address: Optional[str] = None
    wallet_balance_eth: Optional[float] = None
    current_block_height: Optional[int] = None
    required_confirmations: int = 1
    status_message: str
    can_anchor_on_chain: bool
    explorer_tx_template: str
    explorer_address_template: str


class OnChainTransactionResult(BaseModel):
    """Result of an on-chain smart contract transaction attempt."""
    success: bool
    tx_hash: Optional[str] = None
    block_number: Optional[int] = None
    confirmations: int = 0
    gas_used: Optional[int] = None
    status: str = Field(description="CONFIRMED | PENDING | REVERTED | FAILED | NOT_SUBMITTED")
    explorer_url: Optional[str] = None
    error_message: Optional[str] = None


class BlockchainClient:
    """Enterprise EVM JSON-RPC Client for SafeContain Evidence Anchoring."""

    def __init__(self, config: Optional[BlockchainNetworkConfig] = None):
        self.config = config or self._load_default_config()
        self._private_key: Optional[str] = settings.BLOCKCHAIN_PRIVATE_KEY
        if self._private_key and not self.config.wallet_address:
            try:
                self.config.wallet_address = private_key_to_address(self._private_key)
            except Exception as e:
                logger.warning("Could not derive wallet address from private key: %s", e)

    @classmethod
    def _load_default_config(cls) -> BlockchainNetworkConfig:
        return BlockchainNetworkConfig(
            enabled=getattr(settings, "BLOCKCHAIN_ENABLED", True),
            network_name=getattr(settings, "BLOCKCHAIN_NETWORK_NAME", "Ethereum Sepolia Testnet"),
            chain_id=getattr(settings, "BLOCKCHAIN_CHAIN_ID", 11155111),
            rpc_url=settings.BLOCKCHAIN_RPC_URL,
            contract_address=settings.BLOCKCHAIN_CONTRACT_ADDRESS or "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            confirmations=getattr(settings, "BLOCKCHAIN_CONFIRMATIONS", 1),
            timeout_seconds=getattr(settings, "BLOCKCHAIN_TIMEOUT_SECONDS", 10.0),
        )

    def _rpc_call(self, method: str, params: List[Any]) -> Any:
        """Executes a standard Ethereum JSON-RPC 2.0 call."""
        if not self.config.rpc_url:
            raise ConnectionError("BLOCKCHAIN_RPC_URL is not configured.")

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        with httpx.Client(timeout=self.config.timeout_seconds) as client:
            resp = client.post(
                self.config.rpc_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                raise RuntimeError(f"JSON-RPC Error ({data['error'].get('code')}): {data['error'].get('message')}")
            return data.get("result")

    def get_block_number(self) -> int:
        """Queries the latest block number."""
        res = self._rpc_call("eth_blockNumber", [])
        return int(res, 16)

    def get_chain_id(self) -> int:
        """Queries the EVM chain ID."""
        res = self._rpc_call("eth_chainId", [])
        return int(res, 16)

    def get_balance(self, address: str) -> float:
        """Queries native token balance (ETH) for address."""
        res = self._rpc_call("eth_getBalance", [address, "latest"])
        wei = int(res, 16)
        return wei / 1e18

    def get_transaction_count(self, address: str) -> int:
        """Queries transaction nonce for account."""
        res = self._rpc_call("eth_getTransactionCount", [address, "pending"])
        return int(res, 16)

    def get_gas_price(self) -> int:
        """Queries current recommended gas price in wei."""
        res = self._rpc_call("eth_gasPrice", [])
        return int(res, 16)

    def eth_call(self, to_address: str, data_hex: str) -> str:
        """Executes a read-only smart contract view call."""
        tx_obj = {"to": to_address, "data": data_hex}
        return self._rpc_call("eth_call", [tx_obj, "latest"])

    def get_status(self) -> BlockchainStatusReport:
        """Evaluates operational readiness of EVM connection."""
        has_rpc = bool(self.config.rpc_url)
        has_key = bool(self._private_key)
        has_contract = bool(self.config.contract_address)

        if not has_rpc:
            return BlockchainStatusReport(
                connected=False,
                mode="UNCONFIGURED",
                network_name=self.config.network_name,
                chain_id=self.config.chain_id,
                contract_address=self.config.contract_address,
                wallet_address=self.config.wallet_address,
                wallet_balance_eth=None,
                current_block_height=None,
                required_confirmations=self.config.confirmations,
                status_message="BLOCKCHAIN UNAVAILABLE: Set BLOCKCHAIN_RPC_URL and BLOCKCHAIN_PRIVATE_KEY in .env.",
                can_anchor_on_chain=False,
                explorer_tx_template=self.config.explorer_tx_template,
                explorer_address_template=self.config.explorer_address_template,
            )

        try:
            curr_block = self.get_block_number()
            chain_id = self.get_chain_id()
            balance = None
            if self.config.wallet_address:
                try:
                    balance = self.get_balance(self.config.wallet_address)
                except Exception:
                    pass

            can_anchor = has_key and has_contract and (balance is not None and balance > 0)
            status_msg = "CONNECTED: Ready to anchor evidence on-chain." if can_anchor else (
                "CONNECTED: Read-only mode (wallet requires private key or testnet ETH to anchor)."
            )

            return BlockchainStatusReport(
                connected=True,
                mode="LIVE_TESTNET",
                network_name=self.config.network_name,
                chain_id=chain_id,
                contract_address=self.config.contract_address,
                wallet_address=self.config.wallet_address,
                wallet_balance_eth=balance,
                current_block_height=curr_block,
                required_confirmations=self.config.confirmations,
                status_message=status_msg,
                can_anchor_on_chain=can_anchor,
                explorer_tx_template=self.config.explorer_tx_template,
                explorer_address_template=self.config.explorer_address_template,
            )
        except Exception as e:
            return BlockchainStatusReport(
                connected=False,
                mode="RPC_UNAVAILABLE",
                network_name=self.config.network_name,
                chain_id=self.config.chain_id,
                contract_address=self.config.contract_address,
                wallet_address=self.config.wallet_address,
                wallet_balance_eth=None,
                current_block_height=None,
                required_confirmations=self.config.confirmations,
                status_message=f"RPC Connection Error: {str(e)}",
                can_anchor_on_chain=False,
                explorer_tx_template=self.config.explorer_tx_template,
                explorer_address_template=self.config.explorer_address_template,
            )

    def anchor_batch_on_chain(
        self,
        anchor_id_hex: str,
        evidence_root_hex: str,
        first_sequence: int,
        last_sequence: int,
        record_count: int,
    ) -> OnChainTransactionResult:
        """Encodes, signs, and broadcasts an anchorBatch transaction to the smart contract."""
        status = self.get_status()
        if not status.connected or not status.can_anchor_on_chain:
            return OnChainTransactionResult(
                success=False,
                status="FAILED",
                error_message=f"Cannot submit on-chain transaction: {status.status_message}"
            )

        if not self._private_key or not self.config.contract_address:
            return OnChainTransactionResult(
                success=False,
                status="FAILED",
                error_message="Missing private key or contract address."
            )

        try:
            # 1. ABI encode calldata for anchorBatch(bytes32,bytes32,uint256,uint256,uint256)
            calldata_hex = encode_abi_call(
                "anchorBatch(bytes32,bytes32,uint256,uint256,uint256)",
                [anchor_id_hex, evidence_root_hex, first_sequence, last_sequence, record_count],
                ["bytes32", "bytes32", "uint256", "uint256", "uint256"]
            )
            calldata_bytes = bytes.fromhex(calldata_hex[2:])

            # 2. Get nonce and gas parameters
            nonce = self.get_transaction_count(self.config.wallet_address)
            gas_price = self.get_gas_price()
            # Safety multiplier on gas price (1.2x)
            gas_price = int(gas_price * 1.2)
            gas_limit = 250000

            # 3. Sign EIP-155 transaction
            raw_tx, tx_hash = sign_transaction(
                nonce=nonce,
                gas_price=gas_price,
                gas_limit=gas_limit,
                to=self.config.contract_address,
                value=0,
                data=calldata_bytes,
                chain_id=self.config.chain_id,
                private_key_hex=self._private_key,
            )

            # 4. Broadcast raw transaction
            submitted_hash = self._rpc_call("eth_sendRawTransaction", [raw_tx])
            explorer_url = self.config.explorer_tx_template.format(tx_hash=submitted_hash)

            # 5. Wait for receipt if confirmations required
            receipt = self._wait_for_receipt(submitted_hash, timeout_sec=20)
            if receipt:
                status_hex = receipt.get("status")
                block_num = int(receipt.get("blockNumber", "0x0"), 16)
                gas_used = int(receipt.get("gasUsed", "0x0"), 16)
                is_ok = (status_hex == "0x1")
                return OnChainTransactionResult(
                    success=is_ok,
                    tx_hash=submitted_hash,
                    block_number=block_num,
                    confirmations=1,
                    gas_used=gas_used,
                    status="CONFIRMED" if is_ok else "REVERTED",
                    explorer_url=explorer_url,
                    error_message=None if is_ok else "Transaction reverted by EVM execution"
                )

            return OnChainTransactionResult(
                success=True,
                tx_hash=submitted_hash,
                block_number=None,
                confirmations=0,
                status="PENDING",
                explorer_url=explorer_url,
                error_message="Broadcast successful; awaiting block confirmation."
            )
        except Exception as e:
            logger.error("Failed to broadcast on-chain anchor: %s", e)
            return OnChainTransactionResult(
                success=False,
                status="FAILED",
                error_message=str(e)
            )

    def _wait_for_receipt(self, tx_hash: str, timeout_sec: int = 15) -> Optional[Dict[str, Any]]:
        """Polls for transaction receipt up to timeout_sec."""
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            try:
                receipt = self._rpc_call("eth_getTransactionReceipt", [tx_hash])
                if receipt is not None:
                    return receipt
            except Exception:
                pass
            time.sleep(2)
        return None

    def verify_anchor_on_chain(
        self,
        anchor_id_hex: str,
        expected_root_hex: str
    ) -> Tuple[bool, int, int]:
        """Queries smart contract verifyAnchor(bytes32,bytes32) view function.
        
        Returns: (is_valid, timestamp, record_count)
        """
        if not self.config.rpc_url or not self.config.contract_address:
            return (False, 0, 0)

        calldata = encode_abi_call(
            "verifyAnchor(bytes32,bytes32)",
            [anchor_id_hex, expected_root_hex],
            ["bytes32", "bytes32"]
        )
        res_hex = self.eth_call(self.config.contract_address, calldata)
        decoded = decode_abi_output(res_hex, ["bool", "uint256", "uint256"])
        return (bool(decoded[0]), int(decoded[1]), int(decoded[2]))
