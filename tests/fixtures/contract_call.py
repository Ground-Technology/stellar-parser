"""Encode the synthetic Soroban deposit fixture using only the standard library.

Prints the base64 envelope and its testnet signing digest, which must match
contract_call.xdr and contract_call.sha256 exactly.
"""

import base64
import hashlib
import struct

NETWORK = b"Test SDF Network ; September 2015"
OWNER = bytes([1]) * 32
VAULT = bytes([5]) * 32
TOKEN = bytes([6]) * 32
AMOUNT = 1_000_000_000


def u32(value):
    return struct.pack(">I", value)


def u64(value):
    return struct.pack(">Q", value)


def i64(value):
    return struct.pack(">q", value)


def string(value):
    return u32(len(value)) + value + b"\0" * (-len(value) % 4)


def array(items):
    return u32(len(items)) + b"".join(items)


def account(key):
    return u32(0) + u32(0) + key  # SC_ADDRESS_TYPE_ACCOUNT, PUBLIC_KEY_TYPE_ED25519


def contract(contract_id):
    return u32(1) + contract_id  # SC_ADDRESS_TYPE_CONTRACT


def address(value):
    return u32(18) + value  # SCV_ADDRESS


def i128(value):
    return u32(10) + i64(value >> 64) + u64(value & (2**64 - 1))  # SCV_I128


def call(target, function, args):
    return target + string(function) + array(args)  # InvokeContractArgs


def authorized(invocation, children):
    return u32(0) + invocation + array(children)  # SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN


def transaction(operation, fee, resource_fee):
    soroban_data = (
        u32(0)  # SorobanTransactionDataExt v0
        + array([]) + array([])  # empty read-only and read-write footprint
        + u32(100_000) + u32(0) + u32(0)  # instructions, disk read bytes, write bytes
        + i64(resource_fee)
    )
    return (
        u32(0) + OWNER  # KEY_TYPE_ED25519 source account
        + u32(fee)
        + i64(42)  # sequence number
        + u32(1) + u64(0) + u64(2_000_000_000)  # PRECOND_TIME
        + u32(0)  # MEMO_NONE
        + array([operation])
        + u32(1) + soroban_data  # TransactionExt v1
    )


def invoke_operation(invocation, authorizations):
    return (
        u32(0)  # no operation source account
        + u32(24)  # INVOKE_HOST_FUNCTION
        + u32(0) + invocation  # HOST_FUNCTION_TYPE_INVOKE_CONTRACT
        + array(authorizations)
    )


def source_account_authorization(root):
    return u32(0) + root  # SOROBAN_CREDENTIALS_SOURCE_ACCOUNT


def encode(tx):
    envelope = u32(2) + tx + array([])  # ENVELOPE_TYPE_TX with no signatures
    payload = hashlib.sha256(NETWORK).digest() + u32(2) + tx
    return base64.b64encode(envelope).decode(), hashlib.sha256(payload).hexdigest()


def main():
    deposit = call(contract(VAULT), b"deposit", [address(account(OWNER)), i128(AMOUNT)])
    transfer = call(
        contract(TOKEN),
        b"transfer",
        [address(account(OWNER)), address(contract(VAULT)), i128(AMOUNT)],
    )
    authorization = source_account_authorization(
        authorized(deposit, [authorized(transfer, [])])
    )
    operation = invoke_operation(deposit, [authorization])
    for line in encode(transaction(operation, fee=10_100, resource_fee=10_000)):
        print(line)


if __name__ == "__main__":
    main()
