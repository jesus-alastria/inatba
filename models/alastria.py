import sys
import time
import pprint
import os
import json
import web3

from web3 import Web3
from eth_account import Account

##########################################################################
# Auxiliary procedures
##########################################################################

# Convert to an Ethereum bytes32 value
def to_32byte_hex(val):
    return Web3.toHex(Web3.toBytes(val).rjust(32, b'\0'))

# Convert a raw address to a checksum-formatted address
def toChecksumAddress(rawAddress):
    address = Web3.toChecksumAddress(rawAddress)
    return address

# Compile a Solidity source file
def compile_source_file(file_path):
    return compile_files([file_path])


# Bind a contract definition to a deployment address in the blockchain
# So the contract functions can be called
def bind_compiled_contract(w3, compiled_sol, raw_contract_address):

    # compiled_sol is a dictionary with a single entry
    # The key is the source file and the value is the full contract interface
    # The contract interface is another dictionary with a key with the ABI definition
    # We use popitem() to destructively but easily obtain the contract interface
    contract_id, contract_interface = compiled_sol.popitem()

    # This is the address where the contract is deployed in Alastria
    contract_address = Web3.toChecksumAddress(raw_contract_address)

    # Bind the address to the contract interface so we can call its functions
    wrapper = w3.eth.contract(
        address=contract_address,
        abi=contract_interface['abi'])

    return wrapper

def bind_contract(w3, contract_source_file, raw_contract_address):

    # Compile the Solidity source file and extract the contract_interface
    # The contract is already deployed in Alastria, but this is a handy method of
    # obtaining the contract interface (ABI)
    compiled_sol = compile_source_file(contract_source_file)

    return bind_compiled_contract(w3, compiled_sol, raw_contract_address)


# Create a signed transaction with the private key, sendt it and wait timeout for the txreceipt
def send_signed_tx(w3, contract_function, private_key, timeout=20):

    # Obtain the Alastria account associated to the private key
    from_account = Account.privateKeyToAccount(private_key)

    # Obtain the transaction count for the account, to build the nonce for the transaction
    nonce = w3.eth.getTransactionCount(from_account.address)

    # Define a high value of gas. For the moment this is not important in Alastria
    gas = 400000000

    # Create a transaction parameter specification with enough gas for executions
    txparms = {
        'gasPrice': 0,
        'gas': gas,
        'nonce': nonce
    }

    # Build the transaction object for the invocation to the provided function
    unsignedTx = contract_function.buildTransaction(txparms)

    # Sign the transaction with the private key
    # This way we can send the transaction without relying on accounts hosted in any node
    # It will act as sending the transaction from the account associated to the private key
    signedTx = Account.signTransaction(unsignedTx, private_key)

    # Send the signed transaction
    tx_hash = w3.eth.sendRawTransaction(signedTx.rawTransaction)

    # Wait for the receipt at most "timeout" seconds
    receipt = w3.eth.waitForTransactionReceipt(tx_hash, timeout)

    # Check for successful transaction execution
    # Before Byzantium, the transaction receipt did not have a "status" field,
    # so the only way to check for success is to compare gas provided to gas consumed.
    # If both are equal, then the transaction did not execute correctly.
    if gas == receipt.gasUsed:
        return False, receipt, tx_hash
    else:
        return True, receipt, tx_hash

# Tell W3 where the node is and that Alastria is a POA network so the length of "extrabytes"
#  in the blockchain header does not match the original Ethereum specification
def setup_provider(node_ip):
    # Create a web3.py instance connecting with an Alastria node
    w3 = Web3(Web3.HTTPProvider(node_ip))

    # Inject the POA compatibility middleware to the innermost layer
    from web3.middleware import geth_poa_middleware
    w3.middleware_stack.inject(geth_poa_middleware, layer=0)

    # Return the Web3 instance
    return w3

##########################################################################
# Setup procedures
##########################################################################

# These are precreated (offline) privateKeys according to Ethereum mechanism
# They have associated external accounts, which can be derived from the keys
# They should work in any Ethereum-compatible network, as Alastria
privKey1 = "0x177f09e04e170779c32244b318009adee2310b3458fd7c137b7b824365d6aa03"
privKey2 = "0xc8bbb9c3247cd5e82170858631fc77d0e2fbd0642f5c59a0688e54e91c65e726"
privKey3 = "0x7608756c9f9a9924c1f9b911028c5adf51d354ccfe4747d62e438f5247c96355"
privKey4 = "0xa451447b67d119fd24da8e2ca2e98b7ad64c7b3a1d3116cf4443add342a21c78"

# The associated external accounts
address1 = "0xfd23b5219B5a6701fC02224847c02f67a21F2fF8"
address2 = "0x1b54Deb0E14D3033C5Ef1CF8f5393eCcb9E4FF8e"
address3 = "0xEc40B6288Bf5F52c62900071976F34fD1cAEb3eb"
address4 = "0xbC1Cf573076CAea29845e7567797Bf1c70AA0655"

