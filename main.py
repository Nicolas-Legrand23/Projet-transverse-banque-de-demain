import hashlib
import json
import time
from uuid import uuid4
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import qrcode


class OfflinePaymentSystem:
    def __init__(self):
        # Generate RSA keys for user and merchant
        self.user_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.user_public_key = self.user_private_key.public_key()

        # Simulate merchant keys (in real system, these would be separate)
        self.merchant_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.merchant_public_key = self.merchant_private_key.public_key()

        # Local transaction ledger
        self.pending_transactions = []
        self.completed_transactions = []

        # User balance (simplified)
        self.balance = 1000.00  # Starting balance
        self.offline_limit = 100.00  # Max offline spending limit

    def generate_payment_qr(self, amount, description):
        """Merchant generates a payment QR code"""
        transaction_id = str(uuid4())
        timestamp = int(time.time())

        transaction_data = {
            "transaction_id": transaction_id,
            "amount": amount,
            "currency": "USD",
            "description": description,
            "merchant_id": "MERCHANT123",
            "timestamp": timestamp
        }

        # Sign the transaction data
        signature = self._sign_data(transaction_data, self.merchant_private_key)
        transaction_data["merchant_signature"] = signature

        # Generate QR code
        qr = qrcode.QRCode()
        qr.add_data(json.dumps(transaction_data))
        qr.make(fit=True)

        print(f"Merchant QR Code for ${amount}:")
        qr.print_ascii()

        return transaction_data

    def process_payment(self, qr_data):
        """User processes payment from QR code"""
        try:
            transaction = json.loads(qr_data)

            # Verify merchant signature
            if not self._verify_signature(transaction, self.merchant_public_key):
                print("Invalid merchant signature!")
                return False

            # Check if already processed
            if any(t["transaction_id"] == transaction["transaction_id"] for t in self.completed_transactions):
                print("Transaction already processed!")
                return False

            # Check balance and offline limit
            if transaction["amount"] > self.offline_limit:
                print("Transaction exceeds offline limit!")
                return False

            if transaction["amount"] > self.balance:
                print("Insufficient funds!")
                return False

            # User signs the transaction
            user_signature = self._sign_data(transaction, self.user_private_key)
            transaction["user_signature"] = user_signature
            transaction["user_id"] = "USER456"

            # Add to pending transactions
            self.pending_transactions.append(transaction)
            self.balance -= transaction["amount"]

            print(f"Payment of ${transaction['amount']} processed offline. Will sync when online.")
            return True

        except Exception as e:
            print(f"Payment processing failed: {str(e)}")
            return False

    def sync_transactions(self):
        """Simulate syncing with server when online"""
        print("\nSyncing transactions with server...")
        for tx in self.pending_transactions[:]:
            # In a real system, this would send to a payment server
            # Here we just move to completed
            self.completed_transactions.append(tx)
            self.pending_transactions.remove(tx)
            print(f"Synced transaction {tx['transaction_id']}")
        print("Sync complete!")

    def _sign_data(self, data, private_key):
        """Sign transaction data"""
        # Remove any existing signature to avoid signing the signature
        data_copy = data.copy()
        if 'merchant_signature' in data_copy:
            del data_copy['merchant_signature']
        if 'user_signature' in data_copy:
            del data_copy['user_signature']

        data_str = json.dumps(data_copy, sort_keys=True)
        signature = private_key.sign(
            data_str.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()

    def _verify_signature(self, data, public_key):
        """Verify signature on transaction data"""
        try:
            data_copy = data.copy()
            signature_hex = data_copy.pop('merchant_signature')
            signature = bytes.fromhex(signature_hex)

            data_str = json.dumps(data_copy, sort_keys=True)

            public_key.verify(
                signature,
                data_str.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False


# Demo Usage
if __name__ == "__main__":
    system = OfflinePaymentSystem()

    # Merchant creates a payment QR for $25.50
    print("\n=== Merchant creating payment QR ===")
    qr_data = system.generate_payment_qr(25.50, "Coffee")

    # User scans and pays (offline)
    print("\n=== User processing payment ===")
    system.process_payment(json.dumps(qr_data))

    # Another payment (offline)
    print("\n=== Second payment ===")
    qr_data2 = system.generate_payment_qr(15.00, "Sandwich")
    system.process_payment(json.dumps(qr_data2))

    # Attempt to double spend
    print("\n=== Double spend attempt ===")
    system.process_payment(json.dumps(qr_data2))

    # Sync when back online
    print("\n=== Coming back online ===")
    system.sync_transactions()

    print("\n=== Final balances ===")
    print(f"Available balance: ${system.balance:.2f}")
    print(f"Pending sync: {len(system.pending_transactions)} transactions")