class WalletClient:
    def __init__(self, initial_balance: int = 100):
        self.balance = initial_balance

    def get_balance(self) -> int:
        return self.balance

    def debit(self, amount: int = 1) -> bool:
        if self.balance < amount:
            return False
        self.balance -= amount
        return True

    def refund(self, amount: int = 1) -> int:
        self.balance += amount
        return self.balance

# Global wallet instance initialized with 100 credits
wallet = WalletClient(initial_balance=100)