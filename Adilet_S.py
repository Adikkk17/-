#!/usr/bin/env python
# coding: utf-8

# In[1]:


import time


# In[2]:


K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

INITIAL_HASHES = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
]


# In[3]:


def _right_rotate(x, n):
    """Циклический сдвиг вправо."""
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


# In[4]:


def sha256(message):
    """SHA-256 без сторонних библиотек."""
    message_bytes = message.encode('utf-8')
    orig_len_in_bits = len(message_bytes) * 8
    message_bytes += b'\x80'
    while (len(message_bytes) * 8) % 512 != 448:
        message_bytes += b'\x00'
    message_bytes += orig_len_in_bits.to_bytes(8, 'big')
    h = INITIAL_HASHES[:]

    for i in range(0, len(message_bytes), 64):
        block = message_bytes[i:i+64]
        w = [0] * 64
        for j in range(16):
            w[j] = int.from_bytes(block[j*4:(j+1)*4], 'big')
        for j in range(16, 64):
            s0 = _right_rotate(w[j-15], 7) ^ _right_rotate(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = _right_rotate(w[j-2], 17) ^ _right_rotate(w[j-2], 19) ^ (w[j-2] >> 10)
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xffffffff

        a, b, c, d, e, f, g, hh = h
        for j in range(64):
            s1 = (_right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25))
            ch = (e & f) ^ ((~e) & g)
            temp1 = (hh + s1 + ch + K[j] + w[j]) & 0xffffffff
            s0 = (_right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22))
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xffffffff
            hh = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        h[0] = (h[0] + a) & 0xffffffff
        h[1] = (h[1] + b) & 0xffffffff
        h[2] = (h[2] + c) & 0xffffffff
        h[3] = (h[3] + d) & 0xffffffff
        h[4] = (h[4] + e) & 0xffffffff
        h[5] = (h[5] + f) & 0xffffffff
        h[6] = (h[6] + g) & 0xffffffff
        h[7] = (h[7] + hh) & 0xffffffff

    return ''.join(f'{value:08x}' for value in h)


# In[5]:


class Transaction:
    """Транзакция (sender, receiver, amount)."""
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount

    def __str__(self):
        return f'{self.sender}|{self.receiver}|{self.amount}'


# In[6]:


def build_merkle_root(transactions):
    current_level = [sha256(str(tx)) for tx in transactions]
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            if i + 1 < len(current_level):
                right = current_level[i+1]
            else:
                right = left
            new_hash = sha256(left + right)
            next_level.append(new_hash)
        current_level = next_level
    return current_level[0] if current_level else ''


# In[7]:


class Block:
    """Блок с хешем предыдущего, 10 транзакциями, меткой времени и nonce."""
    def __init__(self, previous_hash, transactions):
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = int(time.time())
        self.merkle_root = build_merkle_root(self.transactions)
        self.nonce = 0
        self.block_hash = None

    def calculate_hash(self):
        data_to_hash = (
            self.previous_hash +
            str(self.timestamp) +
            self.merkle_root +
            str(self.nonce)
        )
        return sha256(data_to_hash)

    def mine_block(self, difficulty=2):
        target_prefix = '0' * difficulty
        while True:
            self.block_hash = self.calculate_hash()
            if self.block_hash.startswith(target_prefix):
                break
            self.nonce += 1


# In[8]:


class Blockchain:
    """Цепочка блоков с проверкой валидности."""
    def __init__(self):
        self.chain = []
        genesis_block = Block('0' * 64, [])
        genesis_block.mine_block(difficulty=2)
        self.chain.append(genesis_block)

    def add_block(self, block):
        self.chain.append(block)

    def validate_blockchain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            if current_block.calculate_hash() != current_block.block_hash:
                print(f"Ошибка: Хеш блока #{i} не совпадает!")
                return False
            if current_block.previous_hash != previous_block.block_hash:
                print(f"Ошибка: Блок #{i} ссылается на некорректный previous_hash!")
                return False
            if build_merkle_root(current_block.transactions) != current_block.merkle_root:
                print(f"Ошибка: Merkle Root блока #{i} некорректен!")
                return False
        return True


# In[11]:


if __name__ == '__main__':
    bc = Blockchain()

    txs_block2 = [
        Transaction("Alice", "Bob", 10),
        Transaction("Bob", "Charlie", 5),
        Transaction("Dave", "Eve", 15),
        Transaction("Eve", "Frank", 7),
        Transaction("Charlie", "Alice", 12),
        Transaction("Frank", "Bob", 4),
        Transaction("Mallory", "Oscar", 11),
        Transaction("Trent", "Peggy", 20),
        Transaction("Victor", "Walter", 1),
        Transaction("Peggy", "Trent", 6),
    ]
    block2 = Block(bc.chain[-1].block_hash, txs_block2)
    block2.mine_block(difficulty=2)
    bc.add_block(block2)

    txs_block3 = [
        Transaction("Oscar", "Mallory", 3),
        Transaction("Walter", "Victor", 9),
        Transaction("Alice", "Frank", 2),
        Transaction("Charlie", "Dave", 14),
        Transaction("Bob", "Eve", 1),
        Transaction("Mall", "Peggy", 3),
        Transaction("Trent", "Walter", 19),
        Transaction("Eve", "Alice", 10),
        Transaction("Frank", "Victor", 8),
        Transaction("Walter", "Mallory", 2),
    ]
    block3 = Block(bc.chain[-1].block_hash, txs_block3)
    block3.mine_block(difficulty=2)
    bc.add_block(block3)

    if bc.validate_blockchain():
        print("Вся цепочка валидна!")
    else:
        print("Цепочка НЕ валидна!")


# In[ ]:




