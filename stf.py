from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json


# ---------- 데이터 모델 ----------

@dataclass
class Account:
    balance: int = 0
    nonce: int = 0


@dataclass(frozen=True)
class Transaction:
    tx_type: str        # mint/transfer
    sender: str          # mint일 땐 "" (L1 -> L2 입금을 흉내낸 특수 tx)
    recipient: str
    amount: int
    nonce: int            # sender의 현재 nonce와 일치해야 함 (replay 공격 방지)


@dataclass
class TxReceipt:
    tx: Transaction
    success: bool
    reason: str = ""


# ---------- 에러 ----------

class STFError(Exception):
    pass


class UnknownSender(STFError):
    pass


class InvalidNonce(STFError):
    pass


class InsufficientBalance(STFError):
    pass


class InvalidAmount(STFError):
    pass


State = dict  # dict[str, Account]


# ---------- 핵심: STF ----------

# tx는 mint, transfer만 있다고 가정하는 중
def apply_tx(state: State, tx: Transaction) -> State:
    """
    state를 직접 수정하지 않고, 반영된 '새 state'를 반환한다.
    실패 시 예외를 던지고 원본 state는 절대 건드리지 않는다.
    """
    # mint던, transfer이던 값이 양수여야 함
    if tx.amount < 0:
        raise InvalidAmount(f"amount must be positive: {tx.amount}")

    new_state = dict(state)  # shallow copy: 이번 tx가 건드리는 계좌만 새로 교체

    if tx.tx_type == "mint":
        recipient = new_state.get(tx.recipient, Account())
        new_state[tx.recipient] = Account(
            balance=recipient.balance + tx.amount,
            nonce=recipient.nonce,
        )
        return new_state

    if tx.tx_type == "transfer":
        sender = new_state.get(tx.sender)
        if sender is None:
            raise UnknownSender(f"no such account: {tx.sender}")
        if tx.nonce != sender.nonce:
            raise InvalidNonce(f"expected nonce {sender.nonce}, got {tx.nonce}")
        if sender.balance < tx.amount:
            raise InsufficientBalance(
                f"{tx.sender} has {sender.balance}, needs {tx.amount}"
            )

        recipient = new_state.get(tx.recipient, Account())

        new_state[tx.sender] = Account(
            balance=sender.balance - tx.amount,
            nonce=sender.nonce + 1,
        )
        new_state[tx.recipient] = Account(
            balance=recipient.balance + tx.amount,
            nonce=recipient.nonce,
        )
        return new_state

    raise STFError(f"unknown tx_type: {tx.tx_type}")


def apply_batch(state: State, txs: list[Transaction]) -> tuple[State, list[TxReceipt]]:
    """
    배치를 순서대로 적용한다. 유효하지 않은 tx는 스킵하고 계속 진행한다
    (배치 전체를 실패시키지 않는다 - 실제 롤업 동작을 흉내).
    """
    receipts = []
    for tx in txs:
        try:
            state = apply_tx(state, tx)
            receipts.append(TxReceipt(tx, success=True))
        except STFError as e:
            receipts.append(TxReceipt(tx, success=False, reason=str(e)))
    return state, receipts


# ---------- state root (Phase 2에서 Merkle tree로 교체할 부분) ----------

def compute_state_root(state: State) -> str:
    """
    지금은 '정렬된 상태를 JSON으로 만들어 해시'하는 방식으로 단순화.
    Phase 2에서 Merkle tree로 바꾸면:
      - 계좌 하나만 바뀌어도 전체를 다시 해시할 필요 없이 root를 효율적으로 갱신 가능
      - 특정 계좌 하나만 증명하는 Merkle proof를 만들 수 있음 (fraud proof에 필수)
    """
    canonical = json.dumps(
        {addr: [acc.balance, acc.nonce] for addr, acc in sorted(state.items())},
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---------- 데모 ----------

if __name__ == "__main__":
    state: State = {}

    # genesis: alice/bob에게 초기 잔액 지급 (mint tx로 L1 입금을 흉내)
    genesis_txs = [
        Transaction("mint", "", "alice", 100, 0),
        Transaction("mint", "", "bob", 50, 0),
    ]
    state, _ = apply_batch(state, genesis_txs)
    print("[genesis] root:", compute_state_root(state))
    print("[genesis] state:", {a: (s.balance, s.nonce) for a, s in state.items()})
    print()

    # 정상 배치: alice -> bob 30, bob -> alice 10
    batch1 = [
        Transaction("transfer", "alice", "bob", 30, 0),
        Transaction("transfer", "bob", "alice", 10, 0),
    ]
    state, receipts = apply_batch(state, batch1)
    print("[batch1] receipts:")
    for r in receipts:
        print(f"  success={r.success} tx={r.tx}")
    print("[batch1] state:", {a: (s.balance, s.nonce) for a, s in state.items()})
    print("[batch1] root:", compute_state_root(state))
    print()

    # 공격/오류 시나리오: 잔액 초과, nonce replay, 존재하지 않는 계좌
    batch2 = [
        Transaction("transfer", "alice", "bob", 9999, 1),   # 잔액 부족
        Transaction("transfer", "alice", "bob", 5, 0),       # nonce replay (이미 1로 증가함)
        Transaction("transfer", "carol", "bob", 5, 0),        # 존재하지 않는 sender
    ]
    state, receipts = apply_batch(state, batch2)
    print("[batch2] receipts (모두 실패해야 정상):")
    for r in receipts:
        print(f"  success={r.success} reason='{r.reason}'")
    print("[batch2] root (batch1과 동일해야 함, state 변화 없음):", compute_state_root(state))