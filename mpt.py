"""
Phase 2 (MPT 버전) - Merkle Patricia Trie 인터페이스

실제 이더리움 state trie와 같은 구조를 목표로 한다.

  - depth는 고정 파라미터가 아니라 데이터에 따라 동적으로 결정된다.
    SMT 버전(merkle.py)의 TREE_DEPTH / default_hashes(depth) 개념은
    여기서 아예 사라진다 — 대신 빈 트라이는 상수 하나(empty_trie_root)로
    표현된다.
  - 노드는 Leaf / Extension / Branch 세 종류이고, 각 노드는 RLP로
    인코딩된 뒤 해시로 참조되어 content-addressed store(db)에 저장된다.
  - 이전 merkle.py(SMT)와 동일한 설계 원칙 유지:
      * stf.py를 import하지 않는다 (의존 방향은 항상 stf.py -> mpt.py)
      * key를 미리 keccak256으로 해싱할지(Secure Trie) 여부는 여기서
        결정하지 않는다 — 호출하는 쪽(stf.py)의 책임.
      * update/delete는 원본을 mutate하지 않고 새 PatriciaTrie를 반환한다.
        (이건 실제 이더리움과도 일치한다 — 과거 state root로 조회가
        가능한 이유가 바로 이 불변성 때문이다.)

의도적으로 범위를 좁힌 부분 (TODO로 남김):
  - 32바이트 미만 노드를 부모에 인라인 임베딩하는 최적화는 다루지 않는다.
    모든 노드는 항상 해시로 참조한다고 가정한다.
  - delete()의 branch -> extension/leaf 재축소(collapse) 로직은 MPT
    구현에서 가장 까다로운 부분이니 가장 마지막에, 별도로 시간을 들여
    설계할 것을 권장한다.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Optional, Union

from Crypto.Hash import keccak

# ---------- 해시 함수 ----------

HashFn = Callable[[bytes], bytes]


def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.hexdigest()

def empty_trie_root(hash_fn: HashFn = keccak256) -> bytes:
    """
    빈 트라이의 root 해시. SMT의 default_hashes[depth]에 대응하는 개념이지만,
    MPT는 depth가 없으므로 상수 하나로 충분하다.
    TODO: keccak256(rlp_encode(b"")) 로 구현.
    """
    raise NotImplementedError


# ---------- 니블(nibble) 유틸 ----------

Nibbles = list[int]  # 각 원소는 0~15 (반 바이트 단위)


def bytes_to_nibbles(data: bytes) -> Nibbles:
    """bytes를 4비트씩(니블) 쪼갠다. 순서는 상위 니블이 먼저."""
    raise NotImplementedError


def nibbles_to_bytes(nibbles: Nibbles) -> bytes:
    """니블 리스트를 다시 bytes로 합친다. len(nibbles)가 홀수면 에러 처리할 것."""
    raise NotImplementedError


def common_prefix_len(a: Nibbles, b: Nibbles) -> int:
    """두 니블 시퀀스가 앞에서부터 몇 개나 일치하는지 반환. extension node
    생성/분기 판단에 필요."""
    raise NotImplementedError


# ---------- Hex-Prefix(HP) 인코딩 ----------
# leaf/extension 노드의 path를 하나의 bytes로 압축 인코딩한다. 첫 니블에
# (terminator 여부: leaf인가, 남은 니블 개수가 홀수인가)를 함께 담는다.
# TODO: 표준 HP 인코딩 표(짝수/홀수 x leaf/extension = 4가지 케이스) 참고해 구현.

def hp_encode(nibbles: Nibbles, is_leaf: bool) -> bytes:
    """path 니블들과 leaf 여부를 하나의 bytes로 압축 인코딩한다."""
    raise NotImplementedError


def hp_decode(data: bytes) -> tuple[Nibbles, bool]:
    """hp_encode의 역변환. (니블 리스트, is_leaf)를 반환."""
    raise NotImplementedError


# ---------- RLP 인코딩 ----------
# 노드를 최종 bytes로 직렬화하는 데 필요한 범용 인코딩 (트라이 로직과는
# 무관한 별도 스펙). 학습 목표가 트라이 구조 자체라면, 직접 구현하는 대신
# `rlp` 패키지(pip install rlp)를 써서 시간을 아끼는 것도 방법이다.

RLPItem = Union[bytes, list["RLPItem"]]


def rlp_encode(item: RLPItem) -> bytes:
    raise NotImplementedError


def rlp_decode(data: bytes) -> RLPItem:
    raise NotImplementedError


# ---------- 노드 표현 ----------

@dataclass
class LeafNode:
    path: Nibbles      # 이 노드부터 값까지 남은 니블 경로
    value: bytes


@dataclass
class ExtensionNode:
    path: Nibbles      # 공유되는 니블 prefix (여러 니블을 한 번에 건너뜀)
    child_ref: bytes   # 다음 노드를 가리키는 해시 참조


@dataclass
class BranchNode:
    # 길이 16 (니블 0~F 각각에 대응하는 자식 참조, 없으면 None)
    children: list[Optional[bytes]] = field(default_factory=lambda: [None] * 16)
    value: Optional[bytes] = None  # 경로가 이 지점에서 끝나는 key가 있으면 그 값


Node = Union[LeafNode, ExtensionNode, BranchNode]


def encode_node(node: Node) -> bytes:
    """
    노드를 이더리움 표준 형태(leaf/extension은 [encoded_path, value] 2-항목,
    branch는 [child0..child15, value] 17-항목)로 변환한 뒤 RLP 인코딩한다.
    """
    raise NotImplementedError


def decode_node(data: bytes) -> Node:
    """encode_node의 역변환. RLP 디코딩 후 항목 개수(2 vs 17)와 HP 인코딩의
    terminator 비트를 보고 Leaf/Extension/Branch 중 무엇인지 판별한다."""
    raise NotImplementedError


def hash_node(node: Node, hash_fn: HashFn = keccak256) -> bytes:
    """encode_node(node)를 해시한다 — 부모 노드가 이 노드를 참조하는 값."""
    raise NotImplementedError


# ---------- 트라이 상태 ----------

@dataclass
class PatriciaTrie:
    """
    root_hash와 db(content-addressed 노드 저장소)만으로 트라이 전체를 표현한다.
    db는 { node_hash: rlp_encoded_node_bytes } 형태의 key-value store다.
    """
    root_hash: bytes
    db: dict[bytes, bytes] = field(default_factory=dict)


def new_empty_trie(hash_fn: HashFn = keccak256) -> PatriciaTrie:
    """빈 PatriciaTrie를 생성한다 (root_hash = empty_trie_root)."""
    raise NotImplementedError


def build_trie(
    items: dict[bytes, bytes],
    hash_fn: HashFn = keccak256,
) -> PatriciaTrie:
    """
    key-value 매핑 전체로부터 트라이를 구성하는 편의 함수.
    내부적으로는 new_empty_trie()에서 시작해 update()를 반복 호출하는 것과
    같다 (MPT는 SMT의 build_tree처럼 한 번에 뭉쳐 계산하는 지름길이 없다).
    """
    raise NotImplementedError


# ---------- 핵심 인터페이스 ----------

def get(trie: PatriciaTrie, key: bytes) -> Optional[bytes]:
    """
    key에 해당하는 값을 조회한다. root부터 니블 경로를 따라 내려가며
    Branch/Extension/Leaf를 순회한다. 없으면 None.
    """
    raise NotImplementedError


def update(trie: PatriciaTrie, key: bytes, value: bytes) -> PatriciaTrie:
    """
    key-value를 삽입/갱신한 '새' PatriciaTrie를 반환한다 (원본은 불변).

    TODO: 최소한 아래 케이스를 다 다뤄야 한다.
      - 빈 트라이에 첫 leaf 삽입
      - 기존 leaf의 경로와 새 key의 경로가 처음부터 갈라짐 -> branch 생성
      - 기존 leaf와 새 key가 니블 일부를 공유 -> extension + branch 조합
      - 이미 있는 key를 그대로 덮어쓰는 경우
    """
    raise NotImplementedError


def delete(trie: PatriciaTrie, key: bytes) -> PatriciaTrie:
    """
    key를 제거한 '새' PatriciaTrie를 반환한다.

    TODO (난이도 최상): 삭제 후 branch node의 자식이 하나만 남으면
    extension/leaf 노드로 재축소(collapse)해야 한다. 이걸 안 하면 같은
    최종 state라도 삽입/삭제 순서에 따라 트라이 모양(=root)이 달라질 수
    있다 — SMT에는 없던 MPT 고유의 문제다. 다른 함수들을 다 구현하고
    테스트까지 통과한 뒤 마지막에 손대는 걸 권장.
    """
    raise NotImplementedError


def state_root(trie: PatriciaTrie) -> bytes:
    """현재 트라이의 root 해시. (SMT 버전과 함수명을 맞춰 stf.py 쪽 변경을 최소화)"""
    raise NotImplementedError


# ---------- 증명(proof) ----------

@dataclass
class MPTProof:
    """
    SMT의 MerkleProof(형제 해시 리스트 하나)와 달리, MPT의 proof는 root에서
    leaf까지 지나온 노드들의 RLP 인코딩 원본 그 자체다. branch 노드는 자식이
    최대 16개라 '형제 하나'만으로는 검증이 안 되고, 노드 전체를 줘야 검증하는
    쪽이 어느 슬롯을 봐야 하는지 알 수 있다.
    """
    key: bytes
    nodes: list[bytes]  # root -> leaf 순서로 지나온, RLP 인코딩된 노드들


def generate_proof(trie: PatriciaTrie, key: bytes) -> MPTProof:
    """root부터 key를 찾아가며 지나온 노드들의 RLP 인코딩을 그대로 수집한다."""
    raise NotImplementedError


def verify_proof(
    root_hash: bytes,
    key: bytes,
    value: Optional[bytes],
    proof: MPTProof,
    hash_fn: HashFn = keccak256,
) -> bool:
    """
    trie 전체 없이 root_hash, key, value, proof만으로 검증한다.

    검증 순서 (TODO):
      1. proof.nodes[0]을 디코딩해 해시가 root_hash와 일치하는지 확인
      2. key의 다음 니블을 보고 이 노드에서 어느 자식을 따라가야 하는지 결정
      3. 그 자식 참조가 proof.nodes[1]의 해시와 일치하는지 확인
      4. leaf에 도달할 때까지 2~3을 반복, 최종 value가 인자로 받은 value와
         일치하는지 확인

    value가 None이면 non-inclusion(해당 key가 존재하지 않음) 증명으로 취급한다.
    """
    raise NotImplementedError