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
import rlp

# ---------- 해시 함수 ----------

def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def empty_trie_root() -> bytes:
    return keccak256(rlp_encode(b""))

# ---------- 니블(nibble) 유틸 ----------

Nibbles = list[int]  # 각 원소는 0~15 (반 바이트 단위)

def bytes_to_nibbles(data: bytes) -> Nibbles:
    nibbles = Nibbles()

    for byte in data:
        nibbles.append(byte >> 4)
        nibbles.append(byte & 0x0F)
    
    return nibbles


def nibbles_to_bytes(nibbles: Nibbles) -> bytes:
    if len(nibbles) % 2 == 1:
        raise ValueError("Number of nibbles must be even") 

    result = bytearray()

    for i in range(0, len(nibbles), 2):
        result.append(nibbles[i] << 4 | nibbles[i + 1])

    return bytes(result)


def common_prefix_len(a: Nibbles, b: Nibbles) -> int:
    min_idx = min(len(a), len(b))
    
    for idx in range(min_idx):
        if a[idx] != b[idx]:
            return idx
    return min_idx

# ---------- Hex-Prefix 인코딩 ----------
# leaf/extension 노드의 path를 하나의 bytes로 압축 인코딩한다. 첫 니블에
# (terminator 여부: leaf인가, 남은 니블 개수가 홀수인가)를 함께 담는다.

def hp_encode(nibbles: Nibbles, is_leaf: bool) -> bytes:
    flag = 2 if is_leaf else 0          # 0=extension, 2=leaf
    if len(nibbles) % 2 == 0:
        prefixed = [flag, 0] + nibbles  
    else:
        prefixed = [flag + 1] + nibbles  
    return nibbles_to_bytes(prefixed)


def hp_decode(data: bytes) -> tuple[Nibbles, bool]:
    nibbles = bytes_to_nibbles(data)
    flag = nibbles[0]
    is_leaf = flag in (2, 3)
    is_odd = flag in (1, 3)
    path = nibbles[1:] if is_odd else nibbles[2:]
    return path, is_leaf


# ---------- RLP 인코딩 ----------

RLPItem = Union[bytes, list["RLPItem"]]

def rlp_encode(item: RLPItem) -> bytes:
    return rlp.encode(item)

def rlp_decode(data: bytes) -> RLPItem:
    return rlp.decode(data)

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
    leaf/extension은 [encoded_path, value] 2-항목,
    branch는 [child0 ~ child15, value] 17-항목)로 변환해서 rlp_encode
    """
    if isinstance(node, LeafNode):
        value = node.value
        if len(value) > 32:
            value = keccak256(value)
        items = [hp_encode(node.path, is_leaf=True), value] # value는 이미 rlp encoding되어있음
    elif isinstance(node, ExtensionNode):
        items = [hp_encode(node.path, is_leaf=False), node.child_ref]
    elif isinstance(node, BranchNode):
        children_enc = [c if c is not None else b"" for c in node.children]
        value_enc = node.value if node.value is not None else b""
        items = children_enc + [value_enc]
    else:
        raise TypeError(f"unknown node type: {type(node)}")

    return rlp_encode(items)

def decode_node(data: bytes) -> Node:
    """
    RLP decode 후 item 수(2 / 17)와 hp encoding의
    terminator bit를 보고 Leaf/Extension/Branch 판별 및 decode
    """
    items = rlp_decode(data)
    if len(items) == 17: # branch node
        children = [c if c != b"" else None for c in items[:16]]
        value = items[16] if items[16] != b"" else None
        return BranchNode(children=children, value=value)
    elif len(items) == 2: # extension/leaf
        encoded_path, second = items
        path, is_leaf = hp_decode(encoded_path)
        if is_leaf: # leaf node
            return LeafNode(path=path, value=second)
        else: 
            return ExtensionNode(path=path, child_ref=second)
    else: 
        raise ValueError(f"Invalid RLP node: expected 2 or 17 items")

def hash_node(node: Node) -> bytes:
    return keccak256(encode_node(node))


# ---------- 트라이 상태 ----------

@dataclass
class PatriciaTrie:
    """
    root_hash와 db(content-addressed 노드 저장소)만으로 트라이 전체를 표현한다.
    db는 { node_hash: rlp_encoded_node_bytes } 형태의 key-value store다.
    """
    root_hash: bytes
    db: dict[bytes, bytes] = field(default_factory=dict)


def new_empty_trie() -> PatriciaTrie:
    """빈 PatriciaTrie를 생성한다 (root_hash = empty_trie_root)."""
    return PatriciaTrie(empty_trie_root())


def build_trie(items: dict[bytes, bytes]) -> PatriciaTrie:
    """
    key-value 매핑 전체로부터 트라이를 구성하는 편의 함수.
    내부적으로는 new_empty_trie()에서 시작해 update()를 반복 호출하는 것과
    같다 (MPT는 SMT의 build_tree처럼 한 번에 뭉쳐 계산하는 지름길이 없다).
    """
    trie = new_empty_trie()
    
    for key, value in items.items():
        trie = update(trie, key, value)
    
    return trie


# ---------- 핵심 인터페이스 ----------

def get(trie: PatriciaTrie, key: bytes) -> Optional[bytes]:
    """
    key 대응 값 조회한다. root부터 nibble path 따라 내려가면서
    Branch/Extension/Leaf 순회 -> 없으면 None
    """
    if trie.root_hash == empty_trie_root():
        return None

    path = bytes_to_nibbles(key)
    node_hash = trie.root_hash

    while True:
        node_data = trie.db.get(node_hash)
        if node_data is None:
            raise KeyError(f"node not in db: {node_hash.hex()}")
        node = decode_node(node_data)

        if isinstance(node, LeafNode):
            if node.path == path:
                return node.value
            return None  # 남은 path가 leaf의 path와 안 맞음 -> key 없음

        elif isinstance(node, ExtensionNode):
            plen = len(node.path)
            if path[:plen] == node.path:
                path = path[plen:]        # 공유된 니블만큼 소비
                node_hash = node.child_ref
                continue
            return None  # extension 단계에서 이미 경로가 갈라짐 -> key 없음

        elif isinstance(node, BranchNode):
            if len(path) == 0:
                return node.value          # key가 정확히 이 branch에서 끝남
            nibble = path[0]
            child_ref = node.children[nibble]
            if child_ref is None:
                return None                # 그 니블 방향엔 자식이 없음 -> key 없음
            path = path[1:]                # 니블 1개 소비
            node_hash = child_ref
            continue

        else:
            raise TypeError(f"unknown node type in trie: {type(node)}")

def _store(db, node): 
    h = hash_node(node)
    db[h] = encode_node(node)

    return h

def _insert(db, node_hash, path, value) -> bytes:
    if node_hash is None:
        return _store(db, LeafNode(path=path, value=value))

    node = decode_node(db[node_hash])

    if isinstance(node, LeafNode):
        if node.path == path:
            return _store(db, LeafNode(path=path, value=value))  # 덮어쓰기

        plen = common_prefix_len(node.path, path)
        old_rem = node.path[plen:]
        new_rem = path[plen:]
        branch = BranchNode()

        # state trie에서는 모든 LeafNode가 같은 길이의 key 값을 가지기 때문에 조건문이 필요없는데, receipt trie, storage trie에서는 다름
        if len(old_rem) == 0:  
            branch.value = node.value
        else:
            branch.children[old_rem[0]] = _store(db, LeafNode(path=old_rem[1:], value=node.value))
        
        if len(new_rem) == 0:
            branch.value = value
        else:
            branch.children[new_rem[0]] = _store(db, LeafNode(path=new_rem[1:], value=value))

        branch_hash = _store(db, branch)
        
        if plen == 0:
            return branch_hash
        return _store(db, ExtensionNode(path=path[:plen], child_ref=branch_hash))

    elif isinstance(node, ExtensionNode):
        plen = common_prefix_len(node.path, path)

        if plen == len(node.path):
            # 새 path가 extension을 포함 -> 재귀
            new_child_hash = _insert(db, node.child_ref, path[plen:], value)
            return _store(db, ExtensionNode(path=node.path, child_ref=new_child_hash))
        
        # extension 중간에서 갈라짐 -> extension을 쪼갬
        old_rem = node.path[plen:]
        new_rem = path[plen:]
        branch = BranchNode()

        if len(old_rem) == 1:
            branch.children[old_rem[0]] = node.child_ref  # 니블 1개 남았으면 바로 연결
        else:
            branch.children[old_rem[0]] = _store(db, ExtensionNode(path=old_rem[1:], child_ref=node.child_ref))

        if len(new_rem) == 0:
            branch.value = value
        else:
            branch.children[new_rem[0]] = _store(db, LeafNode(path=new_rem[1:], value=value))

        branch_hash = _store(db, branch)
        if plen == 0:
            return branch_hash
        return _store(db, ExtensionNode(path=node.path[:plen], child_ref=branch_hash))

    elif isinstance(node, BranchNode):
        if len(path) == 0:
            return _store(db, BranchNode(children=list(node.children), value=value))
        nibble = path[0]
        new_child_hash = _insert(db, node.children[nibble], path[1:], value)
        new_children = list(node.children)
        new_children[nibble] = new_child_hash
        return _store(db, BranchNode(children=new_children, value=node.value))

    else:
        raise TypeError(f"unknown node type: {type(node)}")

    

def update(trie: PatriciaTrie, key: bytes, value: bytes) -> PatriciaTrie:
    """
    key-value를 삽입/갱신한 '새' PatriciaTrie를 반환한다(원본 건들지 않기)
    """
    new_db = dict(trie.db)
    path = bytes_to_nibbles(key)
    root_hash = None if trie.root_hash == empty_trie_root() else trie.root_hash
    new_root = _insert(new_db, root_hash, path, value)

    return PatriciaTrie(root_hash=new_root, db=new_db)


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
    trie.root_hash


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
    proof: MPTProof
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