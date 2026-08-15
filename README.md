# optimistic_rollup

개발 순서

step1 - L2 state transition function
    {address: balance} dictionary 형태 계좌 state 만들고
    execute_tx(state, tx) -> new_state 구현
    docs 보고 할거긴 한데, 일단은 nonce검증, 잔액 부족 시 처리 정도만. 필요시 더 추가하기.

step2 - state commitment
    merkle tree를 만들어서 state 전체를 state_root로 압축
    state transition마다 root 재계산
    -> L1에 upload하는건 root 하나만.

step3 - custom L1 rollup contract 작성 & anvil 배포

step4 - sequencer 구현
    web3py 이용해 L1컨트랙트의 commitBatch 호출 로직

step5 - verifier 구현
    BatchCommited event를 subscribe해서 감지 -> replay -> 결과가 불일치 시, challenge 호출

step6 - Fraud proof 구현
    L1에서 challenge 호출 시, disputed batch를 solidity로 포팅한 상태전이함수로 직접 온체인 replay 및 root 비교
    일단 완전 재실행 방식으로 실행, 그리고 bisection game으로 최적화