import pytest
from src.dag_consensus import MysticetiDAG


def test_round_jumping_prevention():
    dag = MysticetiDAG(max_round_jump=2)

    # Should work (target_round = 1 <= current_round + max_round_jump = 0 + 2)
    dag.propose_block(author=b"node0", peer=b"node1", transactions=[b"tx1"], target_round=1)

    # Should fail (target_round = 4 > current_round + max_round_jump = 1 + 2)
    with pytest.raises(ValueError):
        dag.propose_block(author=b"node0", peer=b"node1", transactions=[b"tx2"], target_round=4)


def test_commit_and_topological_order():
    dag = MysticetiDAG(n_validators=4, f_byzantine=1)

    # Round 1
    b0 = dag.propose_block(author=b"node0", peer=b"node1", transactions=[b"tx1"], target_round=1)
    b1 = dag.propose_block(author=b"node1", peer=b"node2", transactions=[b"tx2"], target_round=1)
    b2 = dag.propose_block(author=b"node2", peer=b"node3", transactions=[b"tx3"], target_round=1)

    # Round 2 (references blocks from Round 1)
    b3 = dag.propose_block(author=b"node0", peer=b"node1", transactions=[b"tx4"], target_round=2, parents=[b0.block_id, b1.block_id, b2.block_id])
    b4 = dag.propose_block(author=b"node1", peer=b"node2", transactions=[b"tx5"], target_round=2, parents=[b0.block_id, b1.block_id, b2.block_id])
    b5 = dag.propose_block(author=b"node2", peer=b"node3", transactions=[b"tx6"], target_round=2, parents=[b0.block_id, b1.block_id, b2.block_id])

    # Round 3 to trigger commits for Round 1
    b6 = dag.propose_block(author=b"node0", peer=b"node1", transactions=[b"tx7"], target_round=3, parents=[b3.block_id, b4.block_id, b5.block_id])

    committed = dag.commit_blocks()

    # Blocks from Round 1 and 2 should be committed since they are referenced by multiple validators
    assert b0.block_id in committed
    assert b1.block_id in committed
    assert b2.block_id in committed

    ordered = dag.topological_order()
    assert len(ordered) == len(committed)
