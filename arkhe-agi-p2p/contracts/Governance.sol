// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title Governance
 * @dev BFT proposal registration and canonicalization for OpenCLAW swarms.
 */
contract Governance {
    struct Proposal {
        bytes32 proposalId;
        string title;
        bytes32 diffDigest;
        uint256 votesFor;
        uint256 votesAgainst;
        bool executed;
    }

    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => mapping(address => bool)) public hasVoted;

    event ProposalCreated(bytes32 indexed proposalId, string title, bytes32 diffDigest);
    event Voted(bytes32 indexed proposalId, address indexed voter, bool support);

    function createProposal(bytes32 proposalId, string calldata title, bytes32 diffDigest) external {
        require(proposals[proposalId].proposalId == bytes32(0), "Proposal already exists");
        proposals[proposalId] = Proposal({
            proposalId: proposalId,
            title: title,
            diffDigest: diffDigest,
            votesFor: 0,
            votesAgainst: 0,
            executed: false
        });
        emit ProposalCreated(proposalId, title, diffDigest);
    }

    function vote(bytes32 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        require(p.proposalId != bytes32(0), "Proposal not found");
        require(!hasVoted[proposalId][msg.sender], "Already voted");

        hasVoted[proposalId][msg.sender] = true;
        if (support) {
            p.votesFor += 1;
        } else {
            p.votesAgainst += 1;
        }
        emit Voted(proposalId, msg.sender, support);
    }
}
