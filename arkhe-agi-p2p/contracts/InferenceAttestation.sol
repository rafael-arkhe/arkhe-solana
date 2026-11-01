// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title InferenceAttestation
 * @dev On-chain anchor for OmniNode & SPICE inference roots and AFiR receipts.
 */
contract InferenceAttestation {
    struct Attestation {
        bytes32 inferenceRoot;
        bytes32 modelCidHash;
        address reporter;
        uint256 timestamp;
    }

    mapping(bytes32 => Attestation) public attestations;

    event InferenceAttested(
        bytes32 indexed sessionHash,
        bytes32 indexed inferenceRoot,
        address indexed reporter
    );

    function recordAttestation(bytes32 sessionHash, bytes32 inferenceRoot, bytes32 modelCidHash) external {
        require(attestations[sessionHash].timestamp == 0, "Attestation already exists");
        attestations[sessionHash] = Attestation({
            inferenceRoot: inferenceRoot,
            modelCidHash: modelCidHash,
            reporter: msg.sender,
            timestamp: block.timestamp
        });
        emit InferenceAttested(sessionHash, inferenceRoot, msg.sender);
    }
}
