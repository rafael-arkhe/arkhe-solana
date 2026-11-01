// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title PaymentChannel
 * @dev Streaming micropayment channels for Hyperspace DAG agent settlement.
 */
contract PaymentChannel {
    struct Channel {
        address sender;
        address recipient;
        uint256 deposit;
        uint256 settled;
        bool closed;
    }

    mapping(bytes32 => Channel) public channels;

    event ChannelOpened(bytes32 indexed channelId, address indexed sender, address indexed recipient, uint256 deposit);
    event Settled(bytes32 indexed channelId, uint256 amount);
    event ChannelClosed(bytes32 indexed channelId);

    function openChannel(bytes32 channelId, address recipient) external payable {
        require(channels[channelId].deposit == 0, "Channel exists");
        require(msg.value > 0, "Deposit required");
        channels[channelId] = Channel({
            sender: msg.sender,
            recipient: recipient,
            deposit: msg.value,
            settled: 0,
            closed: false
        });
        emit ChannelOpened(channelId, msg.sender, recipient, msg.value);
    }

    function settle(bytes32 channelId, uint256 amount) external {
        Channel storage ch = channels[channelId];
        require(!ch.closed, "Channel closed");
        require(msg.sender == ch.sender || msg.sender == ch.recipient, "Unauthorized");
        require(ch.settled + amount <= ch.deposit, "Exceeds deposit");
        ch.settled += amount;
        emit Settled(channelId, amount);
    }

    function closeChannel(bytes32 channelId) external {
        Channel storage ch = channels[channelId];
        require(!ch.closed, "Already closed");
        require(msg.sender == ch.sender, "Only sender");
        ch.closed = true;
        uint256 refund = ch.deposit - ch.settled;
        if (ch.settled > 0) {
            payable(ch.recipient).transfer(ch.settled);
        }
        if (refund > 0) {
            payable(ch.sender).transfer(refund);
        }
        emit ChannelClosed(channelId);
    }
}
