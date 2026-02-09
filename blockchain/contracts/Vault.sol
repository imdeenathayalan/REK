// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {

    struct Record {
        string data;      // Encrypted data
        uint256 updated; // Last update time
    }

    mapping(address => Record) private records;

    event RecordUpdated(address indexed user, uint256 time);

    // Store / Update encrypted data
    function setRecord(string calldata _data) external {
        records[msg.sender] = Record(_data, block.timestamp);
        emit RecordUpdated(msg.sender, block.timestamp);
    }

    // Read your own data
    function getRecord() external view returns (string memory, uint256) {
        Record memory r = records[msg.sender];
        return (r.data, r.updated);
    }

    // Check if record exists
    function hasRecord() external view returns (bool) {
        return bytes(records[msg.sender].data).length > 0;
    }
}
