pragma solidity ^0.7.4;

contract TokenSaleChallenge {
    mapping(address => uint256) public balanceOf;
    uint256 constant PRICE_PER_TOKEN = 1 ether;

    function sell(uint256 numTokens) public {
        require(balanceOf[msg.sender]-numTokens > 0);
        balanceOf[msg.sender] -= numTokens;
        msg.sender.transfer(numTokens * PRICE_PER_TOKEN);
    }
}