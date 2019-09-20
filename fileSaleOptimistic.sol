pragma solidity ^0.4.23;

/*
This contract is an extension of the fileSale contract based on FairSwap(https://github.com/lEthDev/FairSwap).
In contains only the methods required for the optimistic mode and a function that calls a 'fileSalePessimistic' contract for dispute resolution.
*/
// abstract 'fileSalePessimistic' contract
contract fileSalePessimistic {
    function startDisputeResolution(address _sender, bytes32 _key, uint[] _Q) public;
    function () payable public;
}

contract fileSaleOptimistic {

    uint constant price = XXXPRICEXXX; // price given in wei
    address public receiver = XXXADDRESSRECEIVERXXX;
    address public sender;

    bytes32 public keyCommit = XXXKEYCOMMITMENTXXX;
    bytes32 public key;

    address public verifierContactAddress = XXXVERIFIERCONTRACTADDRESSXXX;

    enum stage {start, active, initialized, revealed, challenged}
    stage public phase = stage.start;

    uint public timeout;
    uint public challengeLimit = XXXCHALLENGELIMITXXX;
    uint constant feeReceiver = XXXRECEIVERFEEXXX;  // receiver fee given in wei

    // function modifier to only allow calling the function in the right phase only from the correct party
    modifier allowed(address p, stage s) {
        require(phase == s);
        require(msg.sender == p);
        _;
    }

    // go to next phase
    function nextStage(stage s) internal {
        phase = s;
        timeout = now + 10 minutes;
    }

    /*
     * Initialization phase
     */
    // constructor is initialize function
    constructor () public {
        sender = msg.sender;
        nextStage(stage.active);
    }

    // function accept
    function accept() allowed(receiver, stage.active) payable public {
        require (msg.value >= price);
        nextStage(stage.initialized);
    }

    /*
     * Abort during the Initialization phase
     */
    // function abort can be accessed by sender and receiver
    function abort() public {
        if (phase == stage.active) selfdestruct(sender);
        if (phase == stage.initialized) selfdestruct(receiver);
    }

    /*
     * Revealing phase
     */
    function revealKey (bytes32 _key) allowed(sender, stage.initialized) public {
        require(keyCommit == keccak256(_key));
        key = _key;
        nextStage(stage.revealed);
    }

    /*
     * Finalization phase
     */
    // function refund implements the 'challenge timeout', 'response timeout', and 'finalize' (executable by the sender) functionalities
    function refund() public {
        require(now > timeout);
        if (phase == stage.revealed) selfdestruct(sender);
        if (phase == stage.challenged) selfdestruct(receiver);
    }

    // function noComplain implements the 'finalize' functionality executed by the receiver
    function noComplain() allowed(receiver, stage.revealed) public {
        selfdestruct(sender);
    }

    function challenge(uint[] _Q) payable public {
        require(msg.sender == receiver);
        require(phase == stage.revealed);
        require(_Q.length <= challengeLimit);
        require(msg.value >= _Q.length * feeReceiver);
        nextStage(stage.challenged);

        fileSalePessimistic verifier = fileSalePessimistic(verifierContactAddress);
        address(verifier).transfer(address(this).balance);
        verifier.startDisputeResolution(sender, key, _Q);
    }
}
