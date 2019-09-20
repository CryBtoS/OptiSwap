pragma solidity ^0.4.23;

/*
This contract is an extension of the fileSale contract based on FairSwap(https://github.com/lEthDev/FairSwap).
It contains additionally methods for the challenge-response procedure.
*/
contract fileSale {

    uint constant length = XXXLENGTHXXX; // lenght of one file chunk (value is multiplied with 32)
    uint constant n = XXXNXXX; // number of file chunks
    uint constant proofLength = XXXPROOFLENGTHXXX; // length of Merkle proofs
    uint constant price = XXXPRICEXXX; // price given in wei
    address public receiver = XXXADDRESSRECEIVERXXX;
    address public sender;

    bytes32 public keyCommit = XXXKEYCOMMITMENTXXX;
    bytes32 public key;
    bytes32 public chiphertextRoot = XXXCIPHERTEXTROOTXXX;
    bytes32 public fileRoot = XXXFILEROOTXXX;
    bytes32 public eRoot = XXXCOMPUTATIONROOTZXXX;

    enum stage {start, active, initialized, revealed, challenged, responded, finalized}
    stage public phase = stage.start;

    uint public timeout;
    uint public challengeLimit = XXXCHALLENGELIMITXXX;
    uint constant feeSender = XXXSENDERFEEXXX;  // sender fee given in wei
    uint constant feeReceiver = XXXRECEIVERFEEXXX;  // receiver fee given in wei

    uint[] public recentChallenges;

    struct Response {
        uint index;
        bytes32 value;
        bytes32[proofLength] proof;
    }
    Response[] public recentResponses;

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
     * Challenge-Response phase
     */
    function challenge(uint[] _Q) payable public {
        require(msg.sender == receiver);
        require(phase == stage.revealed || phase == stage.responded);
        require(_Q.length <= challengeLimit);
        require(msg.value >= _Q.length * feeReceiver);
        recentChallenges = _Q;
        challengeLimit = challengeLimit - _Q.length;
        nextStage(stage.challenged);
    }

    function respond(uint[] indices, bytes32[] values, bytes32[proofLength][] proofs) allowed(sender, stage.challenged) payable public {
        require(indices.length == recentChallenges.length);
        require(values.length == recentChallenges.length);
        require(proofs.length == recentChallenges.length);
        require(msg.value >= recentChallenges.length * feeSender);

        delete recentResponses;
        for (uint i = 0; i < recentChallenges.length; i++) {
            Response memory r = Response(indices[i], values[i], proofs[i]);
            recentResponses.push(r);
        }
        nextStage(stage.responded);
    }

    /*
     * Finalization phase
     */
    // function refund implements the 'challenge timeout', 'response timeout', and 'finalize' (executable by the sender) functionalities
    function refund() public {
        require(now > timeout);
        if (phase == stage.revealed) selfdestruct(sender);
        if (phase == stage.responded) selfdestruct(sender);
        if (phase == stage.challenged) selfdestruct(receiver);
    }

    // function noComplain implements the 'finalize' functionality executed by the receiver
    function noComplain() allowed(receiver, stage.revealed) public {
        selfdestruct(sender);
    }

    // function complainAboutResponse implements 'complain' functionality
    function complainAboutResponse() allowed(receiver, stage.responded) public {
        for(uint i = 0; i < recentChallenges.length; i++) {
            bool found = false;
            Response memory r;

            for(uint j = 0; j < recentResponses.length; j++) {
                if (recentChallenges[i] == recentResponses[j].index) {
                    found = true;
                    r = recentResponses[j];
                    break;
                }
            }

            if (found == false) {
                selfdestruct(receiver);
            } else {
                if(vrfy(r.index, r.value, r.proof) == false) {
                    selfdestruct(receiver);
                }
            }
        }
        selfdestruct(sender);
    }

    // function complain about wrong hash of file
    function complainAboutRoot (bytes32 _Zm, bytes32[proofLength] memory _proofZm) public {
        require(msg.sender == receiver);
        require(uint(phase) >= uint(stage.revealed));

        require (vrfy(2*(n-1), _Zm, _proofZm));
        if (cryptSmall(2*(n-1), _Zm) != fileRoot){
            selfdestruct(receiver);
        }
    }

    // function complain about wrong hash of two inputs
    function complainAboutLeaf (uint _indexOut, uint _indexIn,
        bytes32 _Zout, bytes32[length] memory _Zin1, bytes32[length] memory _Zin2, bytes32[proofLength] memory _proofZout,
        bytes32[proofLength] memory _proofZin) public {
        require(msg.sender == receiver);
        require(uint(phase) >= uint(stage.revealed));

        require (vrfy(_indexOut, _Zout, _proofZout));
        bytes32 Xout = cryptSmall(_indexOut, _Zout);

        require (vrfy(_indexIn, keccak256(_Zin1), _proofZin));
        require (_proofZin[0] == keccak256(_Zin2));

        if (Xout != keccak256(cryptLarge(_indexIn, _Zin1), cryptLarge(_indexIn+1, _Zin2))) {
            selfdestruct(receiver);
        }
    }

    // function complain about wrong gate computation
    function complainAboutNode (uint _indexOut, uint _indexIn,
        bytes32 _Zout, bytes32 _Zin1, bytes32 _Zin2, bytes32[proofLength] memory _proofZout,
        bytes32[proofLength] memory _proofZin) public {
        require(msg.sender == receiver);
        require(uint(phase) >= uint(stage.revealed));

        require (vrfy(_indexOut, _Zout, _proofZout));
        bytes32 Xout = cryptSmall(_indexOut, _Zout);

        require (vrfy(_indexIn, _Zin1, _proofZin));
        require (_proofZin[0] == _Zin2);

        if (Xout != keccak256(cryptSmall(_indexIn, _Zin1), cryptSmall(_indexIn+1, _Zin2))) {
            selfdestruct(receiver);
        }
    }

    // function to both encrypt and decrypt text chunks with key k
    function cryptLarge (uint _index, bytes32[length] memory _ciphertext) public view returns (bytes32[length] memory){
        _index = _index*length;
        for (uint i = 0; i < length; i++){
        _ciphertext[i] = keccak256(_index, key) ^ _ciphertext[i];
        _index++;
        }
        return _ciphertext;
    }

    // function to decrypt hashes of the Merkle tree
    function cryptSmall (uint _index, bytes32 _ciphertext) public view returns (bytes32){
        return keccak256(n+_index, key) ^ _ciphertext;
    }

    // function to verify Merkle tree proofs
    function vrfy(uint _index, bytes32 _value, bytes32[proofLength] memory _proof) public view returns (bool){
        for (uint8 i = 0; i < proofLength; i++){
            if ((_index & uint(1)<<i)>>i == 1)
                _value = keccak256(_proof[proofLength -i], _value);
            else
                _value = keccak256(_value, _proof[proofLength -i]);
        }
        return (_value == chiphertextRoot);
    }
}
