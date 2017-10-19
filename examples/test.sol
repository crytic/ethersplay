pragma solidity ^0.4.11;

library SafeMath{
 function sub(uint a, uint b) internal returns (uint) {
    assert(b <= a);
    return a - b;
  }

  function div(uint a, uint b) internal returns (uint) {
    assert(b <= a);
    return a - b;
  }
}

contract Test {

  using SafeMath for uint;
  struct Transaction {
    address to;
    uint value;
    bytes data;
  }
  event test(string);

  mapping (bytes32 => Transaction) m_txs;
  function execute(address _to, uint _value, bytes _data) external returns (bytes32 o_hash) {
    this.balance.sub(msg.value).div(1);
    if (_data.length == 0) {
       {
        if (!_to.call.value(_value)(_data))
          throw;
        else
          return;
      }
    } else {
        m_txs[o_hash].to = _to;
    }
  }

  function nothing(){
    test('nothing');
  }


}
