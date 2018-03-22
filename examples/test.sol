contract Test {
    uint256 value;
    function Test() {
        value = 5;
    }
    function set_value(uint256 v) {
        value = v;
    }
    function() payable {}
}
