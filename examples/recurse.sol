contract C{
    
    function f0() internal{

    }

    function f1() internal{
        f0();
    }

    function f2() internal{
        f0();
        f1();
    }

    function (){
        f2();
    }
}