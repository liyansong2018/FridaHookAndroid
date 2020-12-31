Java.perform(function (){
    send("start hook...");
    var InnerTest = Java.use("com.example.testfrida.Animal$InnerlTest");

    InnerTest.getClassInfo.implementation = function (){
        send("hijack inner Class");
        return "hello, frida!";
    }
});