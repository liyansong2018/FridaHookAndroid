Java.perform(function (){
    send("start hook...");
    var Animal = Java.use("com.example.testfrida.Animal");

    Animal.$init.overload("java.lang.String", "int").implementation = function (){
        send("hijack Animal()");
        send("参数1：" + arguments[0]);
        send("参数2：" + arguments[1]);
        return this.$init("frida", 999);	// 修改
    };
});