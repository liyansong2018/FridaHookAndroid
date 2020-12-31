Java.perform(function (){
    send("start hook...");
    var AnoyClass = Java.use("com.example.testfrida.Animal$1");

    AnoyClass.getAnimalInfo.implementation = function (){
        return "hello,frida";	// 修改函数返回值
    };

    /*
    var Animal = Java.use("com.example.testfrida.Animal");
    Animal.$init.overload("java.lang.String", "int").implementation = function (){
        send("constructor called from " + this.$className);
        const NewAnimal = Java.use(this.$className);
        NewAnimal.getAnimalInfo.implementation = function (){
            return "hello, frida";
        };
    };
    */
});