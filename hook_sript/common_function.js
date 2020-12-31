Java.perform(function (){
    send("start hook...");
    var Animal = Java.use("com.example.testfrida.Animal");

    Animal.getAnimalInfo.implementation = function (){
        send("hijack getAnimalInfo");
        return "hello, frida!";
    };
});
