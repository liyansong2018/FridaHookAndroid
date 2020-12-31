Java.perform(function (){
    send("start hook...");
    var Animal = Java.use("com.example.testfrida.Animal");

    Animal.getAge.implementation = function (){
        send("obtain key");

        // 直接调用类中的函数
        send("call public function >> getName(): " + this.getName());
        send("call private function >> getKey(): " + this.getKey());
        // 直接调用类中的私有属性
        send("call private property >> name: " + this.name.value);
        send("call private property >> age: " + this.age.value);
        send("call private property >> key: " + this.key.value);

        return 9999;
    };
});