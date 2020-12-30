package com.example.testfrida;

public class Animal {
    // 私有属性
    private String name;
    private int age;
    private static final String key = "AEKL3KJK23KLASLDKOCVL";

    // 私有方法
    private String getKey(){
        return this.key;
    }

    // 普通方法
    public String getName(){
        return this.name;
    }

    public int getAge(){
        return this.age;
    }

    public void setName(String name){
        this.name = name;
    }

    public void setAge(int age){
        this.age = age;
    }

    // 普通方法
    public String getAnimalInfo(){
        return "名字：" + this.name + "\n" + "年龄：" + Integer.toString(this.age);
    }

    // 构造方法1
    public Animal(String name, int age){
        this.name = name;
        this.age = age;
    }

    // 构造方法2
    public Animal(){

    }

    // 内部类
    class InnerlTest{
        public String getClassInfo(){
            return "内部类的getInfo方法";
        }
    }

    public InnerlTest getInnerTestInstance(){
        return new InnerlTest();
    }

    // 匿名内部类
    public String getAnoymousClass(){
        Animal dog = new Animal("dog", 4){
            // 重写getName方法
            public String getAnimalInfo(){
                return "匿名类重写getAnimalInfo()\n" + "名字：" + super.name + "\n" + "年龄：" + Integer.toString(super.age);
            }
        };
        return dog.getAnimalInfo();
    }

}
