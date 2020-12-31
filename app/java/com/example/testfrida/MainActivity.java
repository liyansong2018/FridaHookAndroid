package com.example.testfrida;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;


public class MainActivity extends AppCompatActivity implements View.OnClickListener{
    Button toastButton;
    Button commonButton;
    Button constructorButton;
    Button innerButton;
    Button anonymousButton;
    Button privateButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        toastButton = findViewById(R.id.toast_button);
        commonButton = findViewById(R.id.common_button);
        constructorButton = findViewById(R.id.constructor_button);
        innerButton = findViewById(R.id.inner_button);
        anonymousButton = findViewById(R.id.anonymous_button);
        privateButton = findViewById(R.id.private_button);

        toastButton.setOnClickListener(this);
        commonButton.setOnClickListener(this);
        constructorButton.setOnClickListener(this);
        innerButton.setOnClickListener(this);
        anonymousButton.setOnClickListener(this);
        privateButton.setOnClickListener(this);

    }

    @Override
    public void onClick(View v) {
        switch (v.getId()){
            case R.id.toast_button:
                Toast.makeText(MainActivity.this, "我是主线程的Toast", Toast.LENGTH_LONG).show();
                break;
            case R.id.common_button:
                Toast.makeText(MainActivity.this, "普通方法\n" + commonFunction(), Toast.LENGTH_LONG).show();
                break;
            case R.id.constructor_button:
                Toast.makeText(MainActivity.this, "构造方法\n" + constructorFunction(), Toast.LENGTH_LONG).show();
                break;
            case R.id.inner_button:
                Toast.makeText(MainActivity.this, "内部类\n" + innerClassFunction(), Toast.LENGTH_LONG).show();
                break;
            case R.id.anonymous_button:
                Toast.makeText(MainActivity.this, "匿名类内部类\n" + anonymousClassFunction(), Toast.LENGTH_LONG).show();
                break;
            case R.id.private_button:
                Toast.makeText(MainActivity.this, "私有属性\n" + getPrivte(), Toast.LENGTH_LONG).show();
                break;
            default:
                break;
        }
    }

    public String commonFunction(){
        Animal animal = new Animal("cat", 1);
        // 调用类的普通方法
        return "动物信息\n" + animal.getAnimalInfo();
    }

    public String constructorFunction(){
        // 调用构造器
        Animal animal = new Animal("duck", 2);
        return "动物信息\n" + animal.getAnimalInfo();
    }

    public String innerClassFunction(){
        Animal animal = new Animal();
        Animal.InnerlTest innerlTest = animal.getInnerTestInstance();
        return innerlTest.getClassInfo();
    }

    public String anonymousClassFunction(){
        Animal animal = new Animal();
        return animal.getAnoymousClass();
    }

    public String getPrivte(){
        Animal animal = new Animal("penguin", 5);
        int age = animal.getAge();    // 专为 hook 使用
        return "私有属性无法查看哟！\n" + "getAge() = " + Integer.toString(age);
    }
}
