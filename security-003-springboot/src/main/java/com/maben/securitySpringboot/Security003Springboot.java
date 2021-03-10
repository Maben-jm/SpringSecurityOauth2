package com.maben.securitySpringboot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * springboot启动类
 */
@SpringBootApplication
public class Security003Springboot {

    /**
     * 项目主启动方法
     * @param args 启动参数
     */
    public static void main(String[] args) {
        SpringApplication.run(Security003Springboot.class, args);
        System.out.println("*****************启动完成******************");
    }

}
