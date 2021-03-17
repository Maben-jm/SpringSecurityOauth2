package com.maben.discovery;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

/**
 * 注册中心
 */
@SpringBootApplication
@EnableEurekaServer
public class Springcloud000Discovery {
    public static void main(String[] args) {
        SpringApplication.run(Springcloud000Discovery.class,args);
        System.out.println("*******************启动成功*********************");
    }
}
