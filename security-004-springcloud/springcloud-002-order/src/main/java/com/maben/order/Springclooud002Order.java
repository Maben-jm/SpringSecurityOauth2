package com.maben.order;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * 启动类
 */
@SpringBootApplication
@EnableDiscoveryClient
public class Springclooud002Order {
    public static void main(String[] args) {
        SpringApplication.run(Springclooud002Order.class, args);
        System.out.println("**************启动成功*************");
    }
}
