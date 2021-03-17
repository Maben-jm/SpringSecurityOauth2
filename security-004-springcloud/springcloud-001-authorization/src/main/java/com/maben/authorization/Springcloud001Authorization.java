package com.maben.authorization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.hystrix.EnableHystrix;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableDiscoveryClient
@EnableHystrix
@EnableFeignClients(basePackages = {"com.maben"})
public class Springcloud001Authorization {
    public static void main(String[] args){
        SpringApplication.run(Springcloud001Authorization.class,args);
        System.out.println("*************************************启动成功!!!***********************************");
    }
}
