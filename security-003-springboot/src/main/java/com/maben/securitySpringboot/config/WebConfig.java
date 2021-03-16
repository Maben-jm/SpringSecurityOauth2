package com.maben.securitySpringboot.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * springmvc配置类
 * 就相当于springmvc.xml文件
 * 由于Spring boot starter自动装配机制，这里无需使用@EnableWebMvc与@ComponentScan
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {


    /**
     * 将默认项目根路径跳转到/login,此URL为spring security提供
     * @param registry registry
     */
//    @Override
//    public void addViewControllers(ViewControllerRegistry registry) {
//        registry.addViewController("/").setViewName("redirect:/login");
//    }

    /**
     * 将默认项目根路径跳转到自定义的登录页面
     * @param registry registry
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("redirect:/login-view");
        registry.addViewController("/login-view").setViewName("login");
    }

}
