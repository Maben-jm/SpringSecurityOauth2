package com.maben.securitySpringboot.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 登录controller
 */
@RestController
public class LoginController {
    /**
     * 认证成功接口
     *
     * @return ..
     */
    @RequestMapping(value = "/login-success", produces = "text/plain;charset=utf-8")
    public String loginSuccess() {
        return " 登录成功";
    }

    /**
     * 测试资源1
     *
     * @return ..
     */
    @GetMapping(value = "/r/r1", produces = "text/plain;charset=utf-8")
    public String r1() {
        return " 访问资源1";
    }

    /**
     * 测试资源2
     *
     * @return ..
     */
    @GetMapping(value = "/r/r2", produces = "text/plain;charset=utf-8")
    public String r2() {
        return " 访问资源2";
    }
}
