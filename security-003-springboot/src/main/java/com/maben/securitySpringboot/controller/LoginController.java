package com.maben.securitySpringboot.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
        String username = getUsername();
        return username + " 登录成功";
    }

    /**
     * 从会话中获取用户名
     *
     * @return username
     */
    private String getUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!authentication.isAuthenticated()) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        String username = null;
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails) {
            username = ((org.springframework.security.core.userdetails.UserDetails) principal).getUsername();
        } else {
            username = principal.toString();
        }
        return username;
    }

    /**
     * 测试资源1
     *
     * @return ..
     */
    @GetMapping(value = "/r/r1", produces = "text/plain;charset=utf-8")
    public String r1() {
        String username = getUsername();
        return username + " 访问资源1";
    }

    /**
     * 测试资源2
     *
     * @return ..
     */
    @GetMapping(value = "/r/r2", produces = "text/plain;charset=utf-8")
    public String r2() {
        String username = getUsername();
        return username + " 访问资源2";
    }
}
