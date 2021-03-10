package com.maben.securitySpringboot.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

/**
 * 使用自定义的UserDetailsService,注释掉缓存的
 */
@Service
public class SpringDataUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //登录账号
        System.out.println("username="+username);
        //获取编码后的密码
        String hashpw = BCrypt.hashpw("123",BCrypt.gensalt());
        //根据账号去数据库查询...
        //这里暂时使用静态数据
        UserDetails userDetails = User.withUsername(username).password(hashpw).authorities("p1").build();
        return userDetails;
    }
}