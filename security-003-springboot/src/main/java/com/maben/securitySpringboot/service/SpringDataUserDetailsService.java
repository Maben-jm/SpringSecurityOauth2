package com.maben.securitySpringboot.service;

import com.maben.securitySpringboot.dao.UserDao;
import com.maben.securitySpringboot.pojo.UserDto;
import org.springframework.beans.factory.annotation.Autowired;
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
    @Autowired
    UserDao userDao;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //登录账号
        System.out.println("username=" + username);
        //根据账号去数据库查询...
        final UserDto user = userDao.getUserByUsername(username);
        if (user == null) {
            return null;
        }
        //这里暂时使用静态数据
        UserDetails userDetails = User.withUsername(user.getFullname()).password(user.getPassword()).authorities("p1").build();
        return userDetails;
    }
}