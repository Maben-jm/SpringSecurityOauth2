package com.maben.authorization.service;

import com.maben.authorization.dao.UserDao;
import com.maben.authorization.pojo.UserDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

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
        System.out.println("username="+username);
        //根据账号去数据库查询...
        UserDto user = userDao.getUserByUsername(username);
        if(user == null){
            return null;
        }
        //查询用户权限
        List<String> permissions = userDao.findPermissionsByUserId(user.getId());
        String[] perarray = new String[permissions.size()];
        permissions.toArray(perarray);
        //创建userDetails
        UserDetails userDetails = User.withUsername(user.getFullname()).password(user.getPassword()).authorities(perarray).build();
        return userDetails;
    }
}