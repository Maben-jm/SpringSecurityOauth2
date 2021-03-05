package com.maben.security.pojo;

import lombok.Data;

@Data
public class AuthenticationRequest {
/**
* 用户名
*/
private String username;
/**
* 密码
*/
private String password;
}