[TOC]

# SpringSecurity和oauth2学习

## 1.基于session的认证方式

### 1.1 认证流程

````
基于session认证的流程:
	1.用户登录,在服务端将用户信息保存到当前会话session中,并返回客户端session_id
	2.客户端将session_id存储到cookie中
	3.这样客户端再次访问的时候就会带上cookie中的session_id,并且在服务端通过session_id到session中进行校验,以此来完成用户的合法校验.
	4.当用户退出或者session过期销毁时,客户端的session_id也就失效了.
````

### 1.2 项目pom.xml

````xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.maben.security</groupId>
    <artifactId>security-001-session</artifactId>
    <version>1.0-SNAPSHOT</version>
    <packaging>war</packaging>
    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-webmvc</artifactId>
            <version>5.1.5.RELEASE</version>
        </dependency>
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>javax.servlet-api</artifactId>
            <version>3.0.1</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <version>1.18.8</version>
            <scope>provided</scope>
        </dependency>
    </dependencies>
    <build>
        <finalName>security-springmvc</finalName>
        <pluginManagement>
            <plugins>
                <!--Tomcat插件-->
                <plugin>
                    <groupId>org.apache.tomcat.maven</groupId>
                    <artifactId>tomcat7-maven-plugin</artifactId>
                    <version>2.2</version>
                    <configuration>
                        <!--
                            部署到具体机器上的Tomcat上会用到下面的参数
                            IP:目标机器Tomcat的IP
                            PORT:目标机器Tomcat的端口
                            username|password:对应目标机器的Tomcat下的 conf/tomcat-users.xml配置文件中的信息
                                例如:<user username="tomcat" password="tomcat" roles="manager-gui,manager-script,manager-jmx,manager-status,admin-gui"/>
                        -->
                        <!--
                            <url>http://IP:PORT/manager/text</url>
                            <username>tomcat</username>
                            <password>tomcat</password>
                        -->
                        <!--端口设置-->
                        <port>80</port>
                        <!--访问路径-->
                        <path>/</path>
                        <!--编码方式-->
                        <uriEncoding>UTF-8</uriEncoding>
                    </configuration>
                </plugin>
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-compiler-plugin</artifactId>
                    <configuration>
                        <source>1.8</source>
                        <target>1.8</target>
                    </configuration>
                </plugin>
                <plugin>
                    <artifactId>maven-resources-plugin</artifactId>
                    <configuration>
                        <encoding>utf-8</encoding>
                        <useDefaultDelimiters>true</useDefaultDelimiters>
                        <resources>
                            <resource>
                                <directory>src/main/resources</directory>
                                <filtering>true</filtering>
                                <includes>
                                    <include>**/*</include>
                                </includes>
                            </resource>
                            <resource>
                            <directory>src/main/java</directory>
                            <includes>
                                <include>**/*.xml</include>
                            </includes>
                            </resource>
                        </resources>
                    </configuration>
                </plugin>
            </plugins>
        </pluginManagement>
    </build>

</project>
````

### 1.3 application-context.xml配置类(Java)

````java
package com.maben.security.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.stereotype.Controller;

/**
 * 在此配置除了Controller的其它bean，比如：数据库链接池、事务管理器、业务bean等。
 * 相当于applicationContext.xml
 */
@Configuration
@ComponentScan(basePackages = "com.maben.security"
        , excludeFilters = {@ComponentScan.Filter(type = FilterType.ANNOTATION, value=Controller.class)})
public class ApplicationConfig {

}

````

### 1.4 springmvc.xml配置类(Java)

````java
package com.maben.security.config;

import com.maben.security.interceptor.SimpleAuthenticationInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

/**
 * springmvc配置类
 * 就相当于springmvc.xml文件
 */
@Configuration
@EnableWebMvc
@ComponentScan(basePackages = "com.maben.security"
        , includeFilters = {@ComponentScan.Filter(type = FilterType.ANNOTATION, value = Controller.class)})
public class WebConfig implements WebMvcConfigurer {

    /**
     * 自定义拦截器
     */
    @Autowired
    SimpleAuthenticationInterceptor simpleAuthenticationInterceptor;

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("login");
    }
    //视频解析器
    @Bean
    public InternalResourceViewResolver viewResolver(){
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB-INF/view/");
        viewResolver.setSuffix(".jsp");
        return viewResolver;
    }

    /**
     * 将自定义的加密机注册到项目
     * @param registry registry
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
       registry.addInterceptor(simpleAuthenticationInterceptor).addPathPatterns("/r/**");
    }
}

````

### 1.5 web.xml配置类(Java)

#### 1.5.1 Java

````java
package com.maben.security.init;

import com.maben.security.config.ApplicationConfig;
import com.maben.security.config.WebConfig;
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

/**
 * 加载相关配置类,相当于web.xml
 */
public class SpringApplicationInitializer extends
        AbstractAnnotationConfigDispatcherServletInitializer {
    /**
     * 加载spring配置类
     *      <listener>
     *          <listener‐class>org.springframework.web.context.ContextLoaderListener</listener‐class>
     *     </listener>
     *     <context‐param>
     *     <param‐name>contextConfigLocation</param‐name>
     *     <param‐value>/WEB‐INF/application‐context.xml</param‐value>
     *     </context‐param>
     * @return ..
     */
    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class<?>[] { ApplicationConfig.class };//指定rootContext的配置类
    }

    /**
     * 加载springMVC配置类
     <servlet>
         <servlet‐name>springmvc</servlet‐name>
            <servlet‐class>org.springframework.web.servlet.DispatcherServlet</servlet‐class>
         <init‐param>
             <param‐name>contextConfigLocation</param‐name>
             <param‐value>/WEB‐INF/spring‐mvc.xml</param‐value>
         </init‐param>
         <load‐on‐startup>1</load‐on‐startup>
     </servlet>
     * @return ..
     */
    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class<?>[] { WebConfig.class }; //指定servletContext的配置类
    }

    /**
     <servlet‐mapping>
         <servlet‐name>springmvc</servlet‐name>
         <url‐pattern>/</url‐pattern>
     </servlet‐mapping>
     * @return
     */
    @Override
    protected String[] getServletMappings() {
        return new String [] {"/"};
    }
}
````

#### 1.5.2 web.xml

````xml
<web‐app>
    <listener>
    	<listener‐class>
       		org.springframework.web.context.ContextLoaderListener
        </listener‐class>
    </listener>
    <context‐param>
        <param‐name>contextConfigLocation</param‐name>
        <param‐value>/WEB‐INF/application‐context.xml</param‐value>
    </context‐param>
    <servlet>
        <servlet‐name>springmvc</servlet‐name>
        <servlet‐class>org.springframework.web.servlet.DispatcherServlet</servlet‐class>
    <init‐param>
        <param‐name>contextConfigLocation</param‐name>
        <param‐value>/WEB‐INF/spring‐mvc.xml</param‐value>
    </init‐param>
    <load‐on‐startup>1</load‐on‐startup>
    </servlet>
        <servlet‐mapping>
        <servlet‐name>springmvc</servlet‐name>
        <url‐pattern>/</url‐pattern>
    </servlet‐mapping>
</web‐app>
````

### 1.6 创建登录页面

````jsp
<%@ page contentType="text/html;charset=UTF-8" pageEncoding="utf-8" %>
<html>
<head>
    <title>用户登录</title>
</head>
<body>
<form action="login" method="post">
    用户名：<input type="text" name="username"><br>
    密 码:
    <input type="password" name="password"><br>
    <input type="submit" value="登录">
</form>
</body>
</html>
````

### 1.7 创建Controller类

````java
package com.maben.security.controller;

import com.maben.security.pojo.AuthenticationRequest;
import com.maben.security.pojo.UserDto;
import com.maben.security.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

/**
 * 登录控制类
 */
@RestController
public class LoginController {

    @Autowired
    AuthenticationService authenticationService;

    /**
     * 登录接口:
     *      1:校验用户是否正确
     *      2:将用户信息存放到session中
     * @param authenticationRequest authenticationRequest
     * @param session  session
     * @return ..
     */
    @RequestMapping(value = "/login", produces = "text/plain;charset=utf-8")
    public String login(AuthenticationRequest authenticationRequest, HttpSession session) {
        UserDto userDto = authenticationService.authentication(authenticationRequest);
        //存入session
        session.setAttribute(UserDto.SESSION_USER_KEY, userDto);
        return userDto.getUsername() + "登录成功";
    }

    /**
     * 退出接口:
     *      退出的同时将session清空
     * @param session
     * @return
     */
    @GetMapping(value = "/logout", produces = {"text/plain;charset=UTF-8"})
    public String logout(HttpSession session) {
        session.invalidate();
        return "退出成功";
    }

    /**
     * 资源访问测试
     * @param session
     * @return
     */
    @GetMapping(value = "/r/r1", produces = {"text/plain;charset=UTF-8"})
    public String r1(HttpSession session) {
        String fullname = null;
        Object object = session.getAttribute(UserDto.SESSION_USER_KEY);
        if (object == null) {
            fullname = "匿名";
        } else {
            UserDto userDto = (UserDto) object;
            fullname = userDto.getFullname();
        }
        return fullname + "访问资源r1";
    }
	/**
     * 资源访问测试
     * @param session
     * @return
     */
    @GetMapping(value = "/r/r2", produces = {"text/plain;charset=UTF-8"})
    public String r2(HttpSession session) {
        String fullname = null;
        Object userObj = session.getAttribute(UserDto.SESSION_USER_KEY);
        if (userObj != null) {
            fullname = ((UserDto) userObj).getFullname();
        } else {
            fullname = "匿名";
        }
        return fullname + " 访问资源2";
    }
}
````

### 1.8 创建PO类

***登录类***

````java
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
````

***用户类***

````java
package com.maben.security.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Set;

/**
 * 当前登录用户信息
 */
@Data
@AllArgsConstructor
public class UserDto {
    /**
     * 在session中存放的扩展key
     */
    public static final String SESSION_USER_KEY = "_user";

    private String id;
    private String username;
    private String password;
    private String fullname;
    private String mobile;
    /**
     * 用户权限
     */
    private Set<String> authorities;
}
````

### 1.9 创建service类

***接口***

````java
package com.maben.security.service;

import com.maben.security.pojo.AuthenticationRequest;
import com.maben.security.pojo.UserDto;

/**
 * 认证服务
 */
public interface AuthenticationService {
    /**
     * 用户认证
     *
     * @param authenticationRequest 用户认证请求
     * @return 认证成功的用户信息
     */
    UserDto authentication(AuthenticationRequest authenticationRequest);
}

````

***实现类***

````java
package com.maben.security.service.impl;

import com.maben.security.pojo.AuthenticationRequest;
import com.maben.security.pojo.UserDto;
import com.maben.security.service.AuthenticationService;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * 认证业务实现类
 */
@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    /**
     * 用户认证，校验用户身份信息是否合法
     *
     * @param authenticationRequest 用户认证请求，账号和密码
     * @return 认证成功的用户信息
     */
    @Override
    public UserDto authentication(AuthenticationRequest authenticationRequest) {
        //校验参数是否为空
        if (authenticationRequest == null
                || StringUtils.isEmpty(authenticationRequest.getUsername())
                || StringUtils.isEmpty(authenticationRequest.getPassword())) {
            throw new RuntimeException("账号和密码为空");
        }
        //根据账号去查询数据库,这里测试程序采用模拟方法
        UserDto user = getUserDto(authenticationRequest.getUsername());
        //判断用户是否为空
        if (user == null) {
            throw new RuntimeException("查询不到该用户");
        }
        //校验密码
        if (!authenticationRequest.getPassword().equals(user.getPassword())) {
            throw new RuntimeException("账号或密码错误");
        }
        //认证通过，返回用户身份信息
        return user;
    }

    //根据账号查询用户信息
    private UserDto getUserDto(String userName) {
        return userMap.get(userName);
    }

    /**
     * 用户信息
     */

    private Map<String, UserDto> userMap = new HashMap<>();

    /**
     * 静态代码块,初始化用户信息,存放到内存中
     */
    {
        Set<String> authorities1 = new HashSet<>();
        authorities1.add("p1");//这个p1我们人为让它和/r/r1对应
        Set<String> authorities2 = new HashSet<>();
        authorities2.add("p2");//这个p2我们人为让它和/r/r2对应
        userMap.put("zhangsan", new UserDto("1010", "zhangsan", "123", "张三", "133443", authorities1));
        userMap.put("lisi", new UserDto("1011", "lisi", "456", "李四", "144553", authorities2));
    }
}
````

### 1.10 创建拦截器

````java
package com.maben.security.interceptor;

import com.maben.security.pojo.UserDto;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 添加一个springMVC拦截器,用来校验用户是否登录
 */
@Component
public class SimpleAuthenticationInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        //在这个方法中校验用户请求的url是否在用户的权限范围内
        //取出用户身份信息
        Object object = request.getSession().getAttribute(UserDto.SESSION_USER_KEY);
        if(object == null){
            //没有认证，提示登录
            writeContent(response,"请登录");
        }
        UserDto userDto = (UserDto) object;
        //请求的url
        String requestURI = request.getRequestURI();
        if( userDto.getAuthorities().contains("p1") && requestURI.contains("/r/r1")){
            return true;
        }
        if( userDto.getAuthorities().contains("p2") && requestURI.contains("/r/r2")){
            return true;
        }
        writeContent(response,"没有权限，拒绝访问");

        return false;
    }

    //响应信息给客户端
    private void writeContent(HttpServletResponse response, String msg) throws IOException {
        response.setContentType("text/html;charset=utf-8");
        PrintWriter writer = response.getWriter();
        writer.print(msg);
        writer.close();
    }
}
````

### 1.11 启动命令

````
Maven启动命令:   clean tomcat7:run
````

