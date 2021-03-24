[TOC]

# SpringSecurity和oauth2学习

## 1.基于session的认证方式

>  项目: security-001-session

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

## 2. SpringSecurity 

> 项目: security-002-spring

### 2.1 SpringSecurity简介

````
SpringSecurity是一个能为基于Spring框架提供声明式的安全访问控制解决方案的安全框架;
````

### 2.2 项目pom.xml

````xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.maben</groupId>
    <artifactId>security-002-spring</artifactId>
    <version>1.0-SNAPSHOT</version>
    <packaging>war</packaging>

    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
    </properties>

    <dependencies>
        <!--spring web依赖-->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-web</artifactId>
            <version>5.1.4.RELEASE</version>
        </dependency>

        <!--spring security依赖-->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-config</artifactId>
            <version>5.1.4.RELEASE</version>
        </dependency>

        <!--spring mvc 依赖-->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-webmvc</artifactId>
            <version>5.1.5.RELEASE</version>
        </dependency>

        <!--servlet依赖-->
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>javax.servlet-api</artifactId>
            <version>3.0.1</version>
            <scope>provided</scope>
        </dependency>

        <!--lombok 依赖-->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <version>1.18.8</version>
            <scope>provided</scope>
        </dependency>
    </dependencies>
    <build>
        <finalName>security-002-spring</finalName>
        <pluginManagement>
            <plugins>
                <!--tomcat7 插件-->
                <plugin>
                    <groupId>org.apache.tomcat.maven</groupId>
                    <artifactId>tomcat7-maven-plugin</artifactId>
                    <version>2.2</version>
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

### 2.3 applicationContext.xml配置类(Java)

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
,excludeFilters = {@ComponentScan.Filter(type = FilterType.ANNOTATION,value =
Controller.class)})
public class ApplicationConfig {
}
````

### 2.4 springmvc.xml配置类(Java)

````java
package com.maben.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
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
    //视频解析器
    @Bean
    public InternalResourceViewResolver viewResolver() {
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB‐INF/views/");
        viewResolver.setSuffix(".jsp");
        return viewResolver;
    }

    /**
     * 默认Url根路径跳转到/login，此url为spring security提供
     *
     * @param registry registry
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("redirect:/login");
    }
}
````



### 2.5 SpringSecurity 配置类

````java
package com.maben.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * SpringSecurity 安全配置类
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 配置用户信息服务
     *
     * @return UserDetailsService
     */
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("zhangsan").password("123").authorities("p1").build());
        manager.createUser(User.withUsername("lisi").password("456").authorities("p2").build());
        return manager;
    }

    /**
     * 密码编码器
     *
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        //密码不需要任何操作,直接比对
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * 配置安全拦截机制
     *
     * @param http http
     * @throws Exception ..
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/r/r1").hasAuthority("p1") //访问[/r/r1]资源需要权限[p1]
                .antMatchers("/r/r2").hasAuthority("p2")//访问[/r/r2]资源需要权限[p2]
                .antMatchers("/r/**").authenticated() //所有/r/**的请求必须认证通过
                .anyRequest().permitAll() //除了/r/**，其它的请求可以访问
                .and()
                .formLogin()//允许表单登录
                .successForwardUrl("/login‐success"); //自定义登录成功的页面地址
    }

}
````

### 2.6 web.xml配置类

````java
package com.maben.security.init;

import com.maben.security.config.ApplicationConfig;
import com.maben.security.config.WebConfig;
import com.maben.security.config.WebSecurityConfig;
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
        //指定rootContext的配置类
        return new Class<?>[] { ApplicationConfig.class, WebSecurityConfig.class};
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

### 2.7 SpringSecurity初始化类

````java
package com.maben.security.init;

import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

/**
 * spring security 初始化类
 */
public class SpringSecurityApplicationInitializer extends AbstractSecurityWebApplicationInitializer {
    public SpringSecurityApplicationInitializer() {
    }
}
````

###  2.8 Controller测试类

````java
package com.maben.security.controller;

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
    @RequestMapping(value = "/login‐success", produces = "text/plain;charset=utf-8")
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

````

## 3. SpringbootSecurity学习

> 项目: security-003-springboot

### 3.1  pom.xml文件

````xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.maben</groupId>
    <artifactId>security-003-springboot</artifactId>
    <version>1.0-SNAPSHOT</version>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.1.3.RELEASE</version>
    </parent>
    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
    </properties>
    <dependencies>
        <!--springboot web依赖-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <!--springboot security依赖-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <!--jsp依赖-->
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>javax.servlet-api</artifactId>
            <scope>provided</scope>
        </dependency>
        <!--jsp中jstl标签依赖-->
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>jstl</artifactId>
        </dependency>
        <!--jsp依赖-->
        <dependency>
            <groupId>org.apache.tomcat.embed</groupId>
            <artifactId>tomcat-embed-jasper</artifactId>
            <scope>provided</scope>
        </dependency>
        <!--Tomcat依赖-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-tomcat</artifactId>
            <scope>provided</scope>
        </dependency>
        <!--lombok依赖-->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
        </dependency>
        <!--测试依赖-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
    <build>
        <finalName>security-002-spring</finalName>
        <pluginManagement>
            <plugins>
                <!--tomcat7 插件-->
                <plugin>
                    <groupId>org.apache.tomcat.maven</groupId>
                    <artifactId>tomcat7-maven-plugin</artifactId>
                    <version>2.2</version>
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

### 3.2  application.yml配置

````yaml
server:
  port: 8080
  servlet:
    context-path: /
spring:
  application:
    name: security-003-springcloud
  mvc:
    view:
      prefix: /WEB-INF/views
      suffix: .jsp
````

### 3.3 主启动类

````java
package com.maben.securitySpringboot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * springboot启动类
 */
@SpringBootApplication
public class Security003Springboot {

    /**
     * 项目主启动方法
     * @param args 启动参数
     */
    public static void main(String[] args) {
        SpringApplication.run(Security003Springboot.class, args);
        System.out.println("*****************启动完成******************");
    }

}
````

### 3.4 springmvc.xml(Java配置类)

````java
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
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("redirect:/login");
    }
}
````

### 3.5 Security配置文件

````java
package com.maben.securitySpringboot.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * SpringSecurity 安全配置类
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 配置用户信息服务
     * @return UserDetailsService
     */
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("zhangsan").password("123").authorities("p1").build());
        manager.createUser(User.withUsername("lisi").password("456").authorities("p2").build());
        return manager;
    }

    /**
     * 密码编码器
     *
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        //密码不需要任何操作,直接比对
       return NoOpPasswordEncoder.getInstance();

        //使用BCrypt编码验证密码
//        return new BCryptPasswordEncoder();
    }

    /**
     * 配置安全拦截机制
     *
     * @param http http
     * @throws Exception ..
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/r/r1").hasAuthority("p1") //访问[/r/r1]资源需要权限[p1]
                .antMatchers("/r/r2").hasAuthority("p2")//访问[/r/r2]资源需要权限[p2]
                .antMatchers("/r/**").authenticated() //所有/r/**的请求必须认证通过
                .anyRequest().permitAll() //除了/r/**，其它的请求可以访问
                .and()
                .formLogin()//允许表单登录
                .successForwardUrl("/login‐success"); //自定义登录成功的页面地址
    }

}
````

### 3.6 Controller类

````java
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
    @RequestMapping(value = "/login‐success", produces = "text/plain;charset=utf-8")
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
````

### 3.7 userDetailsService不用内存的

#### 3.7.1 自定义userDetailService类

````java
package com.maben.securitySpringboot.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

/**
 * 使用自定义的UserDetailsService
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
````

#### 3.7.2 WebSecurityConfig.java修改

> 1.注释掉缓存用户信息
>
> 2.将编码方式换成BCrypt
>
> 3.将访问权限去掉(因为使用的userDetailService)

````java
package com.maben.securitySpringboot.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * SpringSecurity 安全配置类
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 配置用户信息服务
     * @return UserDetailsService
     */
   /* @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("zhangsan").password("123").authorities("p1").build());
        manager.createUser(User.withUsername("lisi").password("456").authorities("p2").build());
        return manager;
    }*/

    /**
     * 密码编码器
     *
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        //密码不需要任何操作,直接比对
//       return NoOpPasswordEncoder.getInstance();

        //使用BCrypt编码验证密码
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置安全拦截机制
     *
     * @param http http
     * @throws Exception ..
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
 //               .antMatchers("/r/r1").hasAuthority("p1") //访问[/r/r1]资源需要权限[p1]
//                .antMatchers("/r/r2").hasAuthority("p2")//访问[/r/r2]资源需要权限[p2]
                .antMatchers("/r/**").authenticated() //所有/r/**的请求必须认证通过
                .anyRequest().permitAll() //除了/r/**，其它的请求可以访问
                .and()
                .formLogin()//允许表单登录
                .successForwardUrl("/login‐success"); //自定义登录成功的页面地址
    }

}
````

### 3.8 BCryptPasswordEncoder测试类

````java
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * 测试BCrypt编码
 */
@SpringBootTest(classes = TestBCrypt.class)
@RunWith(SpringRunner.class)
public class TestBCrypt {

    @Test
    public void testBCrypt(){
        //对原始密码加密
        String hashpw = BCrypt.hashpw("123",BCrypt.gensalt());
        System.out.println(hashpw);
        //校验原始密码和BCrypt密码是否一致
        boolean checkpw = BCrypt.checkpw("123","$2a$10$NlBC84MVb7F95EXYTXwLneXgCca6/GipyWR5NHm8K0203bSQMLpvm");
        System.out.println(checkpw);
    }
}
````

### 3.9 配置自定义的登录页面

#### 3.9.0 application.yml

````yaml
server:
  port: 8080
  servlet:
    context-path: /
spring:
  application:
    name: security-003-springcloud
  mvc:
    view:
      prefix: /WEB-INF/view/
      suffix: .jsp
````



#### 3.9.1 WebConfifig.java

````java
 /**
     * 将默认项目根路径跳转到自定义的登录页面
     * @param registry registry
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("redirect:/login-view");
        registry.addViewController("/login-view").setViewName("login");
    }
````

#### 3.9.2 WebSecurityConfifig

````java
    /**
     * 配置安全拦截机制
     *
     * @param http http
     * @throws Exception ..
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        自定义登录页面
        http.csrf().disable() //屏蔽CSRF控制，即spring security不再限制CSRF
                .authorizeRequests()
                .antMatchers("/r/**").authenticated() //所有/r/**的请求必须认证通过
                .anyRequest().permitAll() //除了/r/**，其它的请求可以访问
                .and()
                .formLogin()//允许表单登录
                .loginPage("/login-view") //指定我们自己开发的登录页面,spring security以重定向方式跳转到/login-view
                .loginProcessingUrl("/login")//指定登录处理的URL，也就是用户名、密码表单提交的目的路径
                .successForwardUrl("/login-success") //自定义登录成功的页面地址
                .permitAll();
    }

````

####  3.9.3 登录页面

````jsp
<%@ page contentType="text/html;charset=UTF-8" pageEncoding="utf-8" %>
<html>
    <head>
        <title>用户登录</title>
    </head>
    <body>
        <form action="login" method="post">
            用户名：<input type="text" name="username"><br>
            密&nbsp;&nbsp;&nbsp;码:
            <input type="password" name="password"><br>
            <input type="submit" value="登录">
        </form>
    </body>
</html>
````

### 3.10 加上数据库

#### 3.10.1 SQL语句

````sql
-- 建库语句
CREATE DATABASE `user_db` CHARACTER SET 'utf8' COLLATE 'utf8_general_ci';
-- 建表语句
CREATE TABLE `t_user` (
    `id` bigint(20) NOT NULL COMMENT '用户id',
    `username` varchar(64) NOT NULL,
    `password` varchar(64) NOT NULL,
    `fullname` varchar(255) NOT NULL COMMENT '用户姓名',
    `mobile` varchar(11) DEFAULT NULL COMMENT '手机号',
    PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=DYNAMIC;
-- 插入语句
 insert into t_user values(1,"zhangsan","$2a$10$NlBC84MVb7F95EXYTXwLneXgCca6/GipyWR5NHm8K0203bSQMLpvm","zhangsan","13780200377");
````

#### 3.10.2 pom.xml

````xml
       <!--mysql依赖-->
        <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-jdbc</artifactId>
    </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>5.1.47</version>
        </dependency>
````

#### 3.10.3 application.yml

````yaml
spring:
  application:
    name: security-003-springcloud
  mvc:
    view:
      prefix: /WEB-INF/view/
      suffix: .jsp
  datasource:
    driver-class-name: com.mysql.jdbc.Driver
    url: jdbc:mysql://localhost:3306/user_db
    username: root
    password: root
````



#### 3.10.4 pojo类

````java
package com.maben.securitySpringboot.pojo;

import lombok.Data;

@Data
public class UserDto {
    private String id;
    private String username;
    private String password;
    private String fullname;
    private String mobile;
}
````

#### 3.10.5 dao类

````java
package com.maben.securitySpringboot.dao;

import com.maben.securitySpringboot.pojo.UserDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class UserDao {
    @Autowired
    JdbcTemplate jdbcTemplate;
    public UserDto getUserByUsername(String username){
        String sql ="select id,username,password,fullname from t_user where username = ?";
        List<UserDto> list = jdbcTemplate.query(sql, new Object[]{username}, new
                BeanPropertyRowMapper<>(UserDto.class));
        if(list == null && list.size() <= 0){
            return null;
        }
        return list.get(0);
    }
}
````

#### 3.10.6 service修改

````java
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
````

### 3.11 会话

> 用户认证通过后，为了避免用户的每次操作都进行认证可将用户的信息保存在会话中。spring security提供会话管理，认证通过后将身份信息放入SecurityContextHolder上下文，SecurityContext与当前线程进行绑定，方便获取用户身份。

#### 3.11.1 获取资源同时获取用户信息

````java
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
````

#### 3.11.2 会话控制简介

````java
/**
SessionCreationPolicy.IF_REQUIRED:每个登录成功的用户会新建一个Session
SessionCreationPolicy.NEVER:Spring Security对登录成功的用户不创建Session了但若你的应用程序在某地方	新建了session，那么Spring Security会用它的。
SessionCreationPolicy.STATELESS:Spring Security对登录成功的用户不会创建Session了，你的应用程序也不	会允许新建session。并且它会暗示不使用cookie，所以每个请求都需要重新进行身份验证。这种无状态架构适用于	 REST API及其无状态认证机制。
*/
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.sessionManagement()
    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
}
````

***会话超时***

> 通过设置会话超时时间来保证session

````java
1.修改application.properties
server.servlet.session.timeout=30s
2.在Webconfig.java中添加设置
   				 @Override
    protected void configure(HttpSecurity http) throws Exception {
//        自定义登录页面
        http.csrf().disable() //屏蔽CSRF控制，即spring security不再限制CSRF
                .authorizeRequests()
                .antMatchers("/r/**").authenticated() //所有/r/**的请求必须认证通过
                .anyRequest().permitAll() //除了/r/**，其它的请求可以访问
                .and()
                .formLogin()//允许表单登录
                .loginPage("/login-view") //指定我们自己开发的登录页面,spring security以重定向方式跳转到/login-view
                .loginProcessingUrl("/login")//指定登录处理的URL，也就是用户名、密码表单提交的目的路径
                .successForwardUrl("/login-success") //自定义登录成功的页面地址            
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) //每个登录成功的用户会新建一个Session
                .invalidSessionUrl("/login‐view?error=INVALID_SESSION");
    }

````

### 3.12 添加退出

````java
   @Override
    protected void configure(HttpSecurity http) throws Exception {
//        自定义登录页面
        http.csrf().disable() //屏蔽CSRF控制，即spring security不再限制CSRF
                .authorizeRequests()
                .antMatchers("/r/**").authenticated() //所有/r/**的请求必须认证通过
                .anyRequest().permitAll() //除了/r/**，其它的请求可以访问
                .and()
                .formLogin()//允许表单登录
                .loginPage("/login-view") //指定我们自己开发的登录页面,spring security以重定向方式跳转到/login-view
                .loginProcessingUrl("/login")//指定登录处理的URL，也就是用户名、密码表单提交的目的路径
                .successForwardUrl("/login-success") //自定义登录成功的页面地址
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) //每个登录成功的用户会新建一个Session
                .invalidSessionUrl("/login-view?error=INVALID_SESSION")
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login-view?logout");
    }
````

### 3.13 授权

#### 3.13.1 SQL

````sql
-- 角色表：
CREATE TABLE `t_role` (
`id` varchar(32) NOT NULL,
`role_name` varchar(255) DEFAULT NULL,
`description` varchar(255) DEFAULT NULL,
`create_time` datetime DEFAULT NULL,
`update_time` datetime DEFAULT NULL,
`status` char(1) NOT NULL,
PRIMARY KEY (`id`),
UNIQUE KEY `unique_role_name` (`role_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
insert into `t_role`(`id`,`role_name`,`description`,`create_time`,`update_time`,`status`) values('1','管理员',NULL,NULL,NULL,'');

-- 用户角色关系表：
CREATE TABLE `t_user_role` (
`user_id` varchar(32) NOT NULL,
`role_id` varchar(32) NOT NULL,
`create_time` datetime DEFAULT NULL,
`creator` varchar(255) DEFAULT NULL,
PRIMARY KEY (`user_id`,`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
insert into `t_user_role`(`user_id`,`role_id`,`create_time`,`creator`) values('1','1',NULL,NULL);

-- 权限表：
CREATE TABLE `t_permission` (
`id` varchar(32) NOT NULL,
`code` varchar(32) NOT NULL COMMENT '权限标识符',
`description` varchar(64) DEFAULT NULL COMMENT '描述',
`url` varchar(128) DEFAULT NULL COMMENT '请求地址',
PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
insert into `t_permission`(`id`,`code`,`description`,`url`) values 
('1','p1','测试资源1','/r/r1'),('2','p3','测试资源2','/r/r2');

-- 角色权限关系表：
CREATE TABLE `t_role_permission` (
`role_id` varchar(32) NOT NULL,
`permission_id` varchar(32) NOT NULL,
PRIMARY KEY (`role_id`,`permission_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
insert into `t_role_permission`(`role_id`,`permission_id`) values 
('1','1'),('1','2');
````

#### 3.13.2 dao接口修改

````java
//根据用户id查询用户权限
public List<String> findPermissionsByUserId(String userId){
        String sql="SELECT * FROM t_permission WHERE id IN(\n" +
                "SELECT permission_id FROM t_role_permission WHERE role_id IN(\n" +
                "\tSELECT role_id FROM t_user_role WHERE user_id = ? \n" +
                ")\n" +
                ")";
        List<PermissionDto> list = jdbcTemplate.query(sql, new Object[]{userId}, new BeanPropertyRowMapper<>(PermissionDto.class));
        List<String> permissions = new ArrayList<>();
        list.iterator().forEachRemaining(c ->permissions.add(c.getCode()));
        return permissions;
    }
````

#### 3.13.3 po类添加

````java
@Data
public class PermissionDto {

    private String id;
    private String code;
    private String description;
    private String url;
}
````

#### 3.13.4 service类修改

````java
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
````

#### 3.13.5 授权

> 第一种方法就是"Web授权"在Webconfig.java中配置,类似:
>
> ​	.antMatchers("/r/r1").hasAuthority("p1") 
>
> ​	.antMatchers("/r/r2").hasAuthority("p2") 
>
> 第二种方法就是"方法授权",也就是方法注解,方便快捷(推荐使用)
>
> ​	我们可以在任何 @Configuration 实例上使用 @EnableGlobalMethodSecurity 注释来启用基于注解的安全性。

````java
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    ...
}

@GetMapping(value = "/r/r1",produces = {"text/plain;charset=UTF-8"})
@PreAuthorize("hasAuthority('p1')")//拥有p1权限才可以访问
public String r1(){
    return getUsername()+" 访问资源1";
}

@GetMapping(value = "/r/r2",produces = {"text/plain;charset=UTF-8"})
@PreAuthorize("hasAuthority('p2') or hasAuthority('p3')")//拥有p2权限或者p3权限才可以访问
public String r2(){
    return getUsername()+" 访问资源2";
}
````

## 4.SpringCloudSecurity

> 项目名称: security-004-springcloud

### 4.0 父项目

#### 4.0.1 pom.xml文件

````xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.maben</groupId>
    <artifactId>security-004-springcloud</artifactId>
    <version>1.0-SNAPSHOT</version>
    <modules>
        <module>springcloud-001-authorization</module>
    </modules>
    <packaging>pom</packaging>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.1.3.RELEASE</version>
    </parent>
    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
        <java.version>1.8</java.version>
    </properties>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>Greenwich.RELEASE</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
            <dependency>
                <groupId>javax.servlet</groupId>
                <artifactId>javax.servlet-api</artifactId>
                <version>3.1.0</version>
                <scope>provided</scope>
            </dependency>
            <dependency>
                <groupId>javax.interceptor</groupId>
                <artifactId>javax.interceptor-api</artifactId>
                <version>1.2</version>
            </dependency>
            <dependency>
                <groupId>com.alibaba</groupId>
                <artifactId>fastjson</artifactId>
                <version>1.2.47</version>
            </dependency>
            <dependency>
                <groupId>org.projectlombok</groupId>
                <artifactId>lombok</artifactId>
                <version>1.18.0</version>
            </dependency>
            <dependency>
                <groupId>mysql</groupId>
                <artifactId>mysql-connector-java</artifactId>
                <version>5.1.47</version>
            </dependency>
            <dependency>
                <groupId>org.springframework.security</groupId>
                <artifactId>spring-security-jwt</artifactId>
                <version>1.0.10.RELEASE</version>
            </dependency>
            <dependency>
                <groupId>org.springframework.security.oauth.boot</groupId>
                <artifactId>spring-security-oauth2-autoconfigure</artifactId>
                <version>2.1.3.RELEASE</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
    <build>
        <finalName>${project.name}</finalName>
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
        <plugins>
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
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
````

### 4.1 discovery子项目

> 项目名称: springcloud-000-discovery

#### 4.1.1 pom.xml

````xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <parent>
        <artifactId>security-004-springcloud</artifactId>
        <groupId>com.maben</groupId>
        <version>1.0-SNAPSHOT</version>
    </parent>
    <modelVersion>4.0.0</modelVersion>

    <artifactId>springcloud-000-discovery</artifactId>

    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-netflix-eureka-server</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>

    </dependencies>
</project>
````

#### 4.1.2 application.yml

````yaml
spring:
  application:
    name: distributed-discovery

server:
  port: 53000 #启动端口

eureka:
  server:
    enable-self-preservation: false    #关闭服务器自我保护，客户端心跳检测15分钟内错误达到80%服务会保护，导致别人还认为是好用的服务
    eviction-interval-timer-in-ms: 10000 #清理间隔（单位毫秒，默认是60*1000）5秒将客户端剔除的服务在服务注册列表中剔除#
    shouldUseReadOnlyResponseCache: true #eureka是CAP理论种基于AP策略，为了保证强一致性关闭此切换CP 默认不关闭 false关闭
  client:
    register-with-eureka: false  #false:不作为一个客户端注册到注册中心
    fetch-registry: false      #为true时，可以启动，但报异常：Cannot execute request on any known server
    instance-info-replication-interval-seconds: 10
    serviceUrl:
      defaultZone: http://localhost:${server.port}/eureka/
  instance:
    hostname: ${spring.cloud.client.ip-address}
    prefer-ip-address: true
    instance-id: ${spring.cloud.client.ip-address}:${server.port}

````

#### 4.1.3 启动类

````java
package com.maben.discovery;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

/**
 * 注册中心
 */
@SpringBootApplication
@EnableEurekaServer
public class Springcloud000Discovery {
    public static void main(String[] args) {
        SpringApplication.run(Springcloud000Discovery.class,args);
        System.out.println("*******************启动成功*********************");
    }
}
````



### 4.2 authorization子项目

> 项目名称: springcloud-001-authorization

#### 4.2.1 pom.xml文件

````xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <parent>
        <artifactId>security-004-springcloud</artifactId>
        <groupId>com.maben</groupId>
        <version>1.0-SNAPSHOT</version>
    </parent>
    <modelVersion>4.0.0</modelVersion>

    <artifactId>springcloud-001-authorization</artifactId>

    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-netflix-hystrix</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-netflix-ribbon</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-openfeign</artifactId>
        </dependency>
        <dependency>
            <groupId>com.netflix.hystrix</groupId>
            <artifactId>hystrix-javanica</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.retry</groupId>
            <artifactId>spring-retry</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-freemarker</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.data</groupId>
            <artifactId>spring-data-commons</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-oauth2</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-jwt</artifactId>
        </dependency>
        <dependency>
            <groupId>javax.interceptor</groupId>
            <artifactId>javax.interceptor-api</artifactId>
        </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-jdbc</artifactId>
        </dependency>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
        </dependency>
    </dependencies>
</project>
````

#### 4.2.2 主启动类

````java
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
    }
}
````

#### 4.2.3 配置文件

````properties
# 项目名称
spring.application.name=springcloud-001-authorization
# server相关
server.port=53020
server.use-forward-headers = true
server.servlet.context-path = /
server.tomcat.remote_ip_header = x-forwarded-for
server.tomcat.protocol_header = x-forwarded-proto
# 日志相关
logging.level.root = info
logging.level.org.springframework.web = info
# spring相关
spring.main.allow-bean-definition-overriding = true
spring.http.encoding.enabled = true
spring.http.encoding.charset = UTF-8
spring.http.encoding.force = true
spring.freemarker.enabled = true
spring.freemarker.suffix = .html
spring.freemarker.request-context-attribute = rc
spring.freemarker.content-type = text/html
spring.freemarker.charset = UTF-8
spring.mvc.throw-exception-if-no-handler-found = true
spring.resources.add-mappings = false
#数据库相关
spring.datasource.url = jdbc:mysql://localhost:3306/user_db?useUnicode=true&characterEncoding=utf-8&useSSL=false
spring.datasource.username = root
spring.datasource.password = root
spring.datasource.driver-class-name = com.mysql.jdbc.Driver
# discovery
eureka.client.serviceUrl.defaultZone = http://localhost:53000/eureka/
eureka.instance.preferIpAddress = true
eureka.instance.instance-id = ${spring.cloud.client.ip-address}:${server.port}
management.endpoints.web.exposure.include = refresh,health,info,env
# feign相关
feign.hystrix.enabled = true
feign.compression.request.enabled = true
feign.compression.request.mime-types[0] = text/xml
feign.compression.request.mime-types[1] = application/xml
feign.compression.request.mime-types[2] = application/json
feign.compression.request.min-request-size = 2048
feign.compression.response.enabled = true
````

#### 4.2.4 授权服务器配置

***认证配置类***

````java
package com.maben.authorization.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * 认证配置类
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {
    /**
     * 一:配置客户端详细信息::
     * ClientDetailsServiceConfigurer能够使用内存或者JDBC来实现客户端详情服务（ClientDetailsService）
     * ClientDetailsService负责查找ClientDetails，而ClientDetails有几个重要的属性如下列表：
     *      clientId：（必须的）用来标识客户的Id。
     *      secret：（需要值得信任的客户端）客户端安全码，如果有的话。
     *      scope：用来限制客户端的访问范围，如果为空（默认）的话，那么客户端拥有全部的访问范围。
     *      authorizedGrantTypes：此客户端可以使用的授权类型，默认为空。
     *      authorities：此客户端可以使用的权限（基于Spring Security authorities）
     *客户端详情（Client Details）能够在应用程序运行的时候进行更新，可以通过访问底层的存储服务（例如将客户端详情存储在一个关系数据库的表中，就可以使用 JdbcClientDetailsService）或者通过自己实现
     * ClientRegistrationService接口（同时你也可以实现 ClientDetailsService 接口）来进行管理。
     * @param clients clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // clients.withClientDetails(clientDetailsService); //最终需要配置成数据库的  现在暂时是临时的
        clients.inMemory()// 使用in‐memory存储
                .withClient("c1")// client_id
                .secret(new BCryptPasswordEncoder().encode("secret"))
                .resourceIds("res1")
                .authorizedGrantTypes("authorization_code","password","client_credentials","implicit","refresh_token")
                // 该client允许的授权类型authorization_code,password,refresh_token,implicit,client_credentials
                .scopes("all")// 允许的授权范围
                .autoApprove(false)//false跳转到授权页面
                //加上验证回调地址
                .redirectUris("http://www.baidu.com");
    }


    /**
     * tokenStore
     */
    @Autowired
    private TokenStore tokenStore;
    @Autowired
    private ClientDetailsService clientDetailsService;

    /**
     * 二:管理令牌::
     *AuthorizationServerTokenServices 接口定义了一些操作使得你可以对令牌进行一些必要的管理，令牌可以被用来加载身份信息，里面包含了这个令牌的相关权限。
     *自己可以创建 AuthorizationServerTokenServices 这个接口的实现，则需要继承 DefaultTokenServices 这个类，里面包含了一些有用实现，你可以使用它来修改令牌的格式和令牌的存储。
     *默认的，当它尝试创建一个令牌的时候，是使用随机值来进行填充的，除了持久化令牌是委托一个 TokenStore 接口来实现以外，这个类几乎帮你做了所有的事情。
     *并且 TokenStore 这个接口有一个默认的实现，它就是 InMemoryTokenStore ，如其命名，所有的令牌是被保存在了内存中。
     * @return
     */
    @Bean
    public AuthorizationServerTokenServices tokenService() {
        DefaultTokenServices service=new DefaultTokenServices();
        service.setClientDetailsService(clientDetailsService);
        service.setSupportRefreshToken(true);
        service.setTokenStore(tokenStore);
        // 令牌默认有效期2小时
        service.setAccessTokenValiditySeconds(7200);
        // 刷新令牌默认有效期3天
        service.setRefreshTokenValiditySeconds(259200);
        return service;
    }

    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 三:令牌访问端点配置::
     * AuthorizationServerEndpointsConfigurer 这个对象的实例可以完成令牌服务以及令牌endpoint配置
     * 第一:配置授权类型（Grant Types）:AuthorizationServerEndpointsConfifigurer 通过设定以下属性决定支持的授权类型（Grant Types）:
     *      authenticationManager：认证管理器，当你选择了资源所有者密码（password）授权类型的时候，请设置
     * 这个属性注入一个 AuthenticationManager 对象。
     *      userDetailsService：如果你设置了这个属性的话，那说明你有一个自己的 UserDetailsService 接口的实现，
     * 或者你可以把这个东西设置到全局域上面去（例如 GlobalAuthenticationManagerConfifigurer 这个配置对
     * 象），当你设置了这个之后，那么 "refresh_token" 即刷新令牌授权类型模式的流程中就会包含一个检查，用
     * 来确保这个账号是否仍然有效，假如说你禁用了这个账户的话。
     *      authorizationCodeServices：这个属性是用来设置授权码服务的（即 AuthorizationCodeServices 的实例对
     * 象），主要用于 "authorization_code" 授权码类型模式。
     *      implicitGrantService：这个属性用于设置隐式授权模式，用来管理隐式授权模式的状态。
     *      tokenGranter：当你设置了这个东西（即 TokenGranter 接口实现），那么授权将会交由你来完全掌控，并
     * 且会忽略掉上面的这几个属性，这个属性一般是用作拓展用途的，即标准的四种授权模式已经满足不了你的
     * 需求的时候，才会考虑使用这个。
     *
     * 第二: 配置授权端点的URL（Endpoint URLs）：
     *  AuthorizationServerEndpointsConfigurer 这个配置对象有一个叫做 pathMapping() 的方法用来配置端点URL链接，它有两个参数：
     *      第一个参数：String 类型的，这个端点URL的默认链接。
     *      第二个参数：String 类型的，你要进行替代的URL链接。
     *      以上的参数都将以 "/" 字符为开始的字符串，框架的默认URL链接如下列表，可以作为这个 pathMapping() 方法的第一个参数：
     *          /oauth/authorize：授权端点。
     *          /oauth/token：令牌端点。
     *          /oauth/confifirm_access：用户确认授权提交端点。
     *          /oauth/error：授权服务错误信息端点。
     *          /oauth/check_token：用于资源服务访问的令牌解析端点。
     *          /oauth/token_key：提供公有密匙的端点，如果你使用JWT令牌的话。
     *      需要注意的是授权端点这个URL应该被Spring Security保护起来只供授权用户访问.
     * @param endpoints endpoints
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
                .authenticationManager(authenticationManager)//密码模式需要
                .authorizationCodeServices(authorizationCodeServices)//授权码模式需要
                .tokenServices(tokenService())//令牌管理服务
                .allowedTokenEndpointRequestMethods(HttpMethod.POST);//允许POST提交
    }

    /**
     * 设置授权码模式的授权码如何存取，暂时采用内存方式
     * @return AuthorizationCodeServices
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new InMemoryAuthorizationCodeServices();
    }

    /**
     * 四:令牌端点的安全约束:
     * AuthorizationServerSecurityConfifigurer：用来配置令牌端点(Token Endpoint)的安全约束.
     *      tokenkey这个endpoint当使用JwtToken且使用非对称加密时，资源服务用于获取公钥而开放的，这里指这个endpoint完全公开。
     *      checkToken这个endpoint完全公开
     *      allowFormAuthenticationForClients: 允许表单认证
     * @param security security
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security){
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("permitAll()")
                .allowFormAuthenticationForClients() //允许表单认证
        ;
    }

}
````

***配置tokenStore***

````java
package com.maben.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * 配置tokenStore 用来生成令牌
 *  InMemoryTokenStore:这个版本的实现是被默认采用的，它可以完美的工作在单服务器上（即访问并发量压力不大的情况下，并且它在失败的时候不会进行备份），大多数的项目都可以使用这个版本的实现来进行尝试，你可以在开发的时候使用它来进行管理，因为不会被保存到磁盘中，所以更易于调试。
 *  JdbcTokenStore: 这是一个基于JDBC的实现版本，令牌会被保存进关系型数据库。使用这个版本的实现时，你可以在不同的服务器之间共享令牌信息，使用这个版本的时候请注意把"spring-jdbc"这个依赖加入到你的classpath当中。
 *  JwtTokenStore: 这个版本的全称是 JSON Web Token（JWT），它可以把令牌相关的数据进行编码（因此对于后端服务来说，它不需要进行存储，这将是一个重大优势），但是它有一个缺点，那就是撤销一个已经授权令牌将会非常困难，所以它通常用来处理一个生命周期较短的令牌以及撤销刷新令牌（refresh_token）。另外一个缺点就是这个令牌占用的空间会比较大，如果你加入了比较多用户凭证信息。JwtTokenStore 不会保存任何数据，但是它在转换令牌值以及授权信息方面与 DefaultTokenServices 所扮演的角色是一样的。
 */
@Configuration
public class TokenConfig {
    @Bean
    public TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }
}
````

***配置WebConfig.java

````java
package com.maben.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * security 相关配置
 **/
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //认证管理器
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    //密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //安全拦截机制（最重要）
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/r/r1").hasAnyAuthority("p1")
                .antMatchers("/login*").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
        ;

    }
}

````

#### 4.2.5 其他

> dao/pojo/service都和SpringSecurity一样

### 4.3 order子项目

> 项目名称: springcloud-002-order

#### 4.3.1 pom.xml

````xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <parent>
        <artifactId>security-004-springcloud</artifactId>
        <groupId>com.maben</groupId>
        <version>1.0-SNAPSHOT</version>
    </parent>
    <modelVersion>4.0.0</modelVersion>

    <artifactId>springcloud-002-order</artifactId>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-oauth2</artifactId>
        </dependency>
        <dependency>
            <groupId>javax.interceptor</groupId>
            <artifactId>javax.interceptor-api</artifactId>
        </dependency>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
        </dependency>
    </dependencies>
</project>
````

#### 4.3.2 启动类

````java
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

````

#### 4.3.3 配置类

````properties
# 项目名
spring.application.name=security-004-springcloud
# server相关
server.port=53021
server.servlet.context-path = /
server.tomcat.remote_ip_header = x-forwarded-for
server.tomcat.protocol_header = x-forwarded-proto
server.use-forward-headers = true
# log相关
logging.level.root = debug
logging.level.org.springframework.web = info
#spring相关
spring.main.allow-bean-definition-overriding = true
spring.http.encoding.enabled = true
spring.http.encoding.charset = UTF-8
spring.http.encoding.force = true
spring.freemarker.enabled = true
spring.freemarker.suffix = .html
spring.freemarker.request-context-attribute = rc
spring.freemarker.content-type = text/html
spring.freemarker.charset = UTF-8
spring.mvc.throw-exception-if-no-handler-found = true
spring.resources.add-mappings = false
management.endpoints.web.exposure.include = refresh,health,info,env
# openfeign相关
feign.hystrix.enabled = true
feign.compression.request.enabled = true
feign.compression.request.mime-types[0] = text/xml
feign.compression.request.mime-types[1] = application/xml
feign.compression.request.mime-types[2] = application/json
feign.compression.request.min-request-size = 2048
feign.compression.response.enabled = true
````

#### 4.3.4 配置类

***资源服务类***

````java
package com.maben.order.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

/**
 *  将@EnableResourceServer 注解到一个 @Configuration 配置类上，
 *  并且必须使用 ResourceServerConfigurer 这个配置对象来进行配置
 */
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResouceServerConfig extends ResourceServerConfigurerAdapter {
    public static final String RESOURCE_ID = "res1";

    /**
     * ResourceServerSecurityConfigurer中主要包括：
     *      -tokenServices：ResourceServerTokenServices 类的实例，用来实现令牌服务。
     *      -tokenStore：TokenStore类的实例，指定令牌如何访问，与tokenServices配置可选
     *      -resourceId：这个资源服务的ID，这个属性是可选的，但是推荐设置并在授权服务中进行验证。
     * @param resources resources
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId(RESOURCE_ID)
        .tokenServices(tokenService())
        .stateless(true);
    }

    /**
     * HttpSecurity配置这个与Spring Security类似：
     *      -请求匹配器，用来设置需要进行保护的资源路径，默认的情况下是保护资源服务的全部路径。
     *      -通过http.authorizeRequests()来设置受保护资源的访问规则
     *      -其他的自定义权限保护规则通过 HttpSecurity 来进行配置。
     * @param http http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
        .authorizeRequests()
        .antMatchers("/**").access("#oauth2.hasScope('all')")
        .and().csrf().disable()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    /**
     * 资源服务令牌解析服务
     * @return ResourceServerTokenServices
     */
    @Bean
    public ResourceServerTokenServices tokenService() {
        //使用远程服务请求授权服务器校验token,必须指定校验token 的url、client_id，client_secret
        RemoteTokenServices service=new RemoteTokenServices();
        service.setCheckTokenEndpointUrl("http://localhost:53020/oauth/check_token");
        service.setClientId("c1");
        service.setClientSecret("secret");
        return service;
    }

}
````

***webSecurity***

````java
package com.maben.order.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * 资源控制类
 */
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    //安全拦截机制（最重要）
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
        .authorizeRequests()
        // .antMatchers("/r/r1").hasAuthority("p2")
        // .antMatchers("/r/r2").hasAuthority("p2")
        .antMatchers("/r/**").authenticated()//所有/r/**的请求必须认证通过
        .anyRequest().permitAll()//除了/r/**，其它的请求可以访问
        ;
    }
}
````

#### 4.3.5 controller类

````java
package com.maben.order.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * controller 测试类
 */
@RestController
public class OrderController {
    @GetMapping(value = "/r1")
    @PreAuthorize("hasAnyAuthority('p1')")
    public String r1(){
        return "访问资源1";
    }
}
````

### 4.4 测试(密码认证方式)

> 使用idea的restful工具导入

#### 4.4.1 获取认证token

````xml
<RestClientRequest>
  <option name="biscuits">
    <list />
  </option>
  <option name="httpMethod" value="POST" />
  <option name="urlBase" value="http://localhost:53020" />
  <option name="urlPath" value="/oauth/token" />
  <option name="headers">
    <list>
      <KeyValuePair>
        <option name="key" value="Accept" />
        <option name="value" value="*/*" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="Cache-Control" />
        <option name="value" value="no-cache" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="Content-Type" />
        <option name="value" value="application/json" />
      </KeyValuePair>
    </list>
  </option>
  <option name="parameters">
    <list>
      <KeyValuePair>
        <option name="key" value="client_id" />
        <option name="value" value="c1" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="client_secret" />
        <option name="value" value="secret" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="username" />
        <option name="value" value="zhangsan" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="password" />
        <option name="value" value="123" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="grant_type" />
        <option name="value" value="password" />
      </KeyValuePair>
    </list>
  </option>
  <option name="parametersEnabled" value="true" />
  <option name="haveTextToSend" value="false" />
  <option name="haveFileToSend" value="false" />
  <option name="isFileUpload" value="false" />
  <option name="textToSend" value="" />
  <option name="filesToSend" value="" />
</RestClientRequest>
````

#### 4.4.2 携带token请求资源

````xml
<RestClientRequest>
  <option name="biscuits">
    <list />
  </option>
  <option name="httpMethod" value="GET" />
  <option name="urlBase" value="http://localhost:53021" />
  <option name="urlPath" value="r1" />
  <option name="headers">
    <list>
      <KeyValuePair>
        <option name="key" value="Accept" />
        <option name="value" value="*/*" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="Cache-Control" />
        <option name="value" value="no-cache" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="Authorization" />
        <option name="value" value="Bearer 7980c2c0-dacb-45d1-a778-274d94d5da72" />
      </KeyValuePair>
    </list>
  </option>
  <option name="parameters">
    <list />
  </option>
  <option name="parametersEnabled" value="true" />
  <option name="haveTextToSend" value="false" />
  <option name="haveFileToSend" value="false" />
  <option name="isFileUpload" value="false" />
  <option name="textToSend" value="" />
  <option name="filesToSend" value="" />
</RestClientRequest>
````

### 4.5 使用JWT验证

#### 4.5.1 authorization 项目修改

**TokenConfig **

````java
@Configuration
public class TokenConfig {
    private String SIGNING_KEY = "uaa123";
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(SIGNING_KEY); //对称秘钥，资源服务器使用该秘钥来验证
        return converter;
    }
}
````

***认证类***

````java
 	@Autowired
    private JwtAccessTokenConverter accessTokenConverter;
    @Bean
    public AuthorizationServerTokenServices tokenService() {
        DefaultTokenServices service=new DefaultTokenServices();
        service.setClientDetailsService(clientDetailsService);
        service.setSupportRefreshToken(true);
        service.setTokenStore(tokenStore);
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(accessTokenConverter));
        service.setTokenEnhancer(tokenEnhancerChain);
        service.setAccessTokenValiditySeconds(7200); // 令牌默认有效期2小时
        service.setRefreshTokenValiditySeconds(259200); // 刷新令牌默认有效期3天
        return service;
    }

````

#### 4.5.2测试

````xml
<RestClientRequest>
  <option name="biscuits">
    <list />
  </option>
  <option name="httpMethod" value="POST" />
  <option name="urlBase" value="http://localhost:53020" />
  <option name="urlPath" value="/oauth/token" />
  <option name="headers">
    <list>
      <KeyValuePair>
        <option name="key" value="Accept" />
        <option name="value" value="*/*" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="Cache-Control" />
        <option name="value" value="no-cache" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="Content-Type" />
        <option name="value" value="application/json" />
      </KeyValuePair>
    </list>
  </option>
  <option name="parameters">
    <list>
      <KeyValuePair>
        <option name="key" value="client_id" />
        <option name="value" value="c1" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="client_secret" />
        <option name="value" value="secret" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="username" />
        <option name="value" value="zhangsan" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="password" />
        <option name="value" value="123" />
      </KeyValuePair>
      <KeyValuePair>
        <option name="key" value="grant_type" />
        <option name="value" value="password" />
      </KeyValuePair>
    </list>
  </option>
  <option name="parametersEnabled" value="true" />
  <option name="haveTextToSend" value="false" />
  <option name="haveFileToSend" value="false" />
  <option name="isFileUpload" value="false" />
  <option name="textToSend" value="" />
  <option name="filesToSend" value="" />
</RestClientRequest>
````

***生成结果***

````json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsicmVzMSJdLCJ1c2VyX25hbWUiOiJ6aGFuZ3NhbiIsInNjb3BlIjpbImFsbCJdLCJleHAiOjE2MTY1NzU5ODAsImF1dGhvcml0aWVzIjpbInAxIiwicDMiXSwianRpIjoiZjA0NzlkNGItZjEwZC00OWRjLTg4ZDUtOWZjYzEzZTY1NGNhIiwiY2xpZW50X2lkIjoiYzEifQ.hjMs6RUXGaZAmAERzSwcTv3x197MyyJIDaMnHjsBv6A",
  "token_type": "bearer",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsicmVzMSJdLCJ1c2VyX25hbWUiOiJ6aGFuZ3NhbiIsInNjb3BlIjpbImFsbCJdLCJhdGkiOiJmMDQ3OWQ0Yi1mMTBkLTQ5ZGMtODhkNS05ZmNjMTNlNjU0Y2EiLCJleHAiOjE2MTY4Mjc5ODAsImF1dGhvcml0aWVzIjpbInAxIiwicDMiXSwianRpIjoiYmVmNjZjNmYtN2M5YS00N2RiLWI2NmItMmMzNTliODg4ZGZiIiwiY2xpZW50X2lkIjoiYzEifQ.Ks4oWVwZJ-v9gDZ6uCK4Robkhft6ZBJ0C8qE2CcZFtw",
  "expires_in": 7199,
  "scope": "all",
  "jti": "f0479d4b-f10d-49dc-88d5-9fcc13e654ca"
}
````

### 4.6 加入DB

#### 4.6.1 SQL语句

> oauth_client_details存储客户端信息

````sql
-- 创建表语句
DROP TABLE IF EXISTS `oauth_client_details`;

CREATE TABLE `oauth_client_details` (
	`client_id` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT '客户端标 识',
	`resource_ids` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '接入资源列表',
	`client_secret` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '客户端秘钥',
	`scope` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	`authorized_grant_types` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	`web_server_redirect_uri` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	`authorities` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	`access_token_validity` int(11) NULL DEFAULT NULL,
	`refresh_token_validity` int(11) NULL DEFAULT NULL,
	`additional_information` longtext CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
	`create_time` timestamp(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0),
	`archived` tinyint(4) NULL DEFAULT NULL,
	`trusted` tinyint(4) NULL DEFAULT NULL,
	`autoapprove` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	PRIMARY KEY USING BTREE (`client_id`)
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic COMMENT '接入客户端信息';

-- 插入语句
INSERT INTO `oauth_client_details`
VALUES ('c1', 'res1', '$2a$10$0J7SLKTpF/y1Lh.zbC5Goez1i56D53wnyB.VA7YVA7nPo3RbmMyx6', 'ROLE_ADMIN,ROLE_USER,ROLE_API', 'client_credentials,password,authorization_code,implicit,refresh_token'
	, 'http://www.baidu.com', NULL, 7200, 259200, NULL
	, str_to_date('2019-09-09 16:04:28','%Y-%m-%d %H:%i:%s'), 0, 0, 'false');

INSERT INTO `oauth_client_details`
VALUES ('c2', 'res2', '$2a$10$0J7SLKTpF/y1Lh.zbC5Goez1i56D53wnyB.VA7YVA7nPo3RbmMyx6', 'ROLE_API', 'client_credentials,password,authorization_code,implicit,refresh_token'
	, 'http://www.baidu.com', NULL, 31536000, 2592000, NULL
	, str_to_date('2019-09-09 21:48:51','%Y-%m-%d %H:%i:%s'), 0, 0, 'false');
````

> oauth_code表，Spring Security OAuth2使用，用来存储授权码：

````sql
DROP TABLE IF EXISTS `oauth_code`;

CREATE TABLE `oauth_code` (
	`create_time` timestamp(0) NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`code` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
	`authentication` blob NULL,
	INDEX `code_index` USING BTREE(`code`)
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Compact;
````

#### 4.6.2 authorization项目修改

> 将之前的认证类注解去掉,使之失效;配置下面的新配置类

````java
package com.maben.authorization.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.sql.DataSource;
import java.util.Arrays;

/**
 * 认证配置类
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerDB extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private TokenStore tokenStore;
    @Autowired
    private JwtAccessTokenConverter accessTokenConverter;
    @Autowired
    private ClientDetailsService clientDetailsService;
    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 1.客户端详情相关配置
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public ClientDetailsService clientDetailsService(DataSource dataSource) {
        ClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
        ((JdbcClientDetailsService)
                clientDetailsService).setPasswordEncoder(passwordEncoder());
        return clientDetailsService;
    }
    @Override
    public void configure(ClientDetailsServiceConfigurer clients)
            throws Exception {
        clients.withClientDetails(clientDetailsService);
    }
    /**
     * 2.配置令牌服务(token services)
     */
    @Bean
    public AuthorizationServerTokenServices tokenService() {
        DefaultTokenServices service=new DefaultTokenServices();
        service.setClientDetailsService(clientDetailsService);
        service.setSupportRefreshToken(true);//支持刷新令牌
        service.setTokenStore(tokenStore); //绑定tokenStore
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(accessTokenConverter));
        service.setTokenEnhancer(tokenEnhancerChain);
        service.setAccessTokenValiditySeconds(7200); // 令牌默认有效期2小时
        service.setRefreshTokenValiditySeconds(259200); // 刷新令牌默认有效期3天
        return service;
    }

    /**
     * 3.配置令牌（token）的访问端点
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices(DataSource dataSource) {
        return new JdbcAuthorizationCodeServices(dataSource);//设置授权码模式的授权码如何存取
    }
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(authenticationManager)
                .authorizationCodeServices(authorizationCodeServices)
                .tokenServices(tokenService())
                .allowedTokenEndpointRequestMethods(HttpMethod.POST);
    }

    /**
     * 4.配置令牌端点(Token Endpoint)的安全约束
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security){
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("permitAll()")
                .allowFormAuthenticationForClients()//允许表单认证
        ;
    }

}

````



#### 4.6.3 测试结果

> 使用idea的restful测试结果如下(测试密码格式的)

````json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsicmVzMSJdLCJ1c2VyX25hbWUiOiJ6aGFuZ3NhbiIsInNjb3BlIjpbIlJPTEVfQURNSU4iLCJST0xFX1VTRVIiLCJST0xFX0FQSSJdLCJleHAiOjE2MTY1ODAxNTYsImF1dGhvcml0aWVzIjpbInAxIiwicDMiXSwianRpIjoiZjgzMmQwODMtNWExOC00ZWI1LWJmYTMtZDE0OTM1OGIzZDk2IiwiY2xpZW50X2lkIjoiYzEifQ.l39-ui7U3SDjASfi1DsGSRHEjck-zaaZBmwnFtLS4Gw",
  "token_type": "bearer",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsicmVzMSJdLCJ1c2VyX25hbWUiOiJ6aGFuZ3NhbiIsInNjb3BlIjpbIlJPTEVfQURNSU4iLCJST0xFX1VTRVIiLCJST0xFX0FQSSJdLCJhdGkiOiJmODMyZDA4My01YTE4LTRlYjUtYmZhMy1kMTQ5MzU4YjNkOTYiLCJleHAiOjE2MTY4MzIxNTYsImF1dGhvcml0aWVzIjpbInAxIiwicDMiXSwianRpIjoiNDhiYmQ3MzAtYTFjNS00YjljLWFlY2QtMzczODZlNDdlMGNhIiwiY2xpZW50X2lkIjoiYzEifQ.2GAIMNW6ON5vsDF4ilZo1pNZHfbjMzAbhC_FwJRoxI8",
  "expires_in": 7199,
  "scope": "ROLE_ADMIN ROLE_USER ROLE_API",
  "jti": "f832d083-5a18-4eb5-bfa3-d149358b3d96"
}
````



