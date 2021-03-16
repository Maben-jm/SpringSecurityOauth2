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
@PreAuthorize("hasAuthority('p2') or hasAuthority('p3')")//拥有p2权限才可以访问
public String r2(){
    return getUsername()+" 访问资源2";
}
````

