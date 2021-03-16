package com.maben.securitySpringboot.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
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
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 配置用户信息服务
     * 因为添加了自定义的SpringDataUserDetailsService类,这里讲缓存读取的去掉
     * @return UserDetailsService
     */
//    @Bean
//    public UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        manager.createUser(User.withUsername("zhangsan").password("123").authorities("p1").build());
//        manager.createUser(User.withUsername("lisi").password("456").authorities("p2").build());
//        return manager;
//    }

    /**
     * 密码编码器
     *
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        //密码不需要任何操作,直接比对
//        return NoOpPasswordEncoder.getInstance();

        //使用BCrypt编码验证密码
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置安全拦截机制
     *
     * @param http http
     * @throws Exception ..
     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        非自定义登录页面
//        http
//                .authorizeRequests()
//                .antMatchers("/r/r1").hasAuthority("p1") //访问[/r/r1]资源需要权限[p1]
//                .antMatchers("/r/r2").hasAuthority("p2")//访问[/r/r2]资源需要权限[p2]
//                .antMatchers("/r/**").authenticated() //所有/r/**的请求必须认证通过
//                .anyRequest().permitAll() //除了/r/**，其它的请求可以访问
//                .and()
//                .formLogin()//允许表单登录
//                .successForwardUrl("/login-success"); //自定义登录成功的页面地址

//    }

    /**
     * 配置安全拦截机制
     *
     * @param http http
     * @throws Exception ..
     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
////        自定义登录页面
//        http.csrf().disable() //屏蔽CSRF控制，即spring security不再限制CSRF
//                .authorizeRequests()
//                .antMatchers("/r/**").authenticated() //所有/r/**的请求必须认证通过
//                .anyRequest().permitAll() //除了/r/**，其它的请求可以访问
//                .and()
//                .formLogin()//允许表单登录
//                .loginPage("/login-view") //指定我们自己开发的登录页面,spring security以重定向方式跳转到/login-view
//                .loginProcessingUrl("/login")//指定登录处理的URL，也就是用户名、密码表单提交的目的路径
//                .successForwardUrl("/login-success") //自定义登录成功的页面地址
//                .permitAll();
//    }


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

}