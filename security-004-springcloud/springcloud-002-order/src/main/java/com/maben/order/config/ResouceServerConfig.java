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