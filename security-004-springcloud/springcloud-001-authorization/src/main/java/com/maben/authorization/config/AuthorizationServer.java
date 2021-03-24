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
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Arrays;

/**
 * 认证配置类
 */
//@Configuration
//@EnableAuthorizationServer
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
//    @Bean
//    public AuthorizationServerTokenServices tokenService() {
//        DefaultTokenServices service=new DefaultTokenServices();
//        service.setClientDetailsService(clientDetailsService);
//        service.setSupportRefreshToken(true);
//        service.setTokenStore(tokenStore);
//         令牌默认有效期2小时
//        service.setAccessTokenValiditySeconds(7200);
//         刷新令牌默认有效期3天
//        service.setRefreshTokenValiditySeconds(259200);
//        return service;
//    }
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