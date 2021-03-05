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
