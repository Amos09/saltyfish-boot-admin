package com.saltyfish.admin.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.UUID;

/**
 * @author: 番薯(Amos)
 * @dateTime: 10:14/06:04:2023
 * @version: v1.0
 * @description:
 */
@Configuration
public class AdminServerSecurityConfig extends WebSecurityConfigurerAdapter {
    
    private final AdminServerProperties adminServer;
    
    /**
     * Instantiates a new Security secure config.
     *
     * @param adminServer the admin server
     */
    public AdminServerSecurityConfig(AdminServerProperties adminServer) {
        this.adminServer = adminServer;
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setTargetUrlParameter("redirectTo");
        final String adminServerContextPath = adminServer.getContextPath();
        successHandler.setDefaultTargetUrl(adminServerContextPath + "/");
        
        http.authorizeRequests()
                .antMatchers(adminServerContextPath + "/assets/**").permitAll()
                .antMatchers(adminServerContextPath + "/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage(adminServerContextPath + "/login").successHandler(successHandler).and()
                .logout().logoutUrl(adminServerContextPath + "/logout").and()
                .httpBasic().and()
                .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers(
                        new AntPathRequestMatcher(adminServerContextPath + "/instances", HttpMethod.POST.toString()),
                        new AntPathRequestMatcher(adminServerContextPath + "/instances/*", HttpMethod.DELETE.toString()),
                        new AntPathRequestMatcher(adminServerContextPath + "/actuator/**")
                )
                .and()
                .rememberMe().key(UUID.randomUUID().toString()).tokenValiditySeconds(1209600);
        
    }
}
