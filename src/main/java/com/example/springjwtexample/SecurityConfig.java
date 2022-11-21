package com.example.springjwtexample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserService userService;

    @Autowired
    public SecurityConfig(UserService userService) {
        this.userService = userService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JWTLoginFilter(authenticationManager()))
                .addFilterAfter(new JWTVerifyFilter(userService), JWTLoginFilter.class)
                .authorizeRequests()
                .antMatchers("/info")
                .authenticated()
                .antMatchers("/**")
                .permitAll();
    }

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http)
//            throws Exception
//    {
//        return http
//                .csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .addFilter(new JWTLoginFilter())
//                .addFilterAfter(new JWTVerifyFilter(), JWTLoginFilter.class)
//                .authorizeRequests()
//                .antMatchers("/info")
//                .authenticated()
//                .antMatchers("/**")
//                .permitAll()
//                .and()
//                .build();
//    }

}
