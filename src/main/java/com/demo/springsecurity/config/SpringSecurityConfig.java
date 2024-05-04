package com.demo.springsecurity.config;

import com.demo.springsecurity.filter.JwtAuthenticationTokenFilter;
import com.demo.springsecurity.handler.AccessDeniedHandlerImpl;
import com.demo.springsecurity.handler.AuthenticationEntryPointImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 19:20
 * @Description:
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringSecurityConfig {
    @Autowired
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

    @Autowired
    private AuthenticationEntryPointImpl authenticationEntryPointImpl;

    @Autowired
    private AccessDeniedHandlerImpl accessDeniedHandlerImpl;

    /**
     * Security filter chain
     * @param http HttpSecurity instance
     * @return SecurityFilterChain instance
     * @throws Exception exception
     * @Description: SecurityConfig is the class used to configure security related beans.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 不通过session获取security context

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/users/login").permitAll()// permit /user/login request without authentication
                        .anyRequest().authenticated() )// any other request need to be authenticated

                .csrf(AbstractHttpConfigurer::disable) // disable csrf
                .httpBasic(Customizer.withDefaults())  // basic authentication

                // Add custom JWT filter before UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)

                // Add custom exception handling
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(authenticationEntryPointImpl)
                        .accessDeniedHandler(accessDeniedHandlerImpl));


        return http.build();
    }

    /**
     * Password encoder
     * @return BCryptPasswordEncoder instance.
     * @Description: Password encoder for password encryption and decryption.
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     *
     * @param http HttpSecurity instance
     * @return AuthenticationManager instance
     * @throws Exception exception
     * @Description: Authentication manager bean
     */
    @Bean
    public AuthenticationManager authenticationManagerBean(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class).build();
    }

//    @Bean
//    public JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter() {
//        return new JwtAuthenticationTokenFilter();
//    }


}

