package com.ssh.greenthumb.config;

import com.ssh.greenthumb.auth.domain.Role;
import com.ssh.greenthumb.auth.exception.RestAuthenticationEntryPoint;
import com.ssh.greenthumb.auth.filter.TokenAuthenticationFilter;
import com.ssh.greenthumb.auth.handler.OAuth2AuthenticationFailureHandler;
import com.ssh.greenthumb.auth.handler.OAuth2AuthenticationSuccessHandler;
import com.ssh.greenthumb.auth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.ssh.greenthumb.auth.service.CustomOAuth2UserService;
import com.ssh.greenthumb.auth.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsService customUserDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler successHandler;
    private final OAuth2AuthenticationFailureHandler failureHandler;
    private final OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestBasedOnCookieDao;

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**", "/js/**", "/img/**", "/lib/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()
            .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .exceptionHandling()
                .authenticationEntryPoint(new RestAuthenticationEntryPoint())
            .and()
                .authorizeRequests()
                .antMatchers("/", "/error", "**/favicon.ico").permitAll()
                .antMatchers("/auth/**", "/oauth2/**").permitAll()
                .antMatchers("/follow-user/**", "/plants", "/plant-name/**", "/posts/**", "**/comments", "/plant-hospital").permitAll()
                .antMatchers(HttpMethod.GET, "/post/{id}").permitAll()
                .antMatchers(HttpMethod.GET, "/user/{id}/feed").permitAll()
                .antMatchers("/v3/api-docs/**", "/swagger-resources/**", "/swagger-ui/**").permitAll()   // OAS_30
                .antMatchers("/post/**", "/comment/**").hasAnyRole(Role.USER.name(), Role.ADMIN.name())
                .antMatchers("/admin/**").hasRole(Role.ADMIN.name())
                .anyRequest().authenticated()
            .and()
                .oauth2Login()
                .authorizationEndpoint()
                .baseUri("/oauth2/authorization")
                .authorizationRequestRepository(authorizationRequestBasedOnCookieDao)
            .and()
                .redirectionEndpoint()
                .baseUri("/*/oauth2/code/*")
            .and()
                .userInfoEndpoint()
                .userService(customOAuth2UserService)
                .and()
                .successHandler(successHandler)
                .failureHandler(failureHandler);
        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}