package com.pocs.jwtboot.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.pocs.jwtboot.auth.RestAuthenticationEntryPoint;
import com.pocs.jwtboot.auth.TokenAuthenticationFilter;
import com.pocs.jwtboot.auth.TokenHelper;
import com.pocs.jwtboot.service.UserService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService jwtUserDetailsService;
    @Autowired
    private RestAuthenticationEntryPoint restAuthenticationEntryPoint;
    @Autowired
    TokenHelper tokenHelper;
    @Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Autowired
    public void configureGlobal( AuthenticationManagerBuilder auth ) throws Exception {
        auth.userDetailsService( jwtUserDetailsService ).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        List<RequestMatcher> csrfMethods = new ArrayList<>();
        Arrays.asList("POST", "PUT", "PATCH", "DELETE").forEach( method -> csrfMethods.add( new AntPathRequestMatcher( "/**", method ) ) );
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy( SessionCreationPolicy.STATELESS ).and()
                .exceptionHandling().authenticationEntryPoint( restAuthenticationEntryPoint ).and()
                .authorizeRequests()
                .antMatchers("/**/auth/**", "**/register/**", "/swagger-ui.html", "/swagger-resources/**", 
                		"/swagger-resources", "/v2/api-docs", "/v2/swagger-ui.html", "/webjars/**").permitAll()
                .anyRequest().authenticated().and()
                .addFilterBefore(new TokenAuthenticationFilter(tokenHelper, jwtUserDetailsService), BasicAuthenticationFilter.class);
    }


    @Override
    public void configure(WebSecurity web) throws Exception {

    	web.ignoring().antMatchers(HttpMethod.POST, "/**/auth/login", 
    			"/**/auth/register", "/**/partners/register", "/**/startups/register");
        web.ignoring().antMatchers(HttpMethod.GET, "/", "/swagger-ui.html", "/swagger-resources/**", 
        		"/swagger-resources", "/v2/api-docs", "/v2/swagger-ui.html", "/webjars/**");
    }
    
    @Bean
	public BCryptPasswordEncoder passwordEncoder() {
		BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
		return bCryptPasswordEncoder;
	}
}
