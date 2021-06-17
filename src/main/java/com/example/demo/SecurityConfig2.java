//package com.example.demo;
//
//
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Configuration;
//
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.core.userdetails.UserDetailsService;
//
//@Configuration
//public class SecurityConfig2 extends WebSecurityConfigurerAdapter {
//	
//	@Autowired
//	UserDetailsService userDetailService;
//	
//	
//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http
//				.authorizeRequests()
//				.anyRequest().authenticated();
//		http
//				.formLogin();
//		http
//				.rememberMe()
//				.userDetailsService(userDetailService);
//	}
//}
