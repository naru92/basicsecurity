//package com.example.demo;
//
//
//
//
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig4 extends WebSecurityConfigurerAdapter {
//	
//	
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
//			 .sessionManagement()
//			 .sessionFixation().none() // 무방비 상태
//			 ;
//	}
//}