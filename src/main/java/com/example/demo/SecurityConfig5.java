//package com.example.demo;
//
//
//
//
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig5 extends WebSecurityConfigurerAdapter {
//	
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		
//		//메모리 방식으로 사용자 생성
//		//암호는 프리픽스 형태로 써줘야함
//		//패스워드는 유형이 있는데, 각각 알고리즘을 통해 저장하기 때문에, 알고리즘 방식을 적어줘야함
//		//{noop}은 암호화 하지 않은 평문 그대로의 문자
//		auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
//		auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS","USER");
//		auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
//		//세명의 각각 다른 권한의 사용자 생성했음
//	}
//	
//	
//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http
//				
//				.authorizeRequests()
//				.antMatchers("/user").hasAnyRole("USER")
//				.antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
//				.antMatchers("/admin/pay").hasRole("ADMIN")
//				.anyRequest().authenticated();
//		http
//				.formLogin();
//		
//	}
//}