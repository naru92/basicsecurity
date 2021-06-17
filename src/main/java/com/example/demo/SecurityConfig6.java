package com.example.demo;




import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig6 extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		//메모리 방식으로 사용자 생성
		//암호는 프리픽스 형태로 써줘야함
		//패스워드는 유형이 있는데, 각각 알고리즘을 통해 저장하기 때문에, 알고리즘 방식을 적어줘야함
		//{noop}은 암호화 하지 않은 평문 그대로의 문자
		auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
		auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS","USER");
		auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
		//세명의 각각 다른 권한의 사용자 생성했음
	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				
				.authorizeRequests()
				.antMatchers("/login").permitAll()
				.antMatchers("/user").hasAnyRole("USER")
				.antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
				.antMatchers("/admin/pay").hasRole("ADMIN")
				.anyRequest().authenticated();
		http
				.formLogin()
				//밑의 예외처리후 DefaultSavedRequest에 저장된 원래 사용자의 요청페이지로 바로 이동시킴
				.successHandler(new AuthenticationSuccessHandler() {
					
					@Override
					public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
						Authentication authentication) throws IOException, ServletException {
						
							RequestCache requestCache = new HttpSessionRequestCache(); //RequestCache의 정보를 얻고 글로 보냄
							SavedRequest savedRequest = requestCache.getRequest(request, response);
							String redirectUrl = savedRequest.getRedirectUrl();
							response.sendRedirect(redirectUrl); //세션 정보에 저장된 요청으로 리다이렉트
							
					}
				});
		
		http
		 		.exceptionHandling()
		 		.authenticationEntryPoint(new AuthenticationEntryPoint() {
					
					@Override
					public void commence(HttpServletRequest request, HttpServletResponse response,
							AuthenticationException authException) throws IOException, ServletException {
						response.sendRedirect("/login");
					}
				})
		 		.accessDeniedHandler(new AccessDeniedHandler() {
					
					@Override
					public void handle(HttpServletRequest request, HttpServletResponse response,
							AccessDeniedException accessDeniedException) throws IOException, ServletException {
						response.sendRedirect("/denied");
					}
				});
		
	}
}