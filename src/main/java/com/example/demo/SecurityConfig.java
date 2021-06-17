//package com.example.demo;
//
//import java.io.IOException;
//
//import javax.servlet.ServletException;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import javax.servlet.http.HttpSession;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Configuration;
//
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.web.authentication.AuthenticationFailureHandler;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.security.web.authentication.logout.LogoutHandler;
//import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
//
//@Configuration
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
//	
//	@Autowired
//	UserDetailsService userDetailService;
//	
//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
////		//인가 정책
////		http.
////				authorizeRequests()
////			   .anyRequest()
////			   .authenticated();
////				//요약 : 사용자의 어떤 요청에도 인증을 받지 않으면 접근을 할수 없다
////		
////		//인증 정책
////		http.
////		       formLogin()
////		       .loginPage("/loginPage") //로그인을 할수 있게 해주는 페이지, 누구나 접근 할수 있어야함
////			   .defaultSuccessUrl("/")
////			   .failureUrl("/login")
////			   .usernameParameter("userId")
////			   .passwordParameter("passwd")
////			   .loginProcessingUrl("/loing_proc")
////			   .successHandler(new AuthenticationSuccessHandler() {
////				
////				@Override
////				public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
////						Authentication authentication) throws IOException, ServletException {
////					System.out.println("authentication " + authentication.getName());
////					response.sendRedirect("/");
////				}
////			})
////			  .failureHandler(new AuthenticationFailureHandler() {
////				
////				@Override
////				public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
////						AuthenticationException exception) throws IOException, ServletException {
////					System.out.println("exception " + exception.getMessage());
////					response.sendRedirect("/login");
////				}
////			})
////			.permitAll() //누구나 허가함(로그인 인증을 거쳐야기 때문에 허가를 열어둠
////		;
//		
//		http
//				.authorizeRequests()
//				.anyRequest() .authenticated();
//		http 
//		  		.formLogin();
//		
//		http
//		//로그아웃은 원칙적으로 포스트 방식으로 처리
//				.logout()
//				.logoutUrl("/logout")
//				.logoutSuccessUrl("/login")
//				.addLogoutHandler(new LogoutHandler() {
//					
//					@Override
//					public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//						HttpSession session = request.getSession();
//						session.invalidate();
//					}
//				})
//				.logoutSuccessHandler(new LogoutSuccessHandler() {
//					
//					@Override
//					public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
//							throws IOException, ServletException {
//						response.sendRedirect("/login");
//					}
//				}).and()
//				.rememberMe()
//				.rememberMeParameter("remember")
//				.tokenValiditySeconds(3600)
//				.userDetailsService(userDetailService);
//		
//				
//		
//	}
//}
