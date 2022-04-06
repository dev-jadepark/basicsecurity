package io.security.basicsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity  //여러 클래스들을 import해서 실행시키는 어노테이션, 웹보안 활성화 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {  //configure 메서드를 오버라이딩 한다.
        http
                .authorizeRequests()
                .anyRequest().authenticated(); //어떠한 요청에도 인증을 받도록 설정
        http
                .formLogin()
                //.loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")  //로그인핸들러
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : "+exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll();

        http
                .logout()
                .logoutUrl("/logout")   //시큐리티는 로그아웃할때 원칙적으로 POST방식으로 처리한다.
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me");   //서버에서 만든 쿠키를 삭제하고 싶을때 사용

        http
                .rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)     //1시간
                .userDetailsService(userDetailsService);

        http
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false);
        //This session has been expired (possibly due to multiple concurrent logins being attempted as the same user).

        http
                .sessionManagement()
                .sessionFixation().changeSessionId();   //none으로 하면 쿠키공격받을때 치명적이다 -> (세션고정공격), changeSessionId가 기본값

        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);

        /*
        Always          스프링 시큐리티가 항상 세션 생성
        If_Required     필요시 생성(기본값)
        Never           생성하지는 않지만 이미 존재하면 사용
        Stateless       생성하지않고 존재해도 사용하지 않음 -> JWT인증방식의 경우 사용한다.
         */

        /*
        http.formLogin()    //Form 로그인 인증 기능이 작동함
                .loginPage("/login.html")               //사용자 정의 로그인페이지
                .defaultSuccessUrl("/home")             //로그인 성공 후 이동페이지
                .failureUrl("/login.html?error=true")   //로그인 실패 후 이동페이지
                .usernameParameter("username")          //아이디 파라미터명 설정
                .passwordParameter("password")          //패스워드 파라미터명 설정
                .loginProcessingUrl("/login")           //로그인 Form Action Url
                .successHandler(loginSuccessHandler())  //로그인 성공 후 핸들러
                .failureHandler(lginFailureHandler())   //로그인 실패 후 핸들러

         */

        /*
        http.logout()                                           //로그아웃처리
                .logoutUrl("/logout")                           //로그아웃 처리 URL
                .logoutSuccessUrl("/login")                     //로그아웃 성공 후 이동페이지
                .deleteCookies("JSESSIONID", "remember-me")     //로그아웃 후 쿠키 삭제, 로그아웃될 때 삭제될 쿠키명을 명시
                .addLogoutHandler(logoutHadler())               //로그아웃 핸들러, 사용자정의 핸들러를 적용할때 인터페이스로 구현한다.
                .logoutSuccessHandler(logoutSuccessHandler())   //로그아웃 성공 후 핸들러
         */

        /*
        http.rememberMe()                                       //rememberMe기능이 작동함
                .rememberMeParameter("remember")                //기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600)                     //default는 14일
                .alwaysRemember(true)                           //rememberMe기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService())

         */

        /*
        http.sessionManagement()    //세션관리기능이 작동
                .maximumSessions(1) //최대 허용 가능 세션수, -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(true) //동시 로그인차단, false인 경우 기존 세션 만료(default)
                .expiredUrl("/expired") //세션만료경우 이동할 페이지
                ;

        http
                .sessionManagement()
                .sessionFixation().changeSessionId(); //서블릿3.1이상인경우, 이하인경우는 migrateSession

         */
    }
}
