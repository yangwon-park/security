package io.security.basicsecurity;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((auth -> auth
                        .anyRequest().authenticated()))
                .formLogin((formLogin) ->
                        formLogin
//                                .loginPage("/loginPage")
                                .defaultSuccessUrl("/")
                                .failureUrl("/login")
                                .usernameParameter("userId")
                                .passwordParameter("passwd")
                                .loginProcessingUrl("/login_proc")
                                .successHandler((request, response, authentication) -> {
                                    System.out.println("authentication " + authentication.getName());
                                    response.sendRedirect("/");
                                })
                                .failureHandler((request, response, exception) -> {
                                    System.out.println("exception " + exception.getMessage());
                                    response.sendRedirect("/login");
                                })
                                .permitAll())
                .logout((logout) ->
                        logout
                                .logoutUrl("/logout")
                                .logoutSuccessUrl("/login")
                                .addLogoutHandler(((request, response, authentication) -> {
                                    HttpSession session = request.getSession();
                                    session.invalidate();
                                })).logoutSuccessHandler((request, response, authentication) -> {
                                    System.out.println("logout succeed");
                                    response.sendRedirect("/login");
                                })
                                .deleteCookies("remember-me"))

                .rememberMe((remember) -> {
                    remember
                            .rememberMeParameter("remember")
                            .tokenValiditySeconds(3600) // default: 14일
                            .alwaysRemember(false)
                            .userDetailsService(userDetailsService);
                })
                .sessionManagement((sm) -> {
                    sm
                            .sessionFixation().changeSessionId() // default
                            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // default: 필요 시 세션 생성 (JWT 쓰는 경우엔 Stateless 정책 사용)
//                            .maximumSessions(1)
//                            .maxSessionsPreventsLogin(false)    // true: 세션이 초과되면 아예 로그인 못 함
                    ;
                });

        return http.build();
    }
}
