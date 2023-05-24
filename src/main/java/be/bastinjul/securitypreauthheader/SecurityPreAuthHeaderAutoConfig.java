package be.bastinjul.securitypreauthheader;

import be.bastinjul.securitypreauthheader.filters.HeaderPreAuthFilter;
import be.bastinjul.securitypreauthheader.filters.HeaderPresenceFilter;
import be.bastinjul.securitypreauthheader.properties.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity(debug = true)
@EnableMethodSecurity(securedEnabled = true)
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityPreAuthHeaderAutoConfig {

    @Bean
    public RequestMatcher shouldFilterRequestMatcher(SecurityProperties securityProperties) {
        if(securityProperties.filterPathPatterns() != null && securityProperties.filterPathPatterns().size() > 0) {
            return new OrRequestMatcher(securityProperties.filterPathPatterns()
                    .stream()
                    .map(AntPathRequestMatcher::new)
                    .toList().toArray(new AntPathRequestMatcher[0]));
        }
        return new AntPathRequestMatcher("/**");
    }

    @Bean
    public RequestMatcher shouldNotFilterRequestMatcher(SecurityProperties securityProperties) {
        if(securityProperties.noFilterPathPatterns() != null && securityProperties.noFilterPathPatterns().size() > 0) {
            return new OrRequestMatcher(securityProperties.noFilterPathPatterns()
                    .stream()
                    .map(noFilterProperties -> {
                        if(noFilterProperties.httpMethod() != null) {
                            return new AntPathRequestMatcher(noFilterProperties.pathPattern(), noFilterProperties.httpMethod().name());
                        }
                        return new AntPathRequestMatcher(noFilterProperties.pathPattern());
                    })
                    .toList().toArray(new AntPathRequestMatcher[0]));
        }
        return new AntPathRequestMatcher("/**");
    }

    @Bean
    public SecurityFilterChain shouldNotFilterChain(HttpSecurity httpSecurity,
                                                    RequestMatcher shouldNotFilterRequestMatcher) throws Exception {
        return httpSecurity
                .securityMatcher(shouldNotFilterRequestMatcher)
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request ->
                        request.requestMatchers(shouldNotFilterRequestMatcher).permitAll())
                .build();
    }

    @Bean
    public AuthenticationManager preAuthManager(HttpSecurity httpSecurity, PreAuthenticatedAuthenticationProvider preAuthProvider) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(preAuthProvider);
        return authenticationManagerBuilder.build();
    }

    @Bean
    public PreAuthenticatedAuthenticationProvider preAuthProvider() {
        PreAuthenticatedGrantedAuthoritiesUserDetailsService authenticationUserDetailsService = new PreAuthenticatedGrantedAuthoritiesUserDetailsService();
        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        provider.setPreAuthenticatedUserDetailsService(authenticationUserDetailsService);
        return provider;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity,
                                                   RequestMatcher shouldFilterRequestMatcher,
                                                   AuthenticationManager preAuthManager,
                                                   PreAuthenticatedAuthenticationProvider preAuthProvider) throws Exception {
        return httpSecurity
                .securityMatchers(matchers -> matchers.requestMatchers(shouldFilterRequestMatcher))
                .authenticationManager(preAuthManager)
                .authenticationProvider(preAuthProvider)
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .addFilterBefore(new HeaderPresenceFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new HeaderPreAuthFilter(preAuthManager), HeaderPresenceFilter.class)
                .authorizeHttpRequests(request ->
                    request
                            .requestMatchers(shouldFilterRequestMatcher)
                            .denyAll())
                .build();
    }
}
