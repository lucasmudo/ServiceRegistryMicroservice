package com.ead.service_registry.configs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfig {

    @Value("${ead.serviceRegistry.username}")
    private String username;

    @Value("${ead.serviceRegistry.password}")
    private String password;


//  VERSÃO ATUALIAZDA
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Desativa CSRF, caso necessário
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated() // Qualquer requisição precisa estar autenticada
                )
                .httpBasic(Customizer.withDefaults()) // Configuração básica de autenticação HTTP
                .formLogin(Customizer.withDefaults()); // Configuração padrão para form login

        return http.build();
    }

//    VERSÃO DEPRECIADA
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .httpBasic()
//                .and()
//                .authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .csrf().disable()
//                .formLogin();
//        return http.build();
//    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withUsername(username)
                .password(passwordEncoder().encode(password))
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
