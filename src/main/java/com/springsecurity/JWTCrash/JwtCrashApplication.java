package com.springsecurity.JWTCrash;

import com.springsecurity.JWTCrash.models.ApplicationUser;
import com.springsecurity.JWTCrash.models.Role;
import com.springsecurity.JWTCrash.repository.RoleRepository;
import com.springsecurity.JWTCrash.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
public class JwtCrashApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtCrashApplication.class, args);
	}

	@Bean
	CommandLineRunner run(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder){
		return args -> {
			if (roleRepository.findByAuthority("ADMIN").isPresent()){
				return;
			}
			Role adminRole = roleRepository.save(new Role("ADMIN"));
			Role userRole = roleRepository.save(new Role("USER"));
			Set<Role> roles = new HashSet<>();
			roles.add(adminRole);

			ApplicationUser admin = new ApplicationUser();
			admin.setUsername("admin");
			admin.setPassword(passwordEncoder.encode("admin"));
			admin.setAuthorities(roles);

			userRepository.save(admin);
		};
	}

}
