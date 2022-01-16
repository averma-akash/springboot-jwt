package com.Springboot.jwt.example.controller;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.Springboot.jwt.example.dao.RoleDao;
import com.Springboot.jwt.example.dao.UserDao;
import com.Springboot.jwt.example.model.ERole;
import com.Springboot.jwt.example.model.Role;
import com.Springboot.jwt.example.model.User;
import com.Springboot.jwt.example.security.jwt.JwtUtils;
import com.Springboot.jwt.example.security.services.UserDetailsImpl;
import com.Springboot.jwt.example.security.services.UserDetailsServiceImpl;
import com.Springboot.jwt.example.vo.JwtResponse;
import com.Springboot.jwt.example.vo.LoginRequest;
import com.Springboot.jwt.example.vo.MessageResponse;
import com.Springboot.jwt.example.vo.SignupRequest;

@CrossOrigin()
@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserDao userRepository;

	@Autowired
	RoleDao roleRepository;

	@Autowired
	PasswordEncoder encoder;
	
	@Autowired
	UserDetailsServiceImpl userDetailsService;

	@Autowired
	JwtUtils jwtUtils;
	
	private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

	@PostMapping("/login")
	public ResponseEntity<?> successfulLogin(@Valid @RequestBody LoginRequest login) {

		Authentication authenticate = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()));

		//SecurityContextHolder.getContext().setAuthentication(authenticate);
		
		final UserDetails userDetails = userDetailsService.loadUserByUsername(login.getUsername());

		final String generateJsonToken = jwtUtils.generateJsonToken(userDetails);
		
		//UserDetailsImpl userDetailsImpl = (UserDetailsImpl) authenticate.getPrincipal();

		List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
				.collect(Collectors.toList());

		JwtResponse jwtResponse = new JwtResponse(generateJsonToken, null, userDetails.getUsername(),
				"", roles);
		return ResponseEntity.ok(jwtResponse);

	}

	@PostMapping("/signup")
	public ResponseEntity<?> userSignup(@Valid @RequestBody SignupRequest signupInput) {
		
		logger.info("Inside Sign up");

		if (userRepository.existsByUsername(signupInput.getUsername())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error : User Already Exist"));
		}
		if (userRepository.existsByEmail(signupInput.getEmail())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
		}

		User user = new User();
		user.setUsername(signupInput.getUsername());
		user.setEmail(signupInput.getEmail());
		user.setPassword(encoder.encode(signupInput.getPassword()));

		Set<String> userRoles = signupInput.getRole();
		Set<Role> roles = new HashSet<>();

		if (userRoles.isEmpty()) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error : Role Not Found!"));
			roles.add(userRole);
		} else {
			userRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);

					break;
				case "mod":
					Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(modRole);

					break;
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));

	}

}
