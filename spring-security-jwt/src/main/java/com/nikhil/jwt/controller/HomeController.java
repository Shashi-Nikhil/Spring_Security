package com.nikhil.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.nikhil.jwt.entity.JwtRequest;
import com.nikhil.jwt.entity.JwtResponse;
import com.nikhil.jwt.service.CustomUserDetailsService;
import com.nikhil.jwt.util.JwtUtil;

@RestController
public class HomeController {
	
	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private CustomUserDetailsService userService;

	@GetMapping("/")
	public String hello() {
		return "Spring Security using Jwt";
	}
	
	@PostMapping("/authenticate")
	public JwtResponse authenticate(@RequestBody JwtRequest jwtRequest) throws Exception {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jwtRequest.getUsername(), jwtRequest.getPassword()));
		}catch (BadCredentialsException e) {
			throw new Exception("Invalid Credentials ",e);
		}
		
		UserDetails userDetails = userService.loadUserByUsername(jwtRequest.getUsername());
		
		String token = jwtUtil.generateToken(userDetails);
		
		return new JwtResponse(token);
	}
}
