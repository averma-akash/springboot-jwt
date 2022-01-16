package com.Springboot.jwt.example.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.Springboot.jwt.example.security.services.UserDetailsServiceImpl;

import io.jsonwebtoken.ExpiredJwtException;

/**
 * 
 * @author akash Verma
 *
 */

/*
 * What we do inside doFilterInternal(): – get JWT from the Authorization header
 * (by removing Bearer prefix) – if the request has JWT, validate it, parse
 * username from it – from username, get UserDetails to create an Authentication
 * object – set the current UserDetails in SecurityContext using
 * setAuthentication(authentication) method.
 * 
 * After this, everytime you want to get UserDetails, just use SecurityContext
 * like this:
 * 
 * UserDetails userDetails = (UserDetails)
 * SecurityContextHolder.getContext().getAuthentication().getPrincipal();
 * 
 * // userDetails.getUsername() // userDetails.getPassword() //
 * userDetails.getAuthorities()
 * 
 */

public class AuthenticationTokenFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private UserDetailsServiceImpl userDetailsService;

	private static final Logger logger = LoggerFactory.getLogger(AuthenticationTokenFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			var jwt = parseJwtToken(request);

			// Once we get the token validate it.
			if (StringUtils.hasText(jwt) && jwtUtils.validateJwtToken(jwt)) {

				String userName = jwtUtils.getUserNameFromJwtToken(jwt);

				UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
				// if token is valid configure Spring Security to manually set authentication
				UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());

				userAuthentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				// After setting the Authentication in the context, we specify
				// that the current user is authenticated. So it passes the Spring Security
				// Configurations successfully.
				SecurityContextHolder.getContext().setAuthentication(userAuthentication);
			}
		} catch (Exception e) {
			logger.error("Cannot set user authentication: {}", e);
		}
		filterChain.doFilter(request, response);

	}

	private String parseJwtToken(HttpServletRequest request) {

		String authenticationHeader = request.getHeader("Authorization");
		String username = null;
		String jwtToken = null;
		// JWT Token is in the form "Bearer token". Remove Bearer word and get only the
		// Token
		if (StringUtils.hasText(authenticationHeader) && authenticationHeader.contains("bearer ")) {
			jwtToken = authenticationHeader.substring(7);
			try {
				username = jwtTokenUtil.getUsernameFromToken(jwtToken);
			} catch (IllegalArgumentException e) {
				System.out.println("Unable to get JWT Token");
			} catch (ExpiredJwtException e) {
				System.out.println("JWT Token has expired");
			}
			return authenticationHeader.substring(7, authenticationHeader.length());
		} else {
			logger.warn("JWT Token does not begin with Bearer String");
		}
		return null;

	}

}
