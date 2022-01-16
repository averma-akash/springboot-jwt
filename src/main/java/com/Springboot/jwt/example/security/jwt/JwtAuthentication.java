package com.Springboot.jwt.example.security.jwt;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

/** 
 * we create JwtAuthentication class that implements AuthenticationEntryPoint interface. 
 * Then we override the commence() method. This method will be triggered any time unauthenticated User
 *  requests a secured HTTP resource and an AuthenticationException is thrown. 
 *  
**/
@Component
public class JwtAuthentication implements AuthenticationEntryPoint, Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -1238417754227658684L;
	private static final Logger logger = LoggerFactory.getLogger(JwtAuthentication.class);

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {

		logger.error("Unauthorized error: {}", authException.getMessage());
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
		
	}
	/** HttpServletResponse.SC_UNAUTHORIZED is the 401 Status code. It indicates that the request requires HTTP authentication. */

}
