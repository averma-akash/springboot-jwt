package com.Springboot.jwt.example.vo;

public class MessageResponse {
	
	private String message;

	public MessageResponse(String string) {
		this.message = string;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

}
