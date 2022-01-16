package com.Springboot.jwt.example.dao;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Springboot.jwt.example.model.User;

@Repository
public interface UserDao extends JpaRepository<User, Long> {
	
	User findByUsername(String username);
	Boolean existsByUsername(String username);
	Boolean existsByEmail(String email);

}
