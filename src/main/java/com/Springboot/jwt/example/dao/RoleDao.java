package com.Springboot.jwt.example.dao;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Springboot.jwt.example.model.ERole;
import com.Springboot.jwt.example.model.Role;

@Repository
public interface RoleDao extends JpaRepository<Role, Long> {
	Optional<Role> findByName(ERole name);
}
