package com.nikhil.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nikhil.jwt.entity.User;

public interface UserRepository extends JpaRepository<User, Integer>{

	User findByUsername(String username);

}
