package com.pocs.jwtboot.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.pocs.jwtboot.model.entity.User;

@Repository
public interface UserRepository extends MongoRepository<User, String>{

	User findByUsernameAndPassword(final String username, final String password);
	
	User findByUsername(final String username);
	
	User findByUsernameAndRoles(final String username, final List<String> roles);
}