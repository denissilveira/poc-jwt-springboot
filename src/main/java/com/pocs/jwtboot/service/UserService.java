package com.pocs.jwtboot.service;

import java.util.List;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.mobile.device.Device;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.pocs.jwtboot.model.resource.UserResource;
import com.pocs.jwtboot.model.resource.UserTokenStateResource;

public interface UserService extends UserDetailsService {
	
	UserTokenStateResource authenticate(final String username, final String password, final Device device) throws Exception;
	
	UserResource registration(final UserResource userModel) throws DuplicateKeyException, Exception;
	
	void autologin(final String username, final String password);
	
	void changePassword(final String oldPassword, final String newPassword);
	
	UserResource findByUsernameAndRoles(final String username, final List<String> roles);
	
	UserResource findById(final String id);
}