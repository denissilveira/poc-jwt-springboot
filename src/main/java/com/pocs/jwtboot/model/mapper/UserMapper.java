package com.pocs.jwtboot.model.mapper;

import com.pocs.jwtboot.model.entity.User;
import com.pocs.jwtboot.model.resource.UserResource;

public class UserMapper {
	
	public static final UserResource parse(final User user) {
		
		if(user == null)
			return null;
		
		final UserResource userResource = new UserResource();
		userResource.setId(user.getId());
		userResource.setPhoto(user.getPhoto());
		userResource.setRoles(user.getRoles());
		userResource.setUsername(user.getUsername());
		userResource.setName(user.getName());
		return userResource;
	}
	
	public static final User parse(final UserResource userResource) {
		
		if(userResource == null)
			return null;
		
		final User user = new User();
		user.setActive(userResource.isActive());
		user.setCreated(userResource.getCreated());
		user.setId(userResource.getId());
		user.setPassword(userResource.getPassword());
		user.setPhoto(userResource.getPhoto());
		user.setRoles(userResource.getRoles());
		user.setUsername(userResource.getUsername());
		user.setName(userResource.getName());
		user.setLastPasswordResetDate(userResource.getLastPasswordResetDate());
		return user;
	}

}