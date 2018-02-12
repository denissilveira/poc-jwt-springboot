package com.pocs.jwtboot.service.impl;

import java.util.Collections;
import java.util.Date;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.mobile.device.Device;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.pocs.jwtboot.auth.TokenHelper;
import com.pocs.jwtboot.model.entity.User;
import com.pocs.jwtboot.model.enums.RolesEnum;
import com.pocs.jwtboot.repository.UserRepository;
import com.pocs.jwtboot.service.UserService;
import com.pocs.jwtboot.web.contract.UserResource;
import com.pocs.jwtboot.web.contract.UserTokenStateResource;

@Service("userService")
public class UserServiceImpl implements UserService {
	
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	@Autowired
    private UserDetailsService userDetailsService;
	@Autowired
    private AuthenticationManager authenticationManager;
	@Autowired
	private TokenHelper tokenHelper;
	@Autowired
    private ModelMapper modelMapper;
	
	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		return userRepository.findByUsername(email);
	}
	
	@Override
	public UserTokenStateResource authenticate(final String username, final String password, final Device device) throws Exception {
		
		try {
			final Authentication authentication = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(username, password));
			
			SecurityContextHolder.getContext().setAuthentication(authentication);
			final User user = (User) authentication.getPrincipal();
			final UserResource userResource = modelMapper.map(user, UserResource.class);
			final String jws = tokenHelper.generateToken(user.getUsername(), device);
			final int expiresIn = tokenHelper.getExpiredIn(device);
			return new UserTokenStateResource(jws, expiresIn, userResource);
		} catch (BadCredentialsException | InternalAuthenticationServiceException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		} catch (Exception e) {
			throw new Exception(e.getMessage());
		}
	}

	@Override
	public UserResource registration(final UserResource userModel) throws DuplicateKeyException, Exception {
		
		try {
			userModel.setActive(true);
			final Date now = new Date();
			userModel.setCreated(now);
			userModel.setLastPasswordResetDate(now);
			userModel.setRoles(Collections.singletonList(RolesEnum.USER.name()));
			userModel.setPassword(bCryptPasswordEncoder.encode(userModel.getPassword()));
			final User user = userRepository.save(modelMapper.map(userModel, User.class));
			
			if(user == null)
				throw new Exception("Erro ao cadastrar usuario");
			
			return modelMapper.map(user, UserResource.class);
		} catch(Exception e) {
			throw new Exception(e);
		}
	}

	@Override
    public void autologin(final String username, final String password) {
		
        final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = 
                new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
        authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        if (usernamePasswordAuthenticationToken.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }
    }
	
	@Override
	public void changePassword(String oldPassword, String newPassword) {

		final Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
		final String username = currentUser.getName();
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, oldPassword));

		final User user = (User) loadUserByUsername(username);
		user.setLastPasswordResetDate(new Date());
		user.setPassword(bCryptPasswordEncoder.encode(newPassword));
		userRepository.save(user);
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	public UserResource findById(final String id) {
		final User user = userRepository.findOne(id);
		if(user == null)
			return null;
		return modelMapper.map(user, UserResource.class);
	}
}