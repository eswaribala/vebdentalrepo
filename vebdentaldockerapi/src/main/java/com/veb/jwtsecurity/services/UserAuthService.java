package com.veb.jwtsecurity.services;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.veb.jwtsecurity.models.Role;
import com.veb.jwtsecurity.models.User;
import com.veb.jwtsecurity.vo.UserVo;



@Service
public class UserAuthService {

	@Autowired
	private UserService userService;

	
	
	public User loadUserByUsername(String username) {
		return userService.getUserByName(username);
		
	}

	public User getUserByUsername(String username) {
		User user= userService.getUserByName(username);

		if (user != null) {

			return user;
		}

		return null;
	}

	
}
