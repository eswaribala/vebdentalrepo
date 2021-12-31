package com.veb.jwtsecurity.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Service;

import com.veb.jwtsecurity.models.Role;
import com.veb.jwtsecurity.models.User;
import com.veb.jwtsecurity.repositories.UserRepository;

@Service
public class UserService {
    @Autowired
	private UserRepository userRepository;


	public User saveUser(User user)
	{
		System.out.println(user.getPassword());
		user.setPassword(user.getPassword());
		return this.userRepository.save(user);
		
	}
	
	public List<User> getUsers()
	{
		return this.userRepository.findAll();
		
	}
	
	public User getUserByName(String userName)
	{
		return this.userRepository.findById(userName).orElse(null);
	}
	
	public List<Role> getRoles(String userName)
	{
		User user =this.userRepository.findById(userName).orElse(null);
		if(user!=null)
			return user.getRoles();
		else
			return null;
	}
	
}
