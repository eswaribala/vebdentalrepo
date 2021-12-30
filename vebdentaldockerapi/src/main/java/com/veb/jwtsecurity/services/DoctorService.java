package com.veb.jwtsecurity.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.veb.jwtsecurity.models.Doctor;
import com.veb.jwtsecurity.models.Patient;
import com.veb.jwtsecurity.repositories.DoctorRepository;
import com.veb.jwtsecurity.repositories.PatientRepository;


@Service
public class DoctorService {
    @Autowired
	private DoctorRepository doctorRepository;
	

	public Doctor saveDoctor(Doctor doctor)
	{
		
		return this.doctorRepository.save(doctor);
		
	}
	
	public List<Doctor> getAllDoctors()
	{
		return this.doctorRepository.findAll();
		
	}
	
	public Doctor getDoctorByMobileNo(long mobileNo)
	{
		return this.doctorRepository.findById(mobileNo).orElse(null);
	}
	
	
	
}
