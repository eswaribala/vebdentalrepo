package com.veb.jwtsecurity.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.veb.jwtsecurity.models.Patient;
import com.veb.jwtsecurity.repositories.PatientRepository;


@Service
public class PatientService {
    @Autowired
	private PatientRepository patientRepository;
	

	public Patient savePatient(Patient patient)
	{
		
		return this.patientRepository.save(patient);
		
	}
	
	public List<Patient> getAllPatients()
	{
		return this.patientRepository.findAll();
		
	}
	
	public Patient getPatientByMobileNo(long mobileNo)
	{
		return this.patientRepository.findById(mobileNo).orElse(null);
	}
	
	
	
}
