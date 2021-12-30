package com.veb.jwtsecurity.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.veb.jwtsecurity.models.Diagnosis;
import com.veb.jwtsecurity.models.Treatment;
import com.veb.jwtsecurity.repositories.DiagnosisRepository;
import com.veb.jwtsecurity.repositories.TreatmentRepository;

@Service
public class TreatmentService {
    @Autowired 
	private TreatmentRepository treatmentRepo;
	
    public Treatment addTreatment(Treatment treatment) {
       	
               return  this.treatmentRepo.save(treatment);
    
       }
    public List<Treatment> getAllTreatments(){
    	return this.treatmentRepo.findAll();
    }
}
