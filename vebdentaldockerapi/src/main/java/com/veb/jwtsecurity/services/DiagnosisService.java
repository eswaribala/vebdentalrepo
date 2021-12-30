package com.veb.jwtsecurity.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.veb.jwtsecurity.models.Diagnosis;
import com.veb.jwtsecurity.repositories.DiagnosisRepository;

@Service
public class DiagnosisService {
    @Autowired 
	private DiagnosisRepository diagnosisRepo;
	
    public Diagnosis addDiagnosis(Diagnosis diagnosis) {
       	
               return  this.diagnosisRepo.save(diagnosis);
    
       }
    public List<Diagnosis> getAllDiagnosis(){
    	return this.diagnosisRepo.findAll();
    }
}
