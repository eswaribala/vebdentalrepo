package com.veb.jwtsecurity.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.veb.jwtsecurity.models.Diagnosis;
import com.veb.jwtsecurity.models.Prescription;
import com.veb.jwtsecurity.repositories.DiagnosisRepository;
import com.veb.jwtsecurity.repositories.PrescriptionRepository;

@Service
public class PrescriptionService {
    @Autowired 
	private PrescriptionRepository prescriptionRepo;
	
    public Prescription addPrescription(Prescription prescription) {
       	
               return  this.prescriptionRepo.save(prescription);
    
       }
    public List<Prescription> getAllPrescription(){
    	return this.prescriptionRepo.findAll();
    }
}
