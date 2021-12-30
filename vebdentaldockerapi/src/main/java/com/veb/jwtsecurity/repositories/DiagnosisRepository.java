package com.veb.jwtsecurity.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.veb.jwtsecurity.models.Diagnosis;

public interface DiagnosisRepository  extends JpaRepository<Diagnosis,Long>{

}
