package com.veb.jwtsecurity.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.veb.jwtsecurity.models.Treatment;

public interface TreatmentRepository extends JpaRepository<Treatment, Long>{

}
