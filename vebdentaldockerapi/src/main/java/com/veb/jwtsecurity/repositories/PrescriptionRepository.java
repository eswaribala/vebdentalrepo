package com.veb.jwtsecurity.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.veb.jwtsecurity.models.Prescription;

public interface PrescriptionRepository extends JpaRepository<Prescription,Long> {

}
