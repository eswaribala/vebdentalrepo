package com.veb.jwtsecurity.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.veb.jwtsecurity.models.Appointment;
import com.veb.jwtsecurity.models.PatientAppointment;


public interface PatientAppointmentRepository extends JpaRepository<PatientAppointment,Long>{

	@Query("select a from PatientAppointment a where a.patient.mobileNo =:mobileNo")
	List<PatientAppointment> findPatientAppointmentsByMobileNo(@Param("mobileNo") long mobileNo);
}
