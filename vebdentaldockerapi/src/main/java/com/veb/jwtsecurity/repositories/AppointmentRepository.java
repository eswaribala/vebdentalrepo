package com.veb.jwtsecurity.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.veb.jwtsecurity.models.Appointment;


public interface AppointmentRepository extends JpaRepository<Appointment,Long>{

	@Query("select a from Appointment a where a.doctor.mobileNo =:mobileNo")
	List<Appointment> findAppointmentsByMobileNo(@Param("mobileNo") long mobileNo);
}
