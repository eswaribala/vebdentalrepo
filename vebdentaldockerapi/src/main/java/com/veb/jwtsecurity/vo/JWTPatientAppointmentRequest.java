package com.veb.jwtsecurity.vo;

import java.util.List;

import com.veb.jwtsecurity.models.Appointment;
import com.veb.jwtsecurity.models.PatientAppointment;

import lombok.Data;
@Data
public class JWTPatientAppointmentRequest {

	private long doctorMobileNo;
	private long patientMobileNo;
	private String doa;
	private String treatment;
	private String chair;
	
}
