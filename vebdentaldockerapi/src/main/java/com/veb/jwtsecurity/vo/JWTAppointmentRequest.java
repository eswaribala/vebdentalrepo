package com.veb.jwtsecurity.vo;

import java.util.List;

import com.veb.jwtsecurity.models.Appointment;

import lombok.Data;
@Data
public class JWTAppointmentRequest {

	private long mobileNo;
	private List<Appointment> appointments;
}
