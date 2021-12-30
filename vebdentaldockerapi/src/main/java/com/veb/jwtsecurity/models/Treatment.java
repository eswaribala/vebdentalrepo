package com.veb.jwtsecurity.models;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;

@Entity
@Table(name="VS_Treatment")
@Data
public class Treatment {
	@Column(name="Patient_MobileNo")
	private long patientMobileNo;
	@Column(name="Doctor_MobileNo")
	private long doctorMobileNo;   
    @Column(name="Appointment_No")
	private long appointmentNo;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="Tratment_Id")
	private long treatmentId;
    @Column(name="Tratment_Cost")
	private long treatmentCost;
    @Column(name="Tratment_Type")
	private String treatmentType;
    @Column(name="Discount")
	private long discount;
    @Column(name="Total_Amount")
	private long totalAmount;
    
      	
}
