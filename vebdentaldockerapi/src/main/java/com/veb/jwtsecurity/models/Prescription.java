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
@Table(name="VS_Prescription")
@Data
public class Prescription {
	
	@Column(name="Patient_MobileNo")
	private long patientMobileNo;
	@Column(name="Doctor_MobileNo")
	private long doctorMobileNo;
    @Column(name="Appointment_No")
	private long appointmentNo;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="Medicine_Id")
	private long medicineId;
    @Column(name="Medicine_Name")
	private String medicineName;
    @Column(name="Dosage")
	private String dosage;
    @Column(name="Duration")
	private String duration;
    @Column(name="Frequency")
	private String frequency;
    @Column(name="Notes")
	private String notes;
    
   	
	
}
