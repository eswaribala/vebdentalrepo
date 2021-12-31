package com.veb.jwtsecurity.models;

import java.util.List;

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
@Table(name="VS_Medicine")
@Data
public class Medicine {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="Medicine_Id")
	private String medicineId;
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
    @ManyToOne(fetch = FetchType.LAZY,cascade = CascadeType.MERGE)
	@JoinColumn(foreignKey = @ForeignKey(name = "Appointment_No"), name = "Appoinment_No")
	@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
    private Diagnosis diagnosis;
   	
	
}
