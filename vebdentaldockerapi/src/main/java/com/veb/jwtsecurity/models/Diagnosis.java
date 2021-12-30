package com.veb.jwtsecurity.models;

import java.time.LocalDate;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonFormat.Shape;

import lombok.Data;

@Entity
@Table(name="VS_Diagnosis")
@Data
public class Diagnosis {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="Diagnosis_Id")
	private long diagnosisId;
	@Column(name="Patient_MobileNo")
	private long patientMobileNo;
	@Column(name="Doctor_MobileNo")
	private long doctorMobileNo;
    @Column(name="Appointment_No")
	private long appointmentNo;
    @Column(name="Complaints")
    @ElementCollection(targetClass=String.class)
	private List<String> complaints;
    @Column(name="Diagnosis_Type")
    @ElementCollection(targetClass=String.class)
	private List<String> diagnosisType;    
    @Column(name="Selected_Tooth")
    @ElementCollection(targetClass=String.class)
	private List<String> selectedTooth;
    /*@OneToMany(mappedBy ="diagnosis", cascade=CascadeType.ALL,fetch=FetchType.LAZY,orphanRemoval = true)
	@JsonProperty("prescriptions")
	@JsonFormat(with = JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY)	
    private List<Prescription> prescriptions;
    @OneToMany(mappedBy ="diagnosis", cascade=CascadeType.ALL,fetch=FetchType.LAZY,orphanRemoval = true)
	@JsonProperty("treatmentCosts")
	@JsonFormat(with = JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY)	
    private List<Treatment> treatmentCosts;
	
*/
}
