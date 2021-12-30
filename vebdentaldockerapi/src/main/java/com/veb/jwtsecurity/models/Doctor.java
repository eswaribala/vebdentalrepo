package com.veb.jwtsecurity.models;

import java.time.LocalDate;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonFormat.Shape;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import lombok.Data;
@Entity
@Table(name="VS_Doctors")
@Data
public class Doctor {
	@Id
	@Column(name="Mobile_No")
	private long mobileNo;
	@Column(name="Title",length = 5)
	private String title;
	@Column(name="First_Name",length = 50)
	private String firstName;
	@Column(name="Last_Name",length = 50)
	private String lastName;
	@Column(name="Address1",length = 150)
	private String address1;
	@Column(name="Address2",length = 150)
	private String address2;
	@Column(name="City",length = 150)
	private String city;
	@Column(name="State",length = 150)
	private String state;
	@Column(name="Zip")
	private long zip;
	@JsonFormat(shape = Shape.STRING,pattern = "yyyy-MM-dd")
    @JsonDeserialize(using=LocalDateDeserializer.class)
	@JsonSerialize(using=LocalDateSerializer.class)	
	@Column(name="DOB")
	private LocalDate dob;
	@Enumerated(EnumType.STRING)
	@Column(name="Gender")
	private Gender gender;
	@Column(name="RegNo",length = 20)
	private String regNo;
	@Column(name="Email",length = 100)
	private String email;
	@Column(name="Signature_File_Name",length = 200)
	private String signatureFileName;
	

}
