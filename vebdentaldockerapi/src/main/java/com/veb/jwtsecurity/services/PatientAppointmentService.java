package com.veb.jwtsecurity.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import com.veb.jwtsecurity.models.Appointment;
import com.veb.jwtsecurity.models.Doctor;
import com.veb.jwtsecurity.models.Patient;
import com.veb.jwtsecurity.models.PatientAppointment;
import com.veb.jwtsecurity.repositories.AppointmentRepository;
import com.veb.jwtsecurity.repositories.PatientAppointmentRepository;
import com.veb.jwtsecurity.vo.JWTPatientAppointmentRequest;
@Service
public class PatientAppointmentService {
	 public static final String ACCOUNT_SID = System.getenv("TWILIO_ACCOUNT_SID");
	public static final String AUTH_TOKEN = System.getenv("TWILIO_AUTH_TOKEN");

    @Autowired
	private PatientAppointmentRepository patientAppointmentRepository;
    @Autowired
    private DoctorService doctorService;
    @Autowired
    private PatientService patientService;
    public PatientAppointment addAppointment(JWTPatientAppointmentRequest request) {
    	Doctor doctor=null;
    	Patient patient=null;
    	PatientAppointment patientAppointment,pobj=null;
    	if(this.doctorService.getDoctorByMobileNo(request.getDoctorMobileNo())!=null){
              doctor=this.doctorService.getDoctorByMobileNo(request.getDoctorMobileNo());
            if(this.patientService.getPatientByMobileNo(request.getPatientMobileNo())!=null) {
            	patient=this.patientService.getPatientByMobileNo(request.getPatientMobileNo());
            	patientAppointment=new PatientAppointment();
            	patientAppointment.setChair(request.getChair());
            	patientAppointment.setTreatment(request.getTreatment());
            	patientAppointment.setDoa(request.getDoa());
            	patientAppointment.setDoctor(doctor);
            	patientAppointment.setPatient(patient);
            	pobj=this.patientAppointmentRepository.save(patientAppointment);
            }
             
    	}
    	 Twilio.init(ACCOUNT_SID, AUTH_TOKEN);
         Message message = Message.creator(
                 new com.twilio.type.PhoneNumber("whatsapp:+91"+String.valueOf(pobj.getDoctor().getMobileNo())),
                 new com.twilio.type.PhoneNumber("whatsapp:+14155238886"),
                 "Your Appointment with VEB Dental Care on"+pobj.getDoa()+","+pobj.getTreatment()+"confirmed")
             .create();
    	
    	
    	return pobj;
    }
    
    public PatientAppointment getPatientAppointmentByAppointmentNo(long appointmentNo){
    	return this.patientAppointmentRepository.findById(appointmentNo).orElse(null);
    }
    public List<PatientAppointment> getAllPatientAppointments(){
    	return this.patientAppointmentRepository.findAll();
    }
    
    public List<PatientAppointment>  getPatientAppointmentByMobileNo(long mobileNo){
    	return this.patientAppointmentRepository.findPatientAppointmentsByMobileNo(mobileNo);
    }
}
 