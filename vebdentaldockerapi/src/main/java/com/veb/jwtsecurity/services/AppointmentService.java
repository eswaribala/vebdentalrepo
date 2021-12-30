package com.veb.jwtsecurity.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.veb.jwtsecurity.models.Appointment;
import com.veb.jwtsecurity.models.Doctor;
import com.veb.jwtsecurity.repositories.AppointmentRepository;

@Service
public class AppointmentService {
    @Autowired
	private AppointmentRepository appointmentRepository;
    @Autowired
    private DoctorService doctorService;
    public boolean addAppointments(List<Appointment> appointments,long mobileNo) {
    	boolean status=false;
    	Doctor doctor=null;
    	if(this.doctorService.getDoctorByMobileNo(mobileNo)!=null){
              doctor=this.doctorService.getDoctorByMobileNo(mobileNo);
              for(Appointment appointment : appointments) {
            	  appointment.setDoctor(doctor);
            	  this.appointmentRepository.save(appointment);
              }
              status=true;
    	}
    	return status;
    }
    
    public List<Appointment> getAppointmentsByMobileNo(long mobileNo){
    	return this.appointmentRepository.findAppointmentsByMobileNo(mobileNo);
    }
}
 