package com.veb.jwtsecurity.controllers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.veb.jwtsecurity.configurations.JwtUtil;
import com.veb.jwtsecurity.exceptions.DisabledUserException;
import com.veb.jwtsecurity.exceptions.InvalidUserCredentialsException;
import com.veb.jwtsecurity.models.Appointment;
import com.veb.jwtsecurity.models.Diagnosis;
import com.veb.jwtsecurity.models.Doctor;
import com.veb.jwtsecurity.models.ImageModel;
import com.veb.jwtsecurity.models.Patient;
import com.veb.jwtsecurity.models.PatientAppointment;
import com.veb.jwtsecurity.models.Prescription;
import com.veb.jwtsecurity.models.Role;
import com.veb.jwtsecurity.models.Treatment;
import com.veb.jwtsecurity.models.User;
import com.veb.jwtsecurity.services.AppointmentService;
import com.veb.jwtsecurity.services.DiagnosisService;
import com.veb.jwtsecurity.services.DoctorService;
import com.veb.jwtsecurity.services.ImageService;
import com.veb.jwtsecurity.services.PatientAppointmentService;
import com.veb.jwtsecurity.services.PatientService;
import com.veb.jwtsecurity.services.PrescriptionService;
import com.veb.jwtsecurity.services.TreatmentService;
import com.veb.jwtsecurity.services.UserAuthService;
import com.veb.jwtsecurity.services.UserService;
import com.veb.jwtsecurity.vo.JWTAppointmentRequest;
import com.veb.jwtsecurity.vo.JWTPatientAppointmentRequest;
import com.veb.jwtsecurity.vo.JwtRequest;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;



@RestController
public class JwtRestController {

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private UserAuthService userAuthService;
	@Autowired
	private UserService userService;
	@Autowired
	private PatientService patientService;
	@Autowired
	private DoctorService doctorService;
	@Autowired
	private AppointmentService appointmentService;
	@Autowired
	private PatientAppointmentService patientAppointmentService;
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private DiagnosisService diagnosisService;
	@Autowired
	private TreatmentService treatmentService;
	@Autowired
	private PrescriptionService prescriptionService;
	@Autowired
	private ImageService imageService;

	@CrossOrigin("*")
	@PostMapping("/signin")	
	public ResponseEntity<?> generateJwtToken(@RequestBody JwtRequest jwtRequest) {
		
		System.out.println(jwtRequest.getUserName()+""+jwtRequest.getUserPwd());
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(jwtRequest.getUserName(), jwtRequest.getUserPwd()));
		} catch (DisabledException e) {
			throw new DisabledUserException("User Inactive");
		} catch (BadCredentialsException e) {
			throw new InvalidUserCredentialsException("Invalid Credentials");
		}
		UserDetails userDetails = userAuthService.loadUserByUsername(jwtRequest.getUserName());
		String username = userDetails.getUsername();
		String userpwd = userDetails.getPassword();
		List<String> roles = userDetails.getAuthorities().stream().map(r -> r.getAuthority())
				.collect(Collectors.toList());
		
		
		User user = new User();
		user.setUserName(username);
		user.setPassword(userpwd);
		List<Role> roleList = new ArrayList(roles);
		user.setRoles(roleList);
		System.out.print(roleList.get(0));
		String token = jwtUtil.generateToken(user);
		JSONObject jsonObject=new JSONObject();
		jsonObject.put("token", token);
		jsonObject.put("roles", user.getRoles());
		
		return ResponseEntity.status(HttpStatus.ACCEPTED).body(jsonObject);
	}

	@CrossOrigin("*")
	@PostMapping("/signup")
	public ResponseEntity<?> signup(@RequestBody User user) {
		System.out.print(user.getUserName());
		System.out.print(user.getPassword());
		System.out.print(user.getRoles());
		User userObj = userAuthService.getUserByUsername(user.getUserName());

		if (userObj == null) {
			userService.saveUser(user);
			return ResponseEntity.status(HttpStatus.ACCEPTED).body(userObj);
		} else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User already exists");
		}
	}
	@CrossOrigin("*")
	@PostMapping("/patients/signup")
	public ResponseEntity<?> pateintSignup(@RequestBody Patient patient) {
		Patient patientObj = patientService.getPatientByMobileNo(patient.getMobileNo());

		if (patientObj == null) {
			patientService.savePatient(patient);
			return ResponseEntity.status(HttpStatus.ACCEPTED).body(patientObj);
		} else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Patient already exists");
		}
	}
	
	@CrossOrigin("*")
	@GetMapping("/patients")
	public List<Patient> getAllPateints() {
		  return patientService.getAllPatients();

	}
	
	@CrossOrigin("*")
	@GetMapping("/patients/{mobileNo}")
	public ResponseEntity<?> getPateintByMobileNo(@PathVariable("mobileNo") long mobileNo) {
		Patient patientObj = patientService.getPatientByMobileNo(mobileNo);

		if (patientObj != null) {
			return ResponseEntity.status(HttpStatus.ACCEPTED).body(patientObj);
		} else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Patient Record Not Found");
		}
	}
	
	@CrossOrigin("*")
	@PostMapping("/doctors/signup")
	public ResponseEntity<?> doctorSignup(@RequestBody Doctor doctor) {
		Doctor doctorObj = doctorService.getDoctorByMobileNo(doctor.getMobileNo());

		if (doctorObj == null) {
			doctorService.saveDoctor(doctor);
			return ResponseEntity.status(HttpStatus.ACCEPTED).body(doctorObj);
		} else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Doctor already exists");
		}
	}
	
	@CrossOrigin("*")
	@GetMapping("/doctors")
	public List<Doctor> getAllDoctors() {
		return this.doctorService.getAllDoctors();
	}
	
	@CrossOrigin("*")
	@PostMapping("/doctors/signature")
	public ResponseEntity<Object> uplaodImage(@RequestParam("imageFile") MultipartFile file) throws IOException {
		System.out.println("Original Image Byte Size - " + file.getBytes().length);
		this.imageService.saveImage(file);
		 JSONObject entity = new JSONObject();
         entity.put("message", "Image Saved ....");
		return new ResponseEntity<Object>(entity, HttpStatus.OK);
	}
	@CrossOrigin("*")
	@GetMapping(path = { "/doctors/signature/{imageName}" })
	public ImageModel getImage(@PathVariable("imageName") String imageName) throws IOException {
		return this.imageService.getImageByName(imageName);
	}

	@CrossOrigin("*")
	@PostMapping("/appointments")
	public ResponseEntity<?> addAppointments(@RequestBody JWTAppointmentRequest request) {
		boolean status =appointmentService.addAppointments(request.getAppointments(), request.getMobileNo());
		 JSONObject resp = new JSONObject();
		if (status) {
			  
			    resp.put("status","Appointments Created");
			  

			return ResponseEntity.status(HttpStatus.ACCEPTED).body(resp);
		} else {
		    resp.put("status","Couldn't Save Appointments");
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
		}
	}
	
	@CrossOrigin("*")
	@GetMapping("/appointments/{mobileNo}")
	public List<Appointment> getDoctorAppointmentsByMobileNo(@PathVariable("mobileNo") long mobileNo) {
	         return this.appointmentService.getAppointmentsByMobileNo(mobileNo);
	}
	
	@CrossOrigin("*")
	@PostMapping("/patientappointments")
	public ResponseEntity<?> addPatientAppointment(@RequestBody JWTPatientAppointmentRequest request) {
		PatientAppointment pobj =patientAppointmentService.addAppointment(request);
		 JSONObject resp = new JSONObject();
		if (pobj!=null) {
			  
			    resp.put("Appointment",pobj);
			  

			return ResponseEntity.status(HttpStatus.ACCEPTED).body(resp);
		} else {
		    resp.put("status","Couldn't Save Appointments");
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
		}
	}
	@CrossOrigin("*")
	@GetMapping("/patientappointments")
	public List<PatientAppointment> getAllPatientAppointments() {
		return this.patientAppointmentService.getAllPatientAppointments();
	}
	@CrossOrigin("*")
	@GetMapping("/patientappointments/{appointmentNo}")
	public PatientAppointment getPatientAppointmentsByAppointmentNo(@PathVariable("appointmentNo") long appointmentNo) {
	         return this.patientAppointmentService.getPatientAppointmentByAppointmentNo(appointmentNo);
	}
	
	@CrossOrigin("*")
	@GetMapping("/patientappointmentsmobile/{mobileNo}")
	public List<PatientAppointment> getPatientAppointmentsByMobileNo(@PathVariable("mobileNo") long mobileNo) {
	         return this.patientAppointmentService.getPatientAppointmentByMobileNo(mobileNo);
	}
	
	@CrossOrigin("*")
	@PostMapping("/diagnosis")
	public ResponseEntity<?> addDiagnosis(@RequestBody Diagnosis diagnosis) {
		System.out.println(diagnosis);
		
		Diagnosis dobj =diagnosisService.addDiagnosis(diagnosis);
		 JSONObject resp = new JSONObject();
		if (dobj!=null) {
			  
			    resp.put("Diagnosis",dobj);
			  

			return ResponseEntity.status(HttpStatus.ACCEPTED).body(resp);
		} else {
		    resp.put("status","Couldn't Save Diagnosis");
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
		}
		
		//return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(diagnosis);
	}
	
	@CrossOrigin("*")
	@PostMapping("/prescriptions")
	public ResponseEntity<?> addPrescription(@RequestBody Prescription prescription) {
		System.out.println(prescription);
		
		Prescription pobj =prescriptionService.addPrescription(prescription);
		 JSONObject resp = new JSONObject();
		if (pobj!=null) {
			  
			    resp.put("Prescription",pobj);
			  

			return ResponseEntity.status(HttpStatus.ACCEPTED).body(resp);
		} else {
		    resp.put("status","Couldn't Save Prescription");
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
		}
		
		//return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(diagnosis);
	}
	
	@CrossOrigin("*")
	@PostMapping("/treatments")
	public ResponseEntity<?> addTreatment(@RequestBody Treatment treatment) {
		System.out.println(treatment);
		
		Treatment tobj =treatmentService.addTreatment(treatment);
		 JSONObject resp = new JSONObject();
		if (tobj!=null) {
			  
			    resp.put("Treatment",tobj);
			  

			return ResponseEntity.status(HttpStatus.ACCEPTED).body(resp);
		} else {
		    resp.put("status","Couldn't Save Treatment");
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
		}
		
		//return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(diagnosis);
	}
}
