package com.veb.jwtsecurity.repositories;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

import com.veb.jwtsecurity.models.ImageModel;


public interface ImageRepository extends JpaRepository<ImageModel, Long> {
	List<ImageModel> findByName(String name);
}