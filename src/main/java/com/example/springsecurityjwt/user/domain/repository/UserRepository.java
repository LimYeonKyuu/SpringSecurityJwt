package com.example.springsecurityjwt.user.domain.repository;

import com.example.springsecurityjwt.user.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUniqueId(String uniqueId);
}
