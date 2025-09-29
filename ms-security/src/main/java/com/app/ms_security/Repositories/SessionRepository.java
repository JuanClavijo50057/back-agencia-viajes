package com.app.ms_security.Repositories;

import org.springframework.data.mongodb.repository.MongoRepository;
import com.app.ms_security.Models.Session;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionRepository extends MongoRepository<Session, String> {
    @Query("{ 'email': ?0, 'code2FA': ?1 }")
    Session findByUserAndCode2FA(String email, String code2FA);
}
