package com.app.ms_security.Repositories;

import org.springframework.data.mongodb.repository.MongoRepository;
import com.app.ms_security.Models.User;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends MongoRepository<User, String> {
    @Query("{ 'email': ?0 }")
    public User getUserByEmail(String userEmail);
}
