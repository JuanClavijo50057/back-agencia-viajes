package com.app.ms_security.Repositories;

import com.app.ms_security.Models.UserRole;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRoleRepository extends MongoRepository<UserRole, String> {
    @Query("{'user.$id': ObjectId(?0)}")
    public List<UserRole> getRolesByUser(String userId);

    @Query("{'role.$id': ObjectId(?0)}")
    public List<UserRole> getUsersByRole(String roleId);

    @Query("{'user.$id': ObjectId(?0), 'role.$id': ObjectId(?1)}")
    UserRole getUserRoleByUserAndRole(String userId, String roleId);
}
