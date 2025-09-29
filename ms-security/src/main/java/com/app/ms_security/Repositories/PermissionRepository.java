package com.app.ms_security.Repositories;

import com.app.ms_security.Models.Permission;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface PermissionRepository extends MongoRepository<Permission, String> {
    @Query("{'url':?0,'method':?1}")
    Permission getPermission(String url,
                             String method);
}
