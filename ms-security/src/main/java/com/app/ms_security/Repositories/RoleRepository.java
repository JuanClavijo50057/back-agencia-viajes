package com.app.ms_security.Repositories;

import com.app.ms_security.Models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.List;
@Repository
public interface RoleRepository extends MongoRepository<Role, String> {
    @Query("{ '_id': { $nin: ?0 } }")
    List<Role> findByIdNotIn(List<String> roleIds);
}
