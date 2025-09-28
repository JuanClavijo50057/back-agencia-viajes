package com.app.ms_security.Controllers;

import com.app.ms_security.Models.Role;
import com.app.ms_security.Models.User;
import com.app.ms_security.Models.UserRole;
import com.app.ms_security.Repositories.RoleRepository;
import com.app.ms_security.Repositories.UserRepository;
import com.app.ms_security.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("api/user-role")
public class UserRoleController {

    @Autowired
    private UserRoleRepository theUserRoleRepository;

    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private RoleRepository theRoleRepository;

    @GetMapping("")
    public List<UserRole> find() {
        return this.theUserRoleRepository.findAll();
    }

    @GetMapping("{id}")
    public UserRole findById(@PathVariable String id) {
        return this.theUserRoleRepository.findById(id).orElse(null);
    }

    @PostMapping("user/{userId}/role/{roleId}")
    public UserRole create(@PathVariable String userId, @PathVariable String roleId) {
        User theUser = this.theUserRepository.findById(userId).orElse(null);
        Role theRole = this.theRoleRepository.findById(roleId).orElse(null);

        if (theUser != null && theRole != null) {
            UserRole newUserRol = new UserRole();
            newUserRol.setUser(theUser);
            newUserRol.setRole(theRole);
            return this.theUserRoleRepository.save(newUserRol);
        } else {
            return null;
        }
    }

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        UserRole theUserRole = this.theUserRoleRepository.findById(id).orElse(null);
        if (theUserRole != null) {
            this.theUserRoleRepository.delete(theUserRole);
        }
    }

    @DeleteMapping("user/{userId}/role/{roleId}")
    public void deleteByUserRol(@PathVariable String userId, @PathVariable String roleId) {
        UserRole theUserRole = this.theUserRoleRepository.getUserRoleByUserAndRole(userId, roleId);
        if (theUserRole != null) {
            this.theUserRoleRepository.delete(theUserRole);
        } else {
            throw new RuntimeException("No se encontró relación UserRole con ese userId y roleId");
        }
    }

    @GetMapping("user/{userId}")
    public List<Role> getRolesByUser(@PathVariable String userId) {
        return this.theUserRoleRepository.getRolesByUser(userId).stream().map(UserRole::getRole).toList();
    }

    @GetMapping("role/{roleId}")
    public List<UserRole> getUsersByRole(@PathVariable String roleId) {
        return this.theUserRoleRepository.getUsersByRole(roleId);
    }
    @GetMapping("rolesToAdd/{userId}")
    public List<Role> getRolesToAddUser(@PathVariable String userId) {
        List<UserRole> userRoles = theUserRoleRepository.getRolesByUser(userId);
        List<String> assignedRoleIds = userRoles.stream()
                .map(ur -> ur.getRole().get_id())
                .toList();
        return theRoleRepository.findByIdNotIn(assignedRoleIds);
    }

}
