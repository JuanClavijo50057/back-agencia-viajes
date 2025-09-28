package com.app.ms_security.Controllers;

import com.app.ms_security.Models.Permission;
import com.app.ms_security.Models.Permission;
import com.app.ms_security.Repositories.PermissionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("api/permissions")
public class PermissionsController {
    @Autowired
    private PermissionRepository thePermissionRepository;
    @GetMapping("")
    public List<Permission> findAll(){
        return this.thePermissionRepository.findAll();
    }
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping
    public Permission create(@RequestBody Permission theNewPermission){
        return this.thePermissionRepository.save(theNewPermission);
    }
    @ResponseStatus(HttpStatus.NO_CONTENT)

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        Permission thePermission = this.thePermissionRepository
                .findById(id)
                .orElse(null);
        if (thePermission != null) {
            this.thePermissionRepository.delete(thePermission);
        }
    }
    
    @PutMapping("{id}")
    public Permission create(@PathVariable String id, @RequestBody Permission theNewPermission){
        Permission actualPermission = this.thePermissionRepository.findById(id).orElse(null);
        if (actualPermission != null){
            actualPermission.setUrl(theNewPermission.getUrl());
            actualPermission.setMethod(theNewPermission.getMethod());
            actualPermission.setModel(theNewPermission.getModel());
            this.thePermissionRepository.save(actualPermission);
            return actualPermission;
        } else {
            return null;
        }
    }
}
