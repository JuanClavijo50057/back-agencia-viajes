package com.app.ms_security.Controllers;

import com.app.ms_security.Models.Session;
import com.app.ms_security.Models.User;
import com.app.ms_security.Repositories.SessionRepository;
import com.app.ms_security.Repositories.UserRepository;

import com.app.ms_security.Services.EncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/users")
public class UsersController {

    @Autowired
    private SessionRepository theSessionRepository;

    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private EncryptionService theEncryptionService;

    @GetMapping("")
    public List<User> find() {
        return this.theUserRepository.findAll();
    }

    @GetMapping("{id}")
    public User findById(@PathVariable String id) {
        return this.theUserRepository.findById(id).orElse(null);
    }

    @PostMapping
    public User create(@RequestBody User newUser) throws Exception {
        User theUser = this.theUserRepository.getUserByEmail(newUser.getEmail());
        if (theUser == null) {
            newUser.setPassword(this.theEncryptionService.convertSHA256(newUser.getPassword()));
            return this.theUserRepository.save(newUser);
        } else {
            throw new Exception("El usuario ya existe");
        }
    }

    @PatchMapping("{id}")
    public User update(@PathVariable String id, @RequestBody User newUser) {
        User actualUser = this.theUserRepository.findById(id).orElse(null);
        if (actualUser != null) {
            if (newUser.getName() != null) actualUser.setName(newUser.getName());
            if (newUser.getEmail() != null) actualUser.setEmail(newUser.getEmail());
            if (newUser.getPassword() != null) actualUser.setPassword(this.theEncryptionService.convertSHA256(newUser.getPassword()));

            this.theUserRepository.save(actualUser);
            return actualUser;
        } else {
            return null;
        }
    }

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        User theUser = this.theUserRepository.findById(id).orElse(null);
        if (theUser != null) {
            this.theUserRepository.delete(theUser);
        }
    }

    @PostMapping("{userId}/session/{sessionId}")
    public void matchSession(@PathVariable String userId, @PathVariable String sessionId) {
        Session theSession = this.theSessionRepository.findById(sessionId).orElse(null);
        User theUser = this.theUserRepository.findById(userId).orElse(null);

        if (theSession != null && theUser != null) {
            theSession.setUser(theUser);
            this.theSessionRepository.save(theSession);
        }
    }
}