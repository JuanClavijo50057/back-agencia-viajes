package com.app.ms_security.Controllers;

import com.app.ms_security.Models.Session;
import com.app.ms_security.Repositories.SessionRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/sessions")
public class SessionsController {
    @Autowired
    private SessionRepository theSessionsRepository;

    @GetMapping("")
    public List<Session> find() {
        return this.theSessionsRepository.findAll();
    }

    @GetMapping("{id}")
    public Session findById(@PathVariable String id) {
        return this.theSessionsRepository.findById(id).orElse(null);
    }

    @PostMapping
    public Session create(@RequestBody Session newSessions) {
        return this.theSessionsRepository.save(newSessions);
    }

    @PutMapping("{id}")
    public Session update(@PathVariable String id, @RequestBody Session newSessions) {
        Session actualSessions = this.theSessionsRepository.findById(id).orElse(null);
        if (actualSessions != null) {
            actualSessions.setToken(newSessions.getToken());
            actualSessions.setExpiration(newSessions.getExpiration());
            actualSessions.setCode2FA(newSessions.getCode2FA());
            this.theSessionsRepository.save(actualSessions);
            return actualSessions;
        } else {
            return null;
        }
    }

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        Session theSessions = this.theSessionsRepository.findById(id).orElse(null);
        if (theSessions != null) {
            this.theSessionsRepository.delete(theSessions);
        }
    }
}