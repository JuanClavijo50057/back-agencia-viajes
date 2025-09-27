package com.app.ms_security.Controllers;

import com.app.ms_security.Models.Profile;
import com.app.ms_security.Repositories.ProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/profiles")
public class ProfilesController {
    @Autowired
    private ProfileRepository theProfilesRepository;

    @GetMapping("")
    public List<Profile> find() {
        return this.theProfilesRepository.findAll();
    }

    @GetMapping("{id}")
    public Profile findById(@PathVariable String id) {
        return this.theProfilesRepository.findById(id).orElse(null);
    }

    @PostMapping
    public Profile create(@RequestBody Profile newProfiles) {
        return this.theProfilesRepository.save(newProfiles);
    }

    @PutMapping("{id}")
    public Profile update(@PathVariable String id, @RequestBody Profile newProfiles) {
        Profile actualProfiles = this.theProfilesRepository.findById(id).orElse(null);
        if (actualProfiles != null) {
            actualProfiles.setPhone(newProfiles.getPhone());
            actualProfiles.setPhoto(newProfiles.getPhoto());
            actualProfiles.setUser(newProfiles.getUser());
            this.theProfilesRepository.save(actualProfiles);
            return actualProfiles;
        } else {
            return null;
        }
    }

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        Profile theProfiles = this.theProfilesRepository.findById(id).orElse(null);
        if (theProfiles != null) {
            this.theProfilesRepository.delete(theProfiles);
        }
    }
}
