package com.app.ms_security.Controllers;

import com.app.ms_security.Configurations.FirebaseConfig;
import com.app.ms_security.Models.Permission;
import com.app.ms_security.Models.Profile;
import com.app.ms_security.Models.Session;
import com.app.ms_security.Models.User;
import com.app.ms_security.Repositories.ProfileRepository;
import com.app.ms_security.Repositories.SessionRepository;
import com.app.ms_security.Repositories.UserRepository;
import com.app.ms_security.Services.EncryptionService;
import com.app.ms_security.Services.JwtService;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import com.app.ms_security.Services.NotificationService;
import com.app.ms_security.Services.ValidatorsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@CrossOrigin
@RestController
@RequestMapping("/api/public/security")
public class SecurityController {
    @Autowired
    private UserRepository theUserRepository;
    @Autowired
    private EncryptionService theEncryptionService;
    @Autowired
    private JwtService theJwtService;
    @Autowired
    private NotificationService theNotificationService;
    @Autowired
    private SessionRepository theSessionRepository;
    @Autowired
    private ProfileRepository theProfileRepository;
    @Autowired
    private FirebaseAuth firebaseAuth;

    private ValidatorsService theValidatorsService;

    @PostMapping("permissions-validation")
    public boolean permissionsValidation(final HttpServletRequest request,
                                         @RequestBody Permission thePermission) {
        boolean success=this.theValidatorsService.validationRolePermission(request,thePermission.getUrl(),thePermission.getMethod());
        return success;
    }

    /*
    @PostMapping("login")
    public HashMap<String,Object> login(@RequestBody User theNewUser,
                                        final HttpServletResponse response)throws IOException {
        HashMap<String,Object> theResponse=new HashMap<>();
        String token="";
        User theActualUser=this.theUserRepository.getUserByEmail(theNewUser.getEmail());
        if(theActualUser!=null &&
           theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))){
            token=theJwtService.generateToken(theActualUser);
            theActualUser.setPassword("");
            theResponse.put("token",token);
            theResponse.put("user",theActualUser);
            return theResponse;
        }else{
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return  theResponse;
        }
    }
    */
    @PostMapping("oauth-login")
    public HashMap<String,Object> loginOauth(@RequestBody  Map<String, String> body, final HttpServletResponse response) throws IOException {
        HashMap<String,Object> theResponse=new HashMap<>();
        String idToken=body.get("idToken");
        if(idToken==null) theResponse.put("status",HttpServletResponse.SC_BAD_REQUEST);
        try {
            FirebaseToken decoded = firebaseAuth.verifyIdToken(idToken, true);
            String email = decoded.getEmail();
            String name = decoded.getName();
            String photo=decoded.getPicture();

            if (email == null || email.isBlank())theResponse.put("status",HttpServletResponse.SC_BAD_REQUEST);
            User theActualUser = this.theUserRepository.getUserByEmail(email);
            if (theActualUser == null) {
                theActualUser =new User();
                theActualUser.setEmail(email);
                theActualUser.setName(name);
                theActualUser=theUserRepository.save(theActualUser);
                Profile thePermission=new Profile(null,theActualUser,null);
                theProfileRepository.save(thePermission);
            }
            String token = theJwtService.generateToken(theActualUser);
            theResponse.put("token", token);
            this.theNotificationService.sendLoginNotification(
                    theActualUser.getEmail(),
                    theActualUser.getName(),
                    LocalDateTime.now().toString()
            );

            theResponse.put("status",HttpServletResponse.SC_OK);
        } catch (Exception e) {
            theResponse.put("status",HttpServletResponse.SC_UNAUTHORIZED);
            theResponse.put("message",e.getMessage());
        }

        return theResponse;
    }

    @PostMapping("login")
    public HashMap<String,Object> login(@RequestBody User theNewUser,
                                        final HttpServletResponse response) throws IOException {
        HashMap<String,Object> theResponse = new HashMap<>();
        User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());
        if (theActualUser != null &&
                theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))) {
            String code2FA = this.theNotificationService.generateCode2FA();
            this.theNotificationService.send2FACode(theActualUser.getEmail(), code2FA);
            // Guarda el código temporalmente (puedes usar una tabla temporal o cache)
            Session session = new Session(null, null, code2FA);
            session.setUser(theActualUser);
            Session savedSession = this.theSessionRepository.save(session);

            theResponse.put("2fa_required", true);
            theResponse.put("message", "Código 2FA enviado al correo");
            theResponse.put("sessionId", savedSession.get_id());

            return theResponse;
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return theResponse;
        }
    }


    @PostMapping("validate-2fa")
    public HashMap<String,Object> validate2FA(@RequestBody Map<String, String> body,
                                              final HttpServletResponse response) throws IOException {
        HashMap<String,Object> theResponse = new HashMap<>();
        String sessionId = body.get("sessionId");
        String code = body.get("code");
        Session session = this.theSessionRepository.findById(sessionId).orElse(null);

        if (session != null && session.getCode2FA().equals(code)) {
            User theActualUser = session.getUser();
            String token = theJwtService.generateToken(theActualUser);
            Date expiration = new Date(System.currentTimeMillis() + 30 * 60 * 1000); // 5 minutos
            session.setToken(token);
            session.setExpiration(expiration);
            this.theSessionRepository.save(session);

            this.theNotificationService.sendLoginNotification(
                    theActualUser.getEmail(),
                    theActualUser.getName(),
                    LocalDateTime.now().toString()
            );

            theResponse.put("valid", true);
            theResponse.put("token", token);
            return theResponse;
        } else {
            if (session != null) {
                this.theSessionRepository.delete(session);
            }
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return theResponse;
        }
    }
}
