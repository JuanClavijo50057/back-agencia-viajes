package com.app.ms_security.Controllers;

import com.app.ms_security.Models.Permission;
import com.app.ms_security.Models.Session;
import com.app.ms_security.Models.User;
import com.app.ms_security.Repositories.SessionRepository;
import com.app.ms_security.Repositories.UserRepository;
import com.app.ms_security.Services.EncryptionService;
import com.app.ms_security.Services.JwtService;
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

    @PostMapping("login")
    public HashMap<String,Object> login(@RequestBody User theNewUser,
                                        final HttpServletResponse response) throws IOException {
        HashMap<String,Object> theResponse = new HashMap<>();
        User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());
        if (theActualUser != null &&
                theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))) {
            String code2FA = this.theNotificationService.generateCode2FA();
            this.theNotificationService.send2FACode(theActualUser.getEmail(), code2FA);

            Date codeExpiration = new Date(System.currentTimeMillis() + 10 * 60 * 1000); // 10 minutos
            Session session = new Session(null, codeExpiration, code2FA);
            session.setUser(theActualUser);
            session.setIntentos(0);
            Session savedSession = this.theSessionRepository.save(session);

            theResponse.put("2fa_required", true);
            theResponse.put("message", "Código 2FA enviado al correo");
            theResponse.put("sessionId", savedSession.get_id());
            return theResponse;
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Credenciales inválidas");
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

        if (session.getExpiration() != null && session.getExpiration().before(new Date()) ||
            session.getIntentos() >= 3) {
            if (session != null) {
                this.theSessionRepository.delete(session);
            }
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Sesión expirada o intentos excedidos");
            return theResponse;
        }

        if (session != null && session.getCode2FA().equals(code)) {
            User theActualUser = session.getUser();
            String token = theJwtService.generateToken(theActualUser);

            session.setToken(token);
            session.setCode2FA(null);
            session.setExpiration(null);
            session.setIntentos(0);
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
            session.setIntentos(session.getIntentos() + 1);
            this.theSessionRepository.save(session);
            int restantes = Math.max(0, 3 - session.getIntentos());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Código incorrecto. Intentos restantes: " + restantes);
            return theResponse;
        }
    }
}
