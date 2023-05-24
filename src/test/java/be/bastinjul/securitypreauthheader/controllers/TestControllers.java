package be.bastinjul.securitypreauthheader.controllers;

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TestControllers {

    @GetMapping("/secured")
    @Secured("role1")
    public String secured() {
        return "ok";
    }

    @GetMapping("/notSecured")
    public String notSecured() {
        return "ok";
    }

    @GetMapping("/noFilter/test")
    public String testNoFilter() {
        return "ok";
    }

}
