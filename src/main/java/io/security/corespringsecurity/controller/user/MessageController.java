package io.security.corespringsecurity.controller.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {
    @GetMapping(value = "/messages")
    public String messages() {
        return "user/messages";
    }

    @GetMapping(value = "/api/messages")
    @ResponseBody
    public String apiMessages(){
        return "messages ok";
    }

    @PostMapping(value = "/api/messages")
    @ResponseBody
    public String apiPostMessages(){
        return "post messages ok";
    }
}
