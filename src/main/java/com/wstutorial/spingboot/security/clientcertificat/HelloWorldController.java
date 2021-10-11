package com.wstutorial.spingboot.security.clientcertificat;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

//@RestController
@Controller
public class HelloWorldController {
	static int count = 1;
    @RequestMapping("/auth")
    public String hello(ServletRequest req, ServletResponse res, Model model){
    	System.out.println("count = " + count++);
    	Object result = req.getAttribute("token");
        Object jwt = req.getAttribute("jwt");
        HttpServletResponse resp = (HttpServletResponse) res;

        //Cookie c = new Cookie();
       // resp.addCookie();
    	String s = "{\"result\":\"error\"}";
    	if(result != null) {
    		s = (String)result;
            model.addAttribute("token", s);
            model.addAttribute("jwt", jwt);
    	}
System.out.println("result= " + s);
        return "auth";
    }

    @CrossOrigin
    @RequestMapping("/protected")
    public String protectedHello(){
        return "Hello World, i was protected";
    }

    @RequestMapping("/admin")
    public String admin(){
        return "Hello World from admin";
    }

}
