package com.wstutorial.spingboot.security.clientcertificat;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import javax.servlet.*;

@RestController
public class HelloWorldController {
	static int count = 1;
    @RequestMapping("/auth")
    public String hello(ServletRequest req, ServletResponse res){
    	System.out.println("count = " + count++);
    	Object result = req.getAttribute("result");
    	String s = "{\"result\":\"error\"}";
    	if(result != null) {
    		s = (String)result;
    	}
        return s;
    }

    @RequestMapping("/protected")
    public String protectedHello(){
        return "Hello World, i was protected";
    }

    @RequestMapping("/admin")
    public String admin(){
        return "Hello World from admin";
    }

}
