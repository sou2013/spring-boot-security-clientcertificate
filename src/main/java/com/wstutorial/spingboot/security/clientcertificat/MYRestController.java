package com.wstutorial.spingboot.security.clientcertificat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

@RestController
public class MYRestController {

    @Autowired
    RestTemplate restTemplate;

    @RequestMapping(value = "/api/proxy/time", method = RequestMethod.GET)
    public String getResponse(ServletRequest request, ServletResponse response, Model model)  {
        HttpServletRequest req = (HttpServletRequest) request;
        String a = req.getHeader("Authorization");
        a = a.substring(7);
/*
        HttpHeaders authenticationHeaders = getHeaders();
        HttpEntity<String> authenticationEntity = new HttpEntity<String>(authenticationBody,
                authenticationHeaders);
*/
       // String url = "http://192.168.254.35:8080/api/add";
        String url = "http://localhost:8080/api/time";
        String token = "Bearer " + a;
        HttpHeaders headers = getHeaders();
        headers.set("Authorization", token);
        HttpEntity<String> jwtEntity = new HttpEntity<String>(headers);
        // Use Token to get Response
        ResponseEntity<String> helloResponse = restTemplate.exchange(url, HttpMethod.GET, jwtEntity,
                String.class);
        String resp = "";
        if (helloResponse.getStatusCode().equals(HttpStatus.OK)) {
            resp = helloResponse.getBody();
        }
        System.out.println("response " + resp);
        return resp;
    }

    private HttpHeaders getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        return headers;
    }

}
