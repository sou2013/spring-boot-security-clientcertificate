package com.wstutorial.spingboot.security.clientcertificat;

import org.apache.http.HttpResponse;
import org.apache.http.entity.StringEntity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        System.out.println("wwwww java version " + System.getProperty("java.version"));
super.authenticationManager() ;
http.authorizeRequests()
                .antMatchers("/auth").permitAll()
               // .antMatchers("/protected").hasRole("USER")
               // .antMatchers("/admin").hasRole("ADMIN")
                .and().x509()

                //.subjectPrincipalRegex("CN=(.*?),")
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")

                .userDetailsService(userDetailsService());

        http.addFilterBefore(new CustomFilter(), X509AuthenticationFilter.class);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            User user = null ;
            if(username.equals("testuser")) {
                user = new User(username, "", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_NONE"));
                return user;
            }else {
                throw new UsernameNotFoundException("User:" + username + " not found");
            }
        };
    }
    /*
    @Bean
    public UserDetailsService userDetailsService() {
        return (UserDetailsService) username -> {
            if (username.contains("testuser")) {
                return new User(username, "",
                        AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
            } else if (username.equals("testsupervisor")) {
                return new User(username, "",
                        AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_ADMIN"));
            } else {
                throw new UsernameNotFoundException("User:" + username + " not found");
            }
        };
    }
    */

    public static void main(String[] ar) {
        primaryAuth();
    }
    private static void primaryAuth() {

        String postEndpoint = "http://localhost:8088/api/authenticate";
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(postEndpoint);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/json");
        String inputJson = "{\"username\":\"testuser\",\"password\":\"password\"}";
        try {
        StringEntity stringEntity = new StringEntity(inputJson);
        httpPost.setEntity(stringEntity);

        System.out.println("Executing request " + httpPost.getRequestLine());

        HttpResponse response = httpclient.execute(httpPost);
        System.out.println("wwwdw done");

        BufferedReader br = new BufferedReader(new InputStreamReader((response.getEntity().getContent())));
        //Throw runtime exception if status code isn't 200
        if (response.getStatusLine().getStatusCode() < 200 || response.getStatusLine().getStatusCode() > 299) {
            throw new RuntimeException("Failed : HTTP error code : "
                    + response.getStatusLine().getStatusCode());
        }
        //Create the StringBuffer object and store the response into it.
        StringBuffer result = new StringBuffer();
        String line = "";
        while ((line = br.readLine()) != null) {
            System.out.println("Response : \n"+result.append(line));
        }
        }catch (Exception e) {
            e.printStackTrace();
        }
    }

}

