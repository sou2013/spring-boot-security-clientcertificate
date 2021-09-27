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
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/protected").hasRole("USER")
                .antMatchers("/admin").hasRole("ADMIN")
                .and().x509()
                //.subjectPrincipalRegex("CN=(.*?),")
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService());
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return (UserDetailsService) username -> {
            if (username.equals("testuser")) {
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

    public static void main(String[] ar) {
        primaryAuth();
    }
    private static void primaryAuth() {
        System.out.println("wwwww 111");
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

            BufferedReader br = new BufferedReader(
                    new InputStreamReader((response.getEntity().getContent())));


            //Throw runtime exception if status code isn't 200
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new RuntimeException("Failed : HTTP error code : "
                        + response.getStatusLine().getStatusCode());
            }


            //Create the StringBuffer object and store the response into it.
            StringBuffer result = new StringBuffer();
            String line = "";
            while ((line = br.readLine()) != null) {
                System.out.println("Response : \n"+result.append(line));
            }


            //Lets validate if a text 'employee_salary' is present in the response
            System.out.println("Does Reponse contains 'employee_salary'? :" + result.toString().contains("employee_salary"));

        }catch (Exception e) {
    e.printStackTrace();
}
        /*
        try (CloseableHttpClient httpclient = HttpClients.createDefault()) {

            List<NameValuePair> form = new ArrayList<>();
            form.add(new BasicNameValuePair("foo", "bar"));
            form.add(new BasicNameValuePair("employee", "John Doe"));
            UrlEncodedFormEntity entity = new UrlEncodedFormEntity(form, Consts.UTF_8);

            HttpPost httpPost = new HttpPost("http://localhost:8088/api/authenticate");
            httpPost.setEntity(entity);
            System.out.println("Executing request " + httpPost.getRequestLine());

            // Create a custom response handler
            ResponseHandler<String> responseHandler = response -> {
                int status = response.getStatusLine().getStatusCode();
                if (status >= 200 && status < 300) {
                    HttpEntity responseEntity = response.getEntity();
                    return responseEntity != null ? EntityUtils.toString(responseEntity) : null;
                } else {
                    throw new ClientProtocolException("Unexpected response status: " + status);
                }
            };
            String responseBody = httpclient.execute(httpPost, responseHandler);
            System.out.println("----------------------------------------");
            System.out.println(responseBody);
        }catch (Exception e) {
            e.printStackTrace();
        }

         */

    }

}

