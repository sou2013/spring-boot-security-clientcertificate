package com.wstutorial.spingboot.security.clientcertificat;

import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class CustomFilter implements Filter {

    @Override
    public void destroy() {
        // Do nothing
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("authentication is null " + (authentication==null));
        if(authentication != null) {
        	String accTkn = "token1234";
        	String name = authentication.getName();
        	String s = primaryAuth(name, null);
        	if(s != null && s.length() > 1) {
        		accTkn = s;
        	}
            Set<String> roles = AuthorityUtils.authorityListToSet(authentication.getAuthorities());
            System.out.println("roles " + roles);
            request.getSession().setAttribute("mykey", "val123");
            String result = "{\"result\":\r\n" + 
            		 accTkn +"\", " + 
            		" \"roles\":[\"NONE\"]" + 
            		" }" + 
            		"}";
           
            try {
				String role = secondaryAuth(name, null);
				result = "{\"result\": \r\n" + 
	            		 accTkn +"\", " + 
	            		" \"roles\":[\"" + role +  "\"]" + 
	            		" }" + 
	            		"}";
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            request.setAttribute("result", result);
            System.out.println("returning result: " + result);
        }
        chain.doFilter(req, res);
 
    }

    private static String secondaryAuth(String username, String password) throws ClientProtocolException, IOException, Exception {
        String pswd = "test123!";
        if(username.contains("user")) {
        	username = "testoperator";
        }
        String postEndpoint = "https://infr-ipa0.168.r2lab.rb.c2fse.northgrum.com/ipa/session/login_password";
        try (CloseableHttpClient httpclient = HttpClients.createDefault()) {

            List<NameValuePair> form = new ArrayList<>();
            form.add(new BasicNameValuePair("user", username));
            form.add(new BasicNameValuePair("password", pswd));
            UrlEncodedFormEntity entity = new UrlEncodedFormEntity(form, Consts.UTF_8);

            HttpPost httpPost = new HttpPost(postEndpoint);
            httpPost.setEntity(entity);
            System.out.println("Executing request " + httpPost.getRequestLine());

            // Create a custom response handler
            ResponseHandler<String> responseHandler = response -> {
                int status = response.getStatusLine().getStatusCode();
                System.out.println("sc = " + status); 
                if (status >= 200 && status < 300) {
                    HttpEntity responseEntity = response.getEntity();
                    return responseEntity != null ? EntityUtils.toString(responseEntity) : null;
                } else {
                    throw new ClientProtocolException("Unexpected response status: " + status);
                }
            };
            String resp = "";
			
			resp = httpclient.execute(httpPost, responseHandler);
			
			httpPost.setURI(new URI("https://infr-ipa0.168.r2lab.rb.c2fse.northgrum.com/ipa/session/json"));
			httpPost.setHeader("Accept", "application/json");
	        httpPost.setHeader("Content-type", "application/json");
	        httpPost.setHeader("Referer", "https://infr-ipa0.168.r2lab.rb.c2fse.northgrum.com/ipa");
	        
	        String inputJson = "{\"jsonrpc\": \"2.0\", \"method\":\"user_show\",\"params\":[[\"" + username + "\"],{\"all\": true,\"version\": \"2.215\"}],\"id\":0}";
	        System.out.println("request json = " + inputJson);	
	        StringEntity stringEntity = new StringEntity(inputJson);
	        httpPost.setEntity(stringEntity);
	        resp = httpclient.execute(httpPost, responseHandler);
	        
            System.out.println("----------------------------------------");
            System.out.println(resp);
            
            if(resp.contains("p093operator")) {
            	resp = "p093operator";
	        }
            return resp;
        }
    }
    
    private static String primaryAuth(String username, String password) {
        String pswd = "password";
        if(username.contains("supervisor")) {
            pswd = "admin";
        }

        String postEndpoint = "http://localhost:8088/api/authenticate";
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(postEndpoint);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/json");
        String inputJson = "{\"username\":\"" + username + "\"" + ",\"password\":\"" +  pswd + "\"}";
        //Create the StringBuffer object and store the response into it.
        StringBuffer result = new StringBuffer();
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

        String line = "";
        while ((line = br.readLine()) != null) {
            System.out.println("Response : \n"+result.append(line));
        }
        }catch (Exception e) {
            e.printStackTrace();
        }
        return result.toString();
    }
    
    @Override
    public void init(FilterConfig arg0) throws ServletException {
        // Do nothing
    }

    
    public static void main(String[] ar) throws Exception {
    	CustomFilter.secondaryAuth("ab", "bb");
    }
}