package com.wstutorial.spingboot.security.clientcertificat;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
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
            Set<String> roles = AuthorityUtils.authorityListToSet(authentication.getAuthorities());
            System.out.println("roles " + roles);
            request.getSession().setAttribute("mykey", "val123");
            String result = "{\"result\": {  \r\n" + 
            		"\"accessToken\":\"" + accTkn +"\", " + 
            		" \"roles\":[\"USER_NONE\"]" + 
            		" }" + 
            		"}";
            request.setAttribute("result", result);
            System.out.println("returning result: " + result);
        }
        chain.doFilter(req, res);
 
    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {
        // Do nothing
    }

}