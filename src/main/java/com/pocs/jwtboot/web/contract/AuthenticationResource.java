package com.pocs.jwtboot.web.contract;

public class AuthenticationResource {
	
    private String username;
    private String password;
    
    public AuthenticationResource() {}

    public AuthenticationResource(final String username, final String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }
}