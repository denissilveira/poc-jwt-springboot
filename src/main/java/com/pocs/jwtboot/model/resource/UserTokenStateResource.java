package com.pocs.jwtboot.model.resource;

public class UserTokenStateResource {
	
    private String access_token;
    private int expires_in;
    private UserResource userResource;

    public UserTokenStateResource() {
    }

    public UserTokenStateResource(String access_token, int expiresIn, UserResource userResource) {
		this.access_token = access_token;
		this.expires_in = expiresIn;
		this.userResource = userResource;
	}

	public String getAccess_token() {
		return access_token;
	}
	public void setAccess_token(String access_token) {
		this.access_token = access_token;
	}
	public int getExpires_in() {
		return expires_in;
	}
	public void setExpires_in(int expires_in) {
		this.expires_in = expires_in;
	}
	public UserResource getUserResource() {
		return userResource;
	}
	public void setUserResource(UserResource userResource) {
		this.userResource = userResource;
	}

}